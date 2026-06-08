"""Orchestrator: poll MSRC → filter → download → diff → blog."""
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import click
import schedule

from pipeline import config
from pipeline.database import (
    init_db, is_update_processed, mark_update_processed,
    upsert_cve, set_cve_status, get_cve,
)
from pipeline.msrc import list_updates, fetch_cvrf, iter_cves
from pipeline.kernel_filter import classify_cve
from pipeline.winbindex import get_binary_pair
from pipeline.ghidriff_runner import run_ghidriff
from pipeline.patch_identifier import identify_patch, PatchNotFoundError
from pipeline.blog_generator import generate_blog_post, save_blog_post


def _setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


log = logging.getLogger("pipeline.main")


def process_cve(cve: dict, binary_name: str) -> None:
    cve_id = cve["id"]
    binaries_dir = config.BINARIES_DIR / cve_id
    diffs_dir = config.DIFFS_DIR
    blogs_dir = config.BLOGS_DIR

    try:
        log.info("[%s] Downloading binaries for %s (KB: %s)",
                 cve_id, binary_name, cve.get("kb_numbers"))
        pre_path, post_path = get_binary_pair(
            binary_name,
            cve.get("kb_numbers", []),
            binaries_dir,
        )
    except Exception as exc:
        log.warning("[%s] Binary download failed: %s", cve_id, exc)
        set_cve_status(cve_id, "binary_failed", error=str(exc))
        return

    diff_name = cve_id.replace("/", "-")
    try:
        log.info("[%s] Running ghidriff", cve_id)
        diff_path = run_ghidriff(pre_path, post_path, diffs_dir, diff_name)
        set_cve_status(cve_id, "diff_done", diff_path=str(diff_path))
    except Exception as exc:
        log.warning("[%s] ghidriff failed: %s", cve_id, exc)
        set_cve_status(cve_id, "diff_failed", error=str(exc))
        return

    patch_result = None
    try:
        log.info("[%s] Identifying patch function", cve_id)
        patch_result = identify_patch(cve, diff_path)
        log.info("[%s] Identified: %s (confidence=%d, type=%s)",
                 cve_id, patch_result.function_name, patch_result.confidence, patch_result.patch_type)
    except PatchNotFoundError as exc:
        log.warning("[%s] Patch identification failed: %s — falling back to full diff", cve_id, exc)
    except Exception as exc:
        log.warning("[%s] Patch identification error: %s — falling back to full diff", cve_id, exc)

    try:
        log.info("[%s] Generating blog post", cve_id)
        blog_text = generate_blog_post(cve, binary_name, patch_result=patch_result, diff_path=diff_path)
        blog_path = save_blog_post(blog_text, cve_id, blogs_dir, title=cve.get("title", ""))
        set_cve_status(cve_id, "done", blog_path=str(blog_path))
        log.info("[%s] Done → %s", cve_id, blog_path)
    except Exception as exc:
        log.warning("[%s] Blog generation failed: %s", cve_id, exc)
        set_cve_status(cve_id, "blog_failed", error=str(exc))


def run_pipeline() -> None:
    log.info("Pipeline run started")

    # Look back 90 days to catch up if this is first run, else just recent
    cutoff = datetime.utcnow() - timedelta(days=90)
    updates = list_updates(since=cutoff)
    log.info("Found %d updates since %s", len(updates), cutoff.date())

    for update in updates:
        update_id = update.get("ID") or update.get("Alias", "")
        if not update_id:
            continue
        if is_update_processed(update_id):
            log.debug("Already processed update %s", update_id)
            continue

        log.info("Processing update: %s (%s)", update_id, update.get("DocumentTitle", ""))
        try:
            cvrf = fetch_cvrf(update_id)
        except Exception as exc:
            log.error("Failed to fetch CVRF for %s: %s", update_id, exc)
            continue

        for cve in iter_cves(cvrf):
            binary_name = classify_cve(cve)
            upsert_cve(
                cve["id"], update_id, cve["title"],
                binary_name, ",".join(cve.get("kb_numbers", [])),
            )

            if binary_name is None:
                log.debug("[%s] Not a kernel CVE, skipping", cve["id"])
                continue

            existing = get_cve(cve["id"])
            if existing and existing["status"] == "done":
                log.debug("[%s] Already done", cve["id"])
                continue

            log.info("[%s] Kernel CVE: %s → %s", cve["id"], cve["title"], binary_name)
            process_cve(cve, binary_name)

        mark_update_processed(update_id)

    log.info("Pipeline run complete")


@click.command()
@click.option("--once", is_flag=True, help="Run once and exit.")
@click.option("--daemon", is_flag=True, help="Run on a recurring schedule.")
def main(once: bool, daemon: bool) -> None:
    _setup_logging()

    if not config.ANTHROPIC_API_KEY:
        log.error("ANTHROPIC_API_KEY is not set")
        sys.exit(1)

    init_db()

    if once or not daemon:
        run_pipeline()
        return

    interval = config.POLL_INTERVAL_HOURS
    log.info("Daemon mode: polling every %d hours", interval)
    run_pipeline()  # run immediately on startup
    schedule.every(interval).hours.do(run_pipeline)
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
