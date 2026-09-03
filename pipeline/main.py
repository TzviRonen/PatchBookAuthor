"""Orchestrator: poll MSRC → filter → download → diff → blog."""
import logging
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import click
import schedule

from pipeline import config
from pipeline.database import (
    init_db, is_update_processed, mark_update_processed,
    upsert_cve, set_cve_status, set_cve_notes, get_cve,
)
from pipeline.msrc import list_updates, fetch_cvrf, iter_cves, fetch_ground_truth
from pipeline.kernel_filter import candidate_binaries
from pipeline.winbindex import get_binary_pair_for_target, has_target
from pipeline.ghidriff_runner import run_ghidriff
from pipeline.patch_identifier import identify_patch, PatchNotFoundError
from pipeline.target_resolver import resolve_targets
from pipeline.validate import validate_patch
from pipeline.blog_generator import generate_blog_post, save_blog_post


def _setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


log = logging.getLogger("pipeline.main")


def _write_diag_log(cve_id: str, status: str, diagnostics: list[str]) -> None:
    """Persist per-CVE diagnostics to data/logs/<cve>.log so a run that produced no
    report is debuggable without querying the DB."""
    try:
        logs_dir = config.DATA_DIR / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        with open(logs_dir / f"{cve_id}.log", "a", encoding="utf-8") as fh:
            fh.write(f"\n===== {datetime.utcnow().isoformat()}  {cve_id}  status={status} =====\n")
            for line in diagnostics:
                fh.write(line + "\n")
    except Exception as exc:
        log.warning("[%s] could not write diagnostics log: %s", cve_id, exc)


def _emit_report(cve: dict, binary_name: str, patch_result, target, pre_path,
                 diagnostics: list[str]) -> bool:
    """Generate + save the blog for a validated patch. Returns True on success."""
    cve_id = cve["id"]
    # _download_binary names files "<binary>.<revision>"; recover the pre revision.
    pre_rev = None
    m = re.search(r"\.(\d+)$", pre_path.name)
    if m:
        pre_rev = int(m.group(1))
    versions = {"pre_build": pre_rev, "post_build": target.revision, "lineage": target.lineage}
    try:
        blog_text, blog_prompt = generate_blog_post(
            cve, binary_name, patch_result=patch_result, versions=versions,
        )
        blog_path = save_blog_post(blog_text, cve_id, config.BLOGS_DIR,
                                   title=cve.get("title", ""), prompt=blog_prompt)
        set_cve_status(cve_id, "done", blog_path=str(blog_path))
        set_cve_notes(cve_id, "VALIDATED\n" + "\n".join(diagnostics))
        _write_diag_log(cve_id, "done", diagnostics)
        log.info("[%s] Done → %s", cve_id, blog_path)
        return True
    except Exception as exc:
        log.warning("[%s] Blog generation failed: %s", cve_id, exc)
        set_cve_status(cve_id, "blog_failed", error=str(exc))
        return False


def process_cve(cve: dict, update_id: str) -> None:
    """Research loop: try each affected lineage × candidate binary until a patch validates.

    A report is emitted ONLY when identify_patch finds a function that validate_patch
    confirms matches the CVE's ground truth. Otherwise the CVE is marked 'unresolved'
    and NO report is written — the pipeline never publishes an unverified patch.
    """
    cve_id = cve["id"]
    binaries_dir = config.BINARIES_DIR / cve_id

    # ── Ground truth (authoritative CWE / vector / affected fixed-builds) ──
    ground_truth = fetch_ground_truth(cve_id)
    # Surface CWE + vector to the identify agent so it matches the real bug class.
    cve = {**cve, "cwe_list": ground_truth.get("cwe_list", []),
           "vector_string": ground_truth.get("vector_string", "")}

    targets = resolve_targets(ground_truth)
    if not targets:
        log.warning("[%s] No affected fixed-build resolved — marking unresolved", cve_id)
        set_cve_status(cve_id, "unresolved", error="no affected fixed-build from MSRC")
        _write_diag_log(cve_id, "unresolved", ["no affected fixed-build resolved from MSRC affected-product data"])
        return

    candidates = candidate_binaries(cve)
    diagnostics: list[str] = []

    for target in targets:
        for binary_name in candidates:
            if not has_target(binary_name, target.lineage, target.revision):
                continue  # this binary isn't shipped/affected on this lineage+revision
            tag = f"{binary_name}@{target.lineage}.{target.revision}"
            try:
                log.info("[%s] Trying %s", cve_id, tag)
                pre_path, post_path = get_binary_pair_for_target(
                    binary_name, target.lineage, target.revision, binaries_dir,
                )
            except Exception as exc:
                diagnostics.append(f"{tag}: binary pair failed: {exc}")
                continue

            diff_name = f"{cve_id.replace('/', '-')}-{binary_name}-{target.lineage}"
            try:
                # start_mcp=False: the text-diff identify path only needs the .md; the MCP
                # server is for the interactive IDA/Ghidra backend used by run_cve.py.
                diff_path, _mcp = run_ghidriff(
                    pre_path, post_path, config.DIFFS_DIR, diff_name, start_mcp=False,
                )
            except Exception as exc:
                diagnostics.append(f"{tag}: ghidriff failed: {exc}")
                continue

            try:
                patch_result = identify_patch(cve, diff_path)
            except PatchNotFoundError as exc:
                diagnostics.append(f"{tag}: no candidate identified ({exc})")
                continue
            except Exception as exc:
                diagnostics.append(f"{tag}: identify error ({exc})")
                continue

            ok, reasons = validate_patch(cve, ground_truth, patch_result)
            diagnostics.append(f"{tag}: candidate={patch_result.function_name} "
                               f"conf={patch_result.confidence} valid={ok} :: {'; '.join(reasons)}")
            if not ok:
                log.info("[%s] %s: %s rejected by validation — keep researching",
                         cve_id, tag, patch_result.function_name)
                continue

            log.info("[%s] VALIDATED %s in %s", cve_id, patch_result.function_name, tag)
            if _emit_report(cve, binary_name, patch_result, target, pre_path, diagnostics):
                return

    # Nothing validated across all targets × binaries → do NOT publish anything.
    log.warning("[%s] Unresolved after %d attempt(s) — no report emitted", cve_id, len(diagnostics))
    set_cve_status(cve_id, "unresolved", error="no validated patch")
    set_cve_notes(cve_id, "UNRESOLVED\n" + "\n".join(diagnostics))
    _write_diag_log(cve_id, "unresolved", diagnostics)


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
            cands = candidate_binaries(cve)
            upsert_cve(
                cve["id"], update_id, cve["title"],
                cands[0] if cands else None, ",".join(cve.get("kb_numbers", [])),
            )

            if not cands:
                log.debug("[%s] Not a kernel CVE, skipping", cve["id"])
                continue

            existing = get_cve(cve["id"])
            if existing and existing["status"] in ("done", "unresolved"):
                log.debug("[%s] Already %s", cve["id"], existing["status"])
                continue

            log.info("[%s] Kernel CVE: %s → candidates %s", cve["id"], cve["title"], cands)
            process_cve(cve, update_id)

        mark_update_processed(update_id)

    log.info("Pipeline run complete")


@click.command()
@click.option("--once", is_flag=True, help="Run once and exit.")
@click.option("--daemon", is_flag=True, help="Run on a recurring schedule.")
def main(once: bool, daemon: bool) -> None:
    _setup_logging()

    # NB: the identify and blog stages call the `claude -p` CLI, which authenticates via its
    # own OAuth/subscription login — no ANTHROPIC_API_KEY is used or needed. Requiring it here
    # was misleading, and *setting* it makes the CLI prefer a (often invalid) API key over the
    # working OAuth login. So there is deliberately no ANTHROPIC_API_KEY check.

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
