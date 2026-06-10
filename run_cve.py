#!/usr/bin/env python3
"""
Run the kernel CVE pipeline end-to-end for a single CVE.

Usage:
    python3 run_cve.py CVE-2024-30088
    python3 run_cve.py https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088
    python3 run_cve.py CVE-2024-30088 --data-dir ./data --force
    python3 run_cve.py CVE-2024-30088 --update-id 2024-Jun   # skip MSRC search
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from pipeline import config
from pipeline.msrc import list_updates, fetch_cvrf, iter_cves
from pipeline.kernel_filter import classify_cve
from pipeline.winbindex import get_binary_pair
from pipeline.ghidriff_runner import run_ghidriff
from pipeline.patch_identifier import identify_patch, PatchNotFoundError
from pipeline.blog_generator import generate_blog_post, save_blog_post

# ── logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("run_cve")


def _print(step: int, total: int, label: str, detail: str = "") -> None:
    tag = f"[{step}/{total}]"
    detail_str = f"  {detail}" if detail else ""
    print(f"{tag} {label}{detail_str}", flush=True)


def _fail(msg: str) -> None:
    print(f"\n  ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ── trace file (crash recovery) ────────────────────────────────────────────────

class Trace:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text())
            except Exception:
                self._data = {}

    def get(self, stage: str):
        s = self._data.get("stages", {}).get(stage, {})
        return s.get("result") if s.get("status") == "done" else None

    def save(self, stage: str, result: dict) -> None:
        self._data.setdefault("stages", {})[stage] = {
            "status": "done",
            "completed_at": datetime.utcnow().isoformat(),
            "result": result,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def clear(self, stage: str) -> None:
        self._data.get("stages", {}).pop(stage, None)
        if self.path.exists():
            self.path.write_text(json.dumps(self._data, indent=2))


# ── MSRC search ────────────────────────────────────────────────────────────────

def _parse_cve_id(raw: str) -> str:
    """Accept a CVE ID or an MSRC URL and return the CVE ID."""
    m = re.search(r"CVE-\d{4}-\d+", raw, re.IGNORECASE)
    if not m:
        _fail(f"Could not find a CVE ID in: {raw!r}")
    return m.group(0).upper()


def _cve_year(cve_id: str) -> int:
    return int(cve_id.split("-")[1])


def _update_id_year(update: dict) -> int | None:
    """Extract the year from the update ID (e.g. '2026-Apr' → 2026)."""
    uid = update.get("ID") or update.get("Alias", "")
    m = re.match(r"^(\d{4})-", uid)
    return int(m.group(1)) if m else None


def find_update_for_cve(cve_id: str) -> tuple[str, dict]:
    """Search MSRC monthly updates to find the one containing cve_id.

    Returns (update_id, cve_dict) e.g. ("2024-Jun", {...}).
    Searches year-1 through year+1 (most recent first) to handle CVEs
    disclosed in one year but patched in an adjacent year.
    """
    year = _cve_year(cve_id)
    # Fetch all updates without a date filter — we filter by ID year below
    # (CurrentReleaseDate is unreliable: MSRC bumps it on every revision)
    all_updates = list_updates()
    search_years = {year - 1, year, year + 1}
    updates_sorted = [
        u for u in all_updates
        if _update_id_year(u) in search_years
    ]
    # Most recent first so we find the fix quickly
    updates_sorted.sort(key=lambda u: u.get("ID", ""), reverse=True)

    searched: list[str] = []
    for update in updates_sorted:
        uid = update.get("ID") or update.get("Alias", "")
        if not uid:
            continue
        try:
            cvrf = fetch_cvrf(uid)
        except Exception as e:
            log.warning("Could not fetch %s: %s", uid, e)
            continue
        searched.append(uid)
        for cve in iter_cves(cvrf):
            if cve["id"].upper() == cve_id.upper():
                return uid, cve

    searched_str = ", ".join(searched) if searched else "(none)"
    _fail(
        f"{cve_id} not found in any MSRC update.\n"
        f"  Searched {len(searched)} update(s): {searched_str}\n\n"
        f"  Possible reasons:\n"
        f"  • The CVE ID is incorrect or doesn't exist in MSRC yet.\n"
        f"  • The fix ships in a different month — try --update-id (e.g. --update-id 2026-Jun).\n"
        f"  • Patch Tuesday for this month hasn't happened yet — the CVRF may be incomplete.\n"
        f"  • This CVE may be tracked under a different product (not ntoskrnl)."
    )


# ── main ───────────────────────────────────────────────────────────────────────

TOTAL_STEPS = 6


def run(cve_id: str, update_id: str | None, data_dir: Path, force: bool, skip_blog: bool = False) -> None:
    traces_dir = data_dir / "traces"
    trace = Trace(traces_dir / f"{cve_id}.json")

    if force:
        # Clear all cached stages
        for stage in ("msrc", "binaries", "ghidriff", "identify", "blog"):
            trace.clear(stage)

    # ── Step 1: Resolve CVE from MSRC ──────────────────────────────────────────
    _print(1, TOTAL_STEPS, "Searching MSRC...")

    cached = trace.get("msrc")
    if cached:
        cve = cached["cve"]
        update_id = cached["update_id"]
        _print(1, TOTAL_STEPS, "MSRC (cached)", f"{cve['title']} — {update_id}")
    else:
        if update_id:
            try:
                cvrf = fetch_cvrf(update_id)
            except Exception as e:
                _fail(f"Could not fetch MSRC update {update_id!r}: {e}")
            cve = next(
                (c for c in iter_cves(cvrf) if c["id"].upper() == cve_id),
                None,
            )
            if cve is None:
                _fail(f"{cve_id} not found in update {update_id}")
        else:
            update_id, cve = find_update_for_cve(cve_id)

        _print(1, TOTAL_STEPS, "MSRC", f"{cve['title']} — {update_id}")
        trace.save("msrc", {"update_id": update_id, "cve": cve})

    binary_name = classify_cve(cve)
    if binary_name is None:
        _fail(f"{cve_id} does not appear to be a kernel CVE (classify_cve returned None)")

    print(f"       Binary: {binary_name}")
    print(f"       KBs:    {', '.join(cve.get('kb_numbers', []) or ['(none)'])}")

    # ── Step 2: Download binaries ───────────────────────────────────────────────
    _print(2, TOTAL_STEPS, "Downloading binaries...")

    cached = trace.get("binaries")
    if cached:
        pre_path = Path(cached["pre_path"])
        post_path = Path(cached["post_path"])
        _print(2, TOTAL_STEPS, "Binaries (cached)",
               f"pre={cached['pre_build']}  post={cached['post_build']}")
    else:
        binaries_dir = data_dir / "binaries" / cve_id
        try:
            pre_path, post_path = get_binary_pair(
                binary_name, cve.get("kb_numbers", []), binaries_dir
            )
        except Exception as e:
            _fail(f"Binary download failed: {e}")

        pre_build = int(pre_path.suffix.lstrip("."))
        post_build = int(post_path.suffix.lstrip("."))
        _print(2, TOTAL_STEPS, "Binaries",
               f"pre={pre_build}  post={post_build}  ({binary_name})")
        trace.save("binaries", {
            "pre_path": str(pre_path), "post_path": str(post_path),
            "pre_build": pre_build, "post_build": post_build,
        })

    # ── Step 3: Ghidriff (+ concurrent MCP server startup) ────────────────────
    _print(3, TOTAL_STEPS, "Running ghidriff (20-40 min)...")

    mcp_server = None
    cached = trace.get("ghidriff")
    if cached:
        diff_path = Path(cached["diff_path"])
        _print(3, TOTAL_STEPS, "Ghidriff (cached)",
               f"{cached['function_count']} changed functions")
        # Diff is cached — still start MCP if identify stage will need it
        if not trace.get("identify"):
            from pipeline.ghidriff_runner import _start_mcp_background, _GHIDRA_PROJECTS_DIR
            _base = f"ghidriff_{cve_id.replace('/', '-')}"
            _proj_name = f"{_base}-{pre_path.name}-{post_path.name}"
            _proj_dir = _GHIDRA_PROJECTS_DIR / _proj_name
            _rep_idata = _proj_dir / f"{_proj_name}.rep" / "idata"
            _gbf_files = list(_rep_idata.rglob("*.gbf")) if _rep_idata.is_dir() else []
            _project_ready = bool(_gbf_files) and any(
                f.stat().st_size > 10 * 1024 * 1024 for f in _gbf_files
            )
            mcp_server = _start_mcp_background(
                pre_path, post_path,
                project_dir=_proj_dir if _project_ready else None,
                project_name=_proj_name,
            )
    else:
        diffs_dir = data_dir / "diffs"
        diff_name = cve_id.replace("/", "-")
        try:
            diff_path, mcp_server = run_ghidriff(pre_path, post_path, diffs_dir, diff_name)
        except Exception as e:
            _fail(f"Ghidriff failed: {e}")

        from pipeline.patch_identifier import parse_ghidriff_sections
        fn_count = len(parse_ghidriff_sections(diff_path))
        _print(3, TOTAL_STEPS, "Ghidriff",
               f"{fn_count} changed functions → {diff_path.name}")
        trace.save("ghidriff", {
            "diff_path": str(diff_path),
            "function_count": fn_count,
        })

    # ── Step 4: Identify patch ─────────────────────────────────────────────────
    _print(4, TOTAL_STEPS, "Identifying patch function...")

    patch_result = None
    cached = trace.get("identify")
    if cached:
        co = cached.get("co_patches", []) or []
        co_str = ""
        if co:
            co_str = " + " + ", ".join(f"{c['name']} ({c['confidence']}%)" for c in co)
        _print(4, TOTAL_STEPS, "Identify (cached)",
               f"{cached['function_name']} ({cached['confidence']}%){co_str}")
        from pipeline.patch_identifier import PatchResult
        patch_result = PatchResult(
            function_name=cached["function_name"],
            confidence=cached["confidence"],
            reasoning=cached["reasoning"],
            patch_type=cached["patch_type"],
            full_diff=cached["full_diff"],
            candidates_evaluated=cached["candidates_evaluated"],
            heuristic_scores=[],
            agent_evals=[],
            co_patches=co,
            decompiled_pre=cached.get("decompiled_pre", ""),
            decompiled_post=cached.get("decompiled_post", ""),
            callers=cached.get("callers", []),
            vulnerability_description=cached.get("vulnerability_description", ""),
            fix_description=cached.get("fix_description", ""),
            attack_vector=cached.get("attack_vector", ""),
        )
        # No MCP needed — stop server if it was started
        if mcp_server:
            mcp_server.stop()
            mcp_server = None
    else:
        # Wait for MCP server to finish starting (ran concurrently with ghidriff)
        mcp_ready = False
        if mcp_server:
            ready_event = getattr(mcp_server, "_ready_event", None)
            start_error = getattr(mcp_server, "_start_error", [])
            if ready_event:
                print("  [mcp] waiting for MCP server to be ready ...", flush=True)
                ready_event.wait()
            if start_error:
                print(f"  [mcp] WARNING: MCP server failed ({start_error[0]}) — "
                      "falling back to one-shot identify", flush=True)
                mcp_server = None
            elif mcp_server.pre and mcp_server.post:
                mcp_ready = True

        try:
            if mcp_ready and mcp_server:
                from pipeline.patch_identifier import identify_patch_with_mcp
                patch_result = identify_patch_with_mcp(cve, diff_path, mcp_server)
            else:
                patch_result = identify_patch(cve, diff_path)

            co = patch_result.co_patches or []
            co_str = ""
            if co:
                co_str = " + " + ", ".join(f"{c['name']} ({c['confidence']}%)" for c in co)
            _print(4, TOTAL_STEPS, "Identify",
                   f"{patch_result.function_name} ({patch_result.confidence}%, "
                   f"type={patch_result.patch_type}){co_str}")
            trace.save("identify", {
                "function_name": patch_result.function_name,
                "confidence": patch_result.confidence,
                "reasoning": patch_result.reasoning,
                "patch_type": patch_result.patch_type,
                "full_diff": patch_result.full_diff,
                "candidates_evaluated": patch_result.candidates_evaluated,
                "heuristic_scores": patch_result.heuristic_scores,
                "agent_evals": patch_result.agent_evals,
                "co_patches": patch_result.co_patches,
                "decompiled_pre": patch_result.decompiled_pre,
                "decompiled_post": patch_result.decompiled_post,
                "callers": patch_result.callers,
                "vulnerability_description": patch_result.vulnerability_description,
                "fix_description": patch_result.fix_description,
                "attack_vector": patch_result.attack_vector,
            })
        except PatchNotFoundError as e:
            print(f"       WARNING: {e} — falling back to full diff for blog")
        except Exception as e:
            print(f"       WARNING: patch identification error: {e} — falling back to full diff")
        finally:
            if mcp_server:
                mcp_server.stop()
                mcp_server = None

    # ── Step 5: Generate blog post ─────────────────────────────────────────────
    if skip_blog:
        _print(5, TOTAL_STEPS, "Blog post skipped (--skip-blog)")
        _print(6, TOTAL_STEPS, "Done")
        print()
        if patch_result:
            print(f"  Patch fn  : {patch_result.function_name} ({patch_result.confidence}% confidence)")
            print(f"  Reasoning : {patch_result.reasoning}")
            for co in (patch_result.co_patches or []):
                print(f"  Co-patch  : {co['name']} ({co['confidence']}% confidence)")
                print(f"  Reasoning : {co['reasoning']}")
        print(f"  Diff      : {diff_path}")
        return

    _print(5, TOTAL_STEPS, "Generating blog post...")

    cached = trace.get("blog")
    if cached:
        blog_path = Path(cached["blog_path"])
        _print(5, TOTAL_STEPS, "Blog (cached)", str(blog_path))
    else:
        try:
            blog_text = generate_blog_post(
                cve, binary_name,
                patch_result=patch_result,
                diff_path=diff_path if patch_result is None else None,
            )
        except Exception as e:
            _fail(f"Blog generation failed: {e}")

        blogs_dir = data_dir / "blogs"
        blog_path = save_blog_post(blog_text, cve_id, blogs_dir, title=cve.get("title", ""))
        _print(5, TOTAL_STEPS, "Blog post written", str(blog_path))
        trace.save("blog", {"blog_path": str(blog_path)})

    # ── Step 6: Done ───────────────────────────────────────────────────────────
    _print(6, TOTAL_STEPS, "Done", f"Blog → {blog_path}")
    print()
    print(f"  Blog post : {blog_path}")
    print(f"  Diff      : {diff_path}")
    if patch_result:
        print(f"  Patch fn  : {patch_result.function_name} ({patch_result.confidence}% confidence)")
        for co in (patch_result.co_patches or []):
            print(f"  Co-patch  : {co['name']} ({co['confidence']}% confidence)")


# ── entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the kernel CVE pipeline for a single CVE.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "cve",
        metavar="CVE_OR_URL",
        help="CVE ID (CVE-2024-30088) or MSRC URL",
    )
    parser.add_argument(
        "--update-id",
        metavar="ID",
        help="MSRC update month ID (e.g. 2024-Jun). If omitted, searched automatically.",
    )
    parser.add_argument(
        "--data-dir",
        metavar="DIR",
        default=str(config.DATA_DIR),
        help=f"Root data directory (default: {config.DATA_DIR})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Ignore cached stage results and re-run everything.",
    )
    parser.add_argument(
        "--skip-blog",
        action="store_true",
        help="Stop after the identify stage — skip blog post generation.",
    )
    parser.add_argument(
        "--from-stage",
        metavar="STAGE",
        choices=["msrc", "binaries", "ghidriff", "identify", "blog"],
        help="Clear and re-run from this stage onwards (ignores --force).",
    )
    args = parser.parse_args()

    cve_id = _parse_cve_id(args.cve)
    data_dir = Path(args.data_dir)

    print(f"\nkernal-cve-pipeline  ·  {cve_id}\n")

    # --from-stage: clear that stage and all subsequent ones
    if args.from_stage:
        stages_order = ["msrc", "binaries", "ghidriff", "identify", "blog"]
        trace = Trace(data_dir / "traces" / f"{cve_id}.json")
        idx = stages_order.index(args.from_stage)
        for stage in stages_order[idx:]:
            trace.clear(stage)
        print(f"  Cleared stages from '{args.from_stage}' onwards.\n")

    run(cve_id, args.update_id, data_dir, force=args.force, skip_blog=args.skip_blog)


if __name__ == "__main__":
    main()
