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
from pipeline.msrc import list_updates, fetch_cvrf, iter_cves, fetch_ground_truth
from pipeline.kernel_filter import candidate_binaries
from pipeline.winbindex import get_binary_pair_for_target, has_target
from pipeline.target_resolver import resolve_targets
from pipeline.validate import validate_patch
from pipeline.ghidriff_runner import run_ghidriff
from pipeline.patch_identifier import identify_patch, PatchNotFoundError
from pipeline.analysis_backend import BACKENDS, BackendError, make_backend
from pipeline.blog_generator import generate_blog_post, save_blog_post

# ── logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("run_cve")

# Path of the per-CVE debug log, set once the CVE id is known (see _attach_log_file).
_LOG_PATH: "Path | None" = None


def _attach_log_file(data_dir: Path, cve_id: str) -> Path:
    """Tee all logging (this run and every pipeline module) to data/logs/<cve>.log.

    Appended, with a per-run header, so a run that exits WITHOUT a report still
    leaves a full, debuggable trace (identify verdicts, validation reasons, errors).
    """
    global _LOG_PATH
    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    _LOG_PATH = logs_dir / f"{cve_id}.log"
    fh = logging.FileHandler(_LOG_PATH, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    logging.getLogger().addHandler(fh)  # root: captures run_cve + all pipeline.* loggers
    log.info("===== run %s  args=%s =====", cve_id, " ".join(sys.argv[1:]))
    return _LOG_PATH


def _print(step: int, total: int, label: str, detail: str = "") -> None:
    tag = f"[{step}/{total}]"
    detail_str = f"  {detail}" if detail else ""
    print(f"{tag} {label}{detail_str}", flush=True)


def _fail(msg: str) -> None:
    log.error(msg)  # lands in the per-CVE log file for debugging
    print(f"\n  ERROR: {msg}", file=sys.stderr)
    if _LOG_PATH is not None:
        print(f"  See log: {_LOG_PATH}", file=sys.stderr)
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
    # Authoritative first: ask the SUG API which monthly update this CVE belongs to.
    # The CVRF /Updates feed lags (often missing the newest month), so scanning it
    # fails for freshly released CVEs even though their CVRF document exists.
    from pipeline.msrc import find_update_id
    sug_uid = find_update_id(cve_id)
    if sug_uid:
        try:
            cvrf = fetch_cvrf(sug_uid)
            for cve in iter_cves(cvrf):
                if cve["id"].upper() == cve_id.upper():
                    log.info("Resolved %s to update %s via SUG API", cve_id, sug_uid)
                    return sug_uid, cve
        except Exception as e:
            log.warning("SUG-resolved update %s fetch failed: %s — falling back to feed scan",
                        sug_uid, e)

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


def run(cve_id: str, update_id: str | None, data_dir: Path, force: bool,
        skip_blog: bool = False, allow_web: bool = True,
        backend: str = "ida", ida_shutdown: bool = True) -> None:
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

    candidates = candidate_binaries(cve)
    if not candidates:
        _fail(f"{cve_id} does not appear to be a kernel CVE (no candidate binaries)")

    # Ground truth (authoritative CWE / vector / affected fixed-builds). Surface CWE + vector
    # to the identify agent and the validation gate.
    ground_truth = fetch_ground_truth(cve_id)
    cve = {**cve, "cwe_list": ground_truth.get("cwe_list", []),
           "vector_string": ground_truth.get("vector_string", "")}

    targets = resolve_targets(ground_truth)
    if not targets:
        _fail(f"{cve_id}: no affected Windows fixed-build resolved from MSRC — cannot pick a build pair")

    print(f"       Candidates: {candidates}")
    print(f"       Targets:    {[f'{t.lineage}.{t.revision}' for t in targets]}")
    print(f"       CWE:        {ground_truth.get('cwe_list')}")

    # ── Steps 2-4b: try candidate binaries until one validates ─────────────────
    # The fix for a generic "Windows Kernel" CVE often lives in a driver, not the first
    # candidate, and a binary's month-over-month delta can be pure CFR cleanup. Rather
    # than diff everything up front, diff ONE binary, identify, and validate; if the
    # validator declines, move on to the next candidate binary and repeat. Only give up
    # when every candidate has been tried.
    binaries_dir = data_dir / "binaries" / cve_id
    diffs_dir = data_dir / "diffs"
    want_ghidra_mcp = backend == "ghidra"

    def _target_for(b):
        return next((t for t in targets if has_target(b, t.lineage, t.revision)), None)

    work = [(b, _target_for(b)) for b in candidates]
    work = [(b, t) for b, t in work if t is not None]
    if not work:
        _fail(f"{cve_id}: none of {candidates} shipped a build for targets "
              f"{[f'{t.lineage}.{t.revision}' for t in targets]}")

    # Resume: if a binary's stages are already cached from a prior run, try it first so its
    # cached download/diff/identify are reused rather than recomputed.
    _cached_bin = (trace.get("binaries") or {}).get("binary_name")
    if _cached_bin in {b for b, _ in work}:
        work.sort(key=lambda bt: bt[0] != _cached_bin)

    def _attempt(binary_name, target, reuse):
        """Download + ghidriff + identify one binary.

        Returns (patch_result, diff_path, pre_build, post_build) on success, or None to
        skip this binary (download/diff/identify failed — try the next candidate).
        Owns the backend/MCP lifecycle for its identify step.
        """
        # ── download pair ──
        if reuse and trace.get("binaries"):
            c = trace.get("binaries")
            pre_path = Path(c["pre_path"]); post_path = Path(c["post_path"])
            _print(2, TOTAL_STEPS, "Binaries (cached)",
                   f"{binary_name} pre={c['pre_build']} post={c['post_build']}")
        else:
            try:
                pre_path, post_path = get_binary_pair_for_target(
                    binary_name, target.lineage, target.revision, binaries_dir)
            except Exception as e:
                print(f"  [!] {binary_name}: binary download failed ({str(e)[:120]})", flush=True)
                return None
            trace.save("binaries", {
                "pre_path": str(pre_path), "post_path": str(post_path),
                "pre_build": int(pre_path.suffix.lstrip('.')),
                "post_build": int(post_path.suffix.lstrip('.')),
                "binary_name": binary_name, "lineage": target.lineage})
            _print(2, TOTAL_STEPS, "Binaries",
                   f"{binary_name} pre={pre_path.suffix.lstrip('.')} "
                   f"post={post_path.suffix.lstrip('.')} lineage={target.lineage}")
        pre_build = int(pre_path.suffix.lstrip('.'))
        post_build = int(post_path.suffix.lstrip('.'))

        # ── ghidriff (+ concurrent MCP startup) ──
        mcp_server = None
        cached = trace.get("ghidriff") if reuse else None
        if cached:
            diff_path = Path(cached["diff_path"])
            _print(3, TOTAL_STEPS, "Ghidriff (cached)",
                   f"{cached['function_count']} changed functions")
            if want_ghidra_mcp and not trace.get("identify"):
                from pipeline.ghidriff_runner import _start_mcp_background, _GHIDRA_PROJECTS_DIR
                _base = f"ghidriff_{cve_id.replace('/', '-')}"
                _proj_name = f"{_base}-{pre_path.name}-{post_path.name}"
                _proj_dir = _GHIDRA_PROJECTS_DIR / _proj_name
                _rep_idata = _proj_dir / f"{_proj_name}.rep" / "idata"
                _gbf_files = list(_rep_idata.rglob("*.gbf")) if _rep_idata.is_dir() else []
                _project_ready = bool(_gbf_files) and any(
                    f.stat().st_size > 10 * 1024 * 1024 for f in _gbf_files)
                mcp_server = _start_mcp_background(
                    pre_path, post_path,
                    project_dir=_proj_dir if _project_ready else None,
                    project_name=_proj_name)
        else:
            _print(3, TOTAL_STEPS, "Running ghidriff (20-40 min)...")
            try:
                diff_path, mcp_server = run_ghidriff(
                    pre_path, post_path, diffs_dir, cve_id.replace("/", "-"),
                    start_mcp=want_ghidra_mcp)
            except Exception as e:
                print(f"  [!] {binary_name}: ghidriff failed ({str(e)[:120]})", flush=True)
                return None
            from pipeline.patch_identifier import parse_ghidriff_sections
            fn_count = len(parse_ghidriff_sections(diff_path))
            _print(3, TOTAL_STEPS, "Ghidriff",
                   f"{fn_count} changed functions → {diff_path.name}")
            trace.save("ghidriff", {"diff_path": str(diff_path), "function_count": fn_count})

        # ── identify ──
        _print(4, TOTAL_STEPS, "Identifying patch function...")
        patch_result = None
        cached = trace.get("identify") if reuse else None
        if cached:
            co = cached.get("co_patches", []) or []
            co_str = (" + " + ", ".join(f"{c['name']} ({c['confidence']}%)" for c in co)) if co else ""
            _print(4, TOTAL_STEPS, "Identify (cached)",
                   f"{cached['function_name']} ({cached['confidence']}%){co_str}")
            from pipeline.patch_identifier import PatchResult
            patch_result = PatchResult(
                function_name=cached["function_name"], confidence=cached["confidence"],
                reasoning=cached["reasoning"], patch_type=cached["patch_type"],
                full_diff=cached["full_diff"], candidates_evaluated=cached["candidates_evaluated"],
                heuristic_scores=[], agent_evals=[], co_patches=co,
                decompiled_pre=cached.get("decompiled_pre", ""),
                decompiled_post=cached.get("decompiled_post", ""),
                callers=cached.get("callers", []),
                vulnerability_description=cached.get("vulnerability_description", ""),
                fix_description=cached.get("fix_description", ""),
                attack_vector=cached.get("attack_vector", ""))
            if mcp_server:
                mcp_server.stop(); mcp_server = None
        else:
            analysis_backend = None
            if backend == "ghidra":
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
                        analysis_backend = make_backend("ghidra", ghidra_server=mcp_server)
            else:
                try:
                    analysis_backend = make_backend(
                        backend, pre_binary=pre_path, post_binary=post_path, cve_id=cve_id,
                        ida_shutdown=ida_shutdown)
                    analysis_backend.start()
                except BackendError as e:
                    _fail(f"{backend} backend unavailable: {e}")
                except Exception as e:
                    _fail(f"{backend} backend failed to start: {e}")
            try:
                if analysis_backend:
                    from pipeline.patch_identifier import identify_patch_with_mcp
                    patch_result = identify_patch_with_mcp(cve, diff_path, analysis_backend,
                                                           allow_web=allow_web)
                else:
                    patch_result = identify_patch(cve, diff_path)
                co = patch_result.co_patches or []
                co_str = (" + " + ", ".join(f"{c['name']} ({c['confidence']}%)" for c in co)) if co else ""
                _print(4, TOTAL_STEPS, "Identify",
                       f"{patch_result.function_name} ({patch_result.confidence}%, "
                       f"type={patch_result.patch_type}){co_str}")
                trace.save("identify", {
                    "function_name": patch_result.function_name,
                    "confidence": patch_result.confidence, "reasoning": patch_result.reasoning,
                    "patch_type": patch_result.patch_type, "full_diff": patch_result.full_diff,
                    "candidates_evaluated": patch_result.candidates_evaluated,
                    "heuristic_scores": patch_result.heuristic_scores,
                    "agent_evals": patch_result.agent_evals, "co_patches": patch_result.co_patches,
                    "decompiled_pre": patch_result.decompiled_pre,
                    "decompiled_post": patch_result.decompiled_post,
                    "callers": patch_result.callers,
                    "vulnerability_description": patch_result.vulnerability_description,
                    "fix_description": patch_result.fix_description,
                    "attack_vector": patch_result.attack_vector})
            except PatchNotFoundError as e:
                print(f"  [!] {binary_name}: no patch identified ({e})", flush=True)
                patch_result = None
            except Exception as e:
                print(f"  [!] {binary_name}: identification error ({str(e)[:120]})", flush=True)
                patch_result = None
            finally:
                # Ghidra: stop the Java server. IDA: tear down tunnels, leave VM instances warm.
                if analysis_backend:
                    analysis_backend.stop()
                elif mcp_server:
                    mcp_server.stop()

        if patch_result is None:
            return None
        return patch_result, diff_path, pre_build, post_build

    patch_result = None
    diff_path = None
    binary_name = None
    target = None
    pre_build = post_build = None
    attempts: list[str] = []

    for attempt_i, (cand_bin, cand_target) in enumerate(work, 1):
        reuse = (trace.get("binaries") or {}).get("binary_name") == cand_bin
        if not reuse:
            for _k in ("binaries", "ghidriff", "identify", "blog"):
                trace.clear(_k)
        print(f"  [binary {attempt_i}/{len(work)}] {cand_bin} "
              f"({cand_target.lineage}.{cand_target.revision})", flush=True)
        result = _attempt(cand_bin, cand_target, reuse)
        if result is None:
            attempts.append(f"{cand_bin}: no identifiable patch")
            for _k in ("binaries", "ghidriff", "identify", "blog"):
                trace.clear(_k)
            continue

        cand_patch, cand_diff, cand_pre, cand_post = result
        ok, reasons = validate_patch(cve, ground_truth, cand_patch)
        for r in reasons:
            print(f"       validate: {r}")
        if ok:
            patch_result, diff_path = cand_patch, cand_diff
            pre_build, post_build = cand_pre, cand_post
            binary_name, target = cand_bin, cand_target
            break

        fails = [r for r in reasons if r.startswith("FAIL")]
        attempts.append(f"{cand_bin}:{cand_patch.function_name} declined ({'; '.join(fails)})")
        print(f"  [!] validator declined {cand_patch.function_name} in {cand_bin} "
              f"— trying next candidate binary", flush=True)
        for _k in ("binaries", "ghidriff", "identify", "blog"):
            trace.clear(_k)

    if patch_result is None:
        _fail(f"{cve_id}: no candidate binary produced a validated patch after "
              f"{len(work)} attempt(s) — refusing to emit an unverified report. "
              f"Tried: {' | '.join(attempts)}")


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
            blog_text, blog_prompt = generate_blog_post(
                cve, binary_name,
                patch_result=patch_result,
                versions={"pre_build": pre_build, "post_build": post_build,
                          "lineage": target.lineage,
                          "patch_date": ground_truth.get("release_date", "")},
            )
        except Exception as e:
            _fail(f"Blog generation failed: {e}")

        blogs_dir = data_dir / "blogs"
        blog_path = save_blog_post(blog_text, cve_id, blogs_dir,
                                   title=cve.get("title", ""), prompt=blog_prompt)
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
    parser.add_argument(
        "--disable-web",
        action="store_true",
        default=False,
        help=(
            "Restrict the MCP identify agent to the analysis backend's tools only, "
            "blocking internet access. By default the agent can also use built-in tools "
            "(Bash, Read, etc.) which allows it to consult external resources."
        ),
    )
    parser.add_argument(
        "--backend",
        choices=BACKENDS,
        default="ida",
        help=(
            "Disassembler backend for the identify stage. 'ida' (default) drives IDA "
            "Pro on the Windows VM over an SSH tunnel (see scripts/start_ida_tunnel.sh); if it "
            "is unavailable the run fails with an error rather than falling back. "
            "'ghidra' uses the local headless GhidraMCP server. Ghidriff still produces "
            "the diff either way."
        ),
    )
    parser.add_argument(
        "--no-ida-shutdown",
        dest="ida_shutdown",
        action="store_false",
        default=True,
        help=(
            "For --backend ida: leave the IDA instances running on the VM after the "
            "identify stage so a later run can reuse the warm databases. By default "
            "IDA is closed once the stage finishes. The .i64 is saved either way."
        ),
    )
    args = parser.parse_args()

    cve_id = _parse_cve_id(args.cve)
    data_dir = Path(args.data_dir)

    log_path = _attach_log_file(data_dir, cve_id)
    print(f"\nkernal-cve-pipeline  ·  {cve_id}   (log: {log_path})\n")

    # --from-stage: clear that stage and all subsequent ones
    if args.from_stage:
        stages_order = ["msrc", "binaries", "ghidriff", "identify", "blog"]
        trace = Trace(data_dir / "traces" / f"{cve_id}.json")
        idx = stages_order.index(args.from_stage)
        for stage in stages_order[idx:]:
            trace.clear(stage)
        print(f"  Cleared stages from '{args.from_stage}' onwards.\n")

    run(cve_id, args.update_id, data_dir, force=args.force, skip_blog=args.skip_blog,
        allow_web=not args.disable_web, backend=args.backend,
        ida_shutdown=args.ida_shutdown)


if __name__ == "__main__":
    main()
