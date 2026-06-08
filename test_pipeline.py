#!/usr/bin/env python3
"""
Test harness for CVE pipeline against CVE-2024-30088 (ntoskrnl.exe TOCTOU).

Stages run outside Docker for fast iteration. Results cached in run_trace.json
so you can resume after a crash without re-running expensive stages.

Usage:
    python3 test_pipeline.py --stage msrc
    python3 test_pipeline.py --stage winbindex
    python3 test_pipeline.py --stage ghidriff
    python3 test_pipeline.py --stage identify
    python3 test_pipeline.py --stage all
    python3 test_pipeline.py --stage all --force   # ignore cached results
"""
import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── Ground truth for CVE-2024-30088 ──────────────────────────────────────────
CVE_ID              = "CVE-2024-30088"
UPDATE_ID           = "2024-Jun"
EXPECTED_KB         = "KB5039211"
BINARY              = "ntoskrnl.exe"
GROUND_TRUTH_FN     = "AuthzBasepCopyoutInternalSecurityAttributes"
EXPECTED_POST_REVISION = 4522   # file version 10.0.19041.4522 (OS build 19044/19045.4529)

# ── Paths ─────────────────────────────────────────────────────────────────────
WORKSPACE     = Path(__file__).parent
DATA_DIR      = WORKSPACE / "data"
FIXTURES_DIR  = WORKSPACE / "fixtures"
BINARIES_DIR  = DATA_DIR / "binaries" / CVE_ID
DIFFS_DIR     = DATA_DIR / "diffs"
TRACE_FILE    = DATA_DIR / "run_trace.json"
FIXTURE_MSRC  = FIXTURES_DIR / f"msrc_{UPDATE_ID.lower().replace(' ', '')}.json"

for d in (DATA_DIR, FIXTURES_DIR, BINARIES_DIR, DIFFS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("test")


# ── Trace helpers ─────────────────────────────────────────────────────────────

def _load_trace() -> dict:
    if TRACE_FILE.exists():
        try:
            return json.loads(TRACE_FILE.read_text())
        except Exception:
            pass
    return {"cve_id": CVE_ID, "run_started": _now(), "stages": {}}


def _save_trace(trace: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = TRACE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(trace, indent=2))
    tmp.rename(TRACE_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stage_done(trace: dict, stage: str) -> bool:
    return trace.get("stages", {}).get(stage, {}).get("status") == "done"


def _mark_done(trace: dict, stage: str, result: dict) -> None:
    trace.setdefault("stages", {})[stage] = {
        "status": "done",
        "completed_at": _now(),
        "result": result,
    }
    _save_trace(trace)


def _mark_failed(trace: dict, stage: str, error: str) -> None:
    trace.setdefault("stages", {})[stage] = {
        "status": "failed",
        "failed_at": _now(),
        "error": error,
    }
    _save_trace(trace)


# ── Formatting helpers ────────────────────────────────────────────────────────

def PASS(msg: str) -> None:
    print(f"\033[32m  ✓ PASS\033[0m  {msg}")


def FAIL(msg: str) -> None:
    print(f"\033[31m  ✗ FAIL\033[0m  {msg}")


def INFO(msg: str) -> None:
    print(f"       {msg}")


# ═════════════════════════════════════════════════════════════════════════════
# Stage 1: MSRC
# ═════════════════════════════════════════════════════════════════════════════

def stage_msrc(trace: dict, force: bool) -> bool:
    print("\n[STAGE 1: MSRC]")

    if not force and _stage_done(trace, "msrc"):
        r = trace["stages"]["msrc"]["result"]
        PASS(f"cached — title='{r.get('title', '')[:60]}' kb={r.get('kb_numbers')}")
        return True

    from pipeline.msrc import fetch_cvrf, iter_cves
    from pipeline.kernel_filter import classify_cve

    # Use fixture if available, else fetch and save
    if FIXTURE_MSRC.exists() and not force:
        INFO(f"Loading MSRC fixture from {FIXTURE_MSRC}")
        cvrf = json.loads(FIXTURE_MSRC.read_text())
    else:
        INFO(f"Fetching MSRC CVRF for {UPDATE_ID}...")
        try:
            cvrf = fetch_cvrf(UPDATE_ID)
        except Exception as e:
            FAIL(f"fetch_cvrf failed: {e}")
            _mark_failed(trace, "msrc", str(e))
            return False
        FIXTURE_MSRC.write_text(json.dumps(cvrf, indent=2))
        INFO(f"Saved fixture → {FIXTURE_MSRC}")

    # Find our CVE
    cve_record = None
    all_cves = list(iter_cves(cvrf))
    INFO(f"Total CVEs in {UPDATE_ID}: {len(all_cves)}")

    for cve in all_cves:
        if cve["id"] == CVE_ID:
            cve_record = cve
            break

    if not cve_record:
        FAIL(f"{CVE_ID} not found in {UPDATE_ID} CVRF")
        _mark_failed(trace, "msrc", f"{CVE_ID} not in document")
        return False

    PASS(f"Found {CVE_ID}")
    INFO(f"  title: {cve_record.get('title', '')}")
    INFO(f"  kb_numbers: {cve_record.get('kb_numbers', [])}")
    INFO(f"  cvss: {cve_record.get('cvss')}")
    INFO(f"  description (first 200): {cve_record.get('description', '')[:200]}")

    passed = True

    if EXPECTED_KB not in cve_record.get("kb_numbers", []):
        FAIL(f"Expected KB {EXPECTED_KB} not in {cve_record.get('kb_numbers')}")
        passed = False
    else:
        PASS(f"KB {EXPECTED_KB} found")

    binary = classify_cve(cve_record)
    if binary != BINARY:
        FAIL(f"kernel_filter returned '{binary}', expected '{BINARY}'")
        passed = False
    else:
        PASS(f"kernel_filter → {binary}")

    if passed:
        _mark_done(trace, "msrc", {
            "title": cve_record.get("title", ""),
            "kb_numbers": cve_record.get("kb_numbers", []),
            "description": cve_record.get("description", ""),
            "cvss": cve_record.get("cvss"),
        })
    else:
        _mark_failed(trace, "msrc", "validation failed")
    return passed


# ═════════════════════════════════════════════════════════════════════════════
# Stage 2: Winbindex binary download
# ═════════════════════════════════════════════════════════════════════════════

def stage_winbindex(trace: dict, force: bool) -> bool:
    print("\n[STAGE 2: Winbindex binary download]")

    if not force and _stage_done(trace, "winbindex"):
        r = trace["stages"]["winbindex"]["result"]
        pre = Path(r["pre_path"])
        post = Path(r["post_path"])
        if pre.exists() and post.exists():
            PASS(f"cached — pre={pre.name}  post={post.name}")
            return True
        INFO("Cached paths no longer exist — re-downloading")

    from pipeline.winbindex import get_binary_pair

    kb_numbers = [EXPECTED_KB]
    msrc_stage = trace.get("stages", {}).get("msrc", {}).get("result", {})
    if msrc_stage.get("kb_numbers"):
        kb_numbers = msrc_stage["kb_numbers"]

    INFO(f"Downloading binary pair for {BINARY}, KBs: {kb_numbers}")
    try:
        pre_path, post_path = get_binary_pair(BINARY, kb_numbers, BINARIES_DIR)
    except Exception as e:
        FAIL(f"get_binary_pair failed: {e}")
        _mark_failed(trace, "winbindex", str(e))
        return False

    passed = True

    for label, path in [("pre-patch", pre_path), ("post-patch", post_path)]:
        if not path.exists():
            FAIL(f"{label} file does not exist: {path}")
            passed = False
            continue
        header = path.read_bytes()[:2]
        if header != b"MZ":
            FAIL(f"{label} is not a valid PE (header={header!r})")
            passed = False
        else:
            size_kb = path.stat().st_size // 1024
            PASS(f"{label}: {path.name}  ({size_kb} KB, valid PE)")

    build_pre = int(str(pre_path).rsplit(".", 1)[-1])
    build_post = int(str(post_path).rsplit(".", 1)[-1])
    INFO(f"  pre-patch file version:  10.0.19041.{build_pre}")
    INFO(f"  post-patch file version: 10.0.19041.{build_post}")

    if build_post != EXPECTED_POST_REVISION:
        FAIL(f"Expected post-patch revision {EXPECTED_POST_REVISION}, got {build_post}")
        passed = False
    else:
        PASS(f"Post-patch revision matches expected ({EXPECTED_POST_REVISION})")

    if build_pre >= build_post:
        FAIL(f"Pre-patch build ({build_pre}) is not less than post-patch ({build_post})")
        passed = False

    if passed:
        _mark_done(trace, "winbindex", {
            "pre_path": str(pre_path),
            "post_path": str(post_path),
            "pre_build": build_pre,
            "post_build": build_post,
        })
    else:
        _mark_failed(trace, "winbindex", "validation failed")
    return passed


# ═════════════════════════════════════════════════════════════════════════════
# Stage 3: ghidriff
# ═════════════════════════════════════════════════════════════════════════════

def stage_ghidriff(trace: dict, force: bool) -> bool:
    print("\n[STAGE 3: ghidriff]")

    diff_name = CVE_ID.replace("/", "-")
    diff_path = DIFFS_DIR / f"{diff_name}.md"

    if not force and _stage_done(trace, "ghidriff"):
        r = trace["stages"]["ghidriff"]["result"]
        dp = Path(r["diff_path"])
        if dp.exists():
            PASS(f"cached — {dp.name}  ({dp.stat().st_size // 1024} KB, {r.get('function_count', '?')} functions)")
            return True
        INFO("Cached diff no longer exists — re-running ghidriff")

    # Load binary paths from winbindex stage
    wb_stage = trace.get("stages", {}).get("winbindex", {}).get("result", {})
    if not wb_stage:
        FAIL("winbindex stage not complete — run --stage winbindex first")
        return False

    pre_path = Path(wb_stage["pre_path"])
    post_path = Path(wb_stage["post_path"])

    if not pre_path.exists() or not post_path.exists():
        FAIL(f"Binary files not found: {pre_path}, {post_path}")
        return False

    from pipeline.ghidriff_runner import run_ghidriff

    INFO(f"Running ghidriff on {pre_path.name} vs {post_path.name}")
    INFO("This will take 20–40 minutes for ntoskrnl.exe ...")

    try:
        result_path = run_ghidriff(pre_path, post_path, DIFFS_DIR, diff_name)
    except Exception as e:
        FAIL(f"ghidriff failed: {e}")
        _mark_failed(trace, "ghidriff", str(e))
        return False

    if not result_path.exists():
        FAIL(f"ghidriff output not found: {result_path}")
        _mark_failed(trace, "ghidriff", "output file missing")
        return False

    diff_text = result_path.read_text(encoding="utf-8", errors="replace")
    fn_count = len([l for l in diff_text.splitlines() if re.match(r"^#{2,4} ", l)])

    PASS(f"Diff generated: {result_path.name}  ({result_path.stat().st_size // 1024} KB)")
    INFO(f"  Section headers found: {fn_count}")

    if GROUND_TRUTH_FN in diff_text:
        PASS(f"Ground truth function '{GROUND_TRUTH_FN}' present in diff")
    else:
        FAIL(f"Ground truth function '{GROUND_TRUTH_FN}' NOT found in diff — wrong binary pair?")
        _mark_failed(trace, "ghidriff", "ground truth function missing from diff")
        return False

    _mark_done(trace, "ghidriff", {
        "diff_path": str(result_path),
        "function_count": fn_count,
    })
    return True



# ═════════════════════════════════════════════════════════════════════════════
# Stage 4: Patch identification
# ═════════════════════════════════════════════════════════════════════════════

def stage_identify(trace: dict, force: bool) -> bool:
    print("\n[STAGE 4: Patch identification]")

    if not force and _stage_done(trace, "identify"):
        r = trace["stages"]["identify"]["result"]
        fn = r.get("function_name", "")
        conf = r.get("confidence", 0)
        PASS(f"cached — function='{fn}'  confidence={conf}")
        if fn == GROUND_TRUTH_FN:
            PASS(f"Matches ground truth: {GROUND_TRUTH_FN}")
        else:
            FAIL(f"Does NOT match ground truth. Expected '{GROUND_TRUTH_FN}', got '{fn}'")
        return fn == GROUND_TRUTH_FN

    # Load diff path from ghidriff stage
    gh_stage = trace.get("stages", {}).get("ghidriff", {}).get("result", {})
    if not gh_stage:
        FAIL("ghidriff stage not complete — run --stage ghidriff first")
        return False

    diff_path = Path(gh_stage["diff_path"])
    if not diff_path.exists():
        FAIL(f"Diff file not found: {diff_path}")
        return False

    # Build CVE record (from MSRC stage or hardcoded fallback)
    msrc_stage = trace.get("stages", {}).get("msrc", {}).get("result", {})
    cve = {
        "id": CVE_ID,
        "title": msrc_stage.get("title", "Windows Kernel Elevation of Privilege Vulnerability"),
        "description": msrc_stage.get("description",
            "An attacker who successfully exploited this vulnerability could gain SYSTEM privileges. "
            "Exploitation requires a race condition in token attribute handling (TOCTOU)."),
        "kb_numbers": msrc_stage.get("kb_numbers", [EXPECTED_KB]),
        "cvss": msrc_stage.get("cvss"),
    }

    from pipeline.patch_identifier import identify_patch, PatchNotFoundError, parse_ghidriff_sections, rank_by_heuristics

    # Show heuristic ranking before agent calls
    sections = parse_ghidriff_sections(diff_path)
    INFO(f"Parsed {len(sections)} changed function sections from diff")

    scored = rank_by_heuristics(sections, cve)
    INFO(f"Heuristic top-10 (of {len(scored)}):")
    for i, s in enumerate(scored[:10]):
        marker = " ← GROUND TRUTH" if s.section.name == GROUND_TRUTH_FN else ""
        INFO(f"  {i+1:2}. {s.section.name:<60} score={s.score:.0f}  "
             f"(+{s.section.added_lines}/-{s.section.removed_lines})  "
             f"{','.join(s.score_reasons[:3])}{marker}")

    gt_rank = next((i + 1 for i, s in enumerate(scored) if s.section.name == GROUND_TRUTH_FN), None)
    if gt_rank:
        INFO(f"\n  Ground truth '{GROUND_TRUTH_FN}' is at heuristic rank #{gt_rank}")
    else:
        INFO(f"\n  WARNING: Ground truth '{GROUND_TRUTH_FN}' not found in heuristic list")

    INFO("\nStarting Claude agent evaluation loop...")

    try:
        result = identify_patch(cve, diff_path)
    except PatchNotFoundError as e:
        FAIL(f"PatchNotFoundError: {e}")
        _mark_failed(trace, "identify", str(e))
        return False
    except Exception as e:
        FAIL(f"identify_patch raised: {e}")
        _mark_failed(trace, "identify", str(e))
        return False

    INFO(f"\nIdentified: '{result.function_name}'")
    INFO(f"  Confidence: {result.confidence}")
    INFO(f"  Patch type: {result.patch_type}")
    INFO(f"  Reasoning: {result.reasoning}")
    INFO(f"  Candidates evaluated: {result.candidates_evaluated}")

    passed = result.function_name == GROUND_TRUTH_FN
    if passed:
        PASS(f"Identified function matches ground truth: {GROUND_TRUTH_FN}")
    else:
        FAIL(f"Expected '{GROUND_TRUTH_FN}', got '{result.function_name}'")

    _mark_done(trace, "identify", {
        "function_name": result.function_name,
        "confidence": result.confidence,
        "patch_type": result.patch_type,
        "reasoning": result.reasoning,
        "candidates_evaluated": result.candidates_evaluated,
        "heuristic_scores": result.heuristic_scores[:20],
        "agent_evals": result.agent_evals,
    })

    return passed


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline test harness for CVE-2024-30088")
    parser.add_argument("--stage", choices=["msrc", "winbindex", "ghidriff", "identify", "all"],
                        default="all")
    parser.add_argument("--force", action="store_true",
                        help="Ignore cached results and re-run the stage")
    args = parser.parse_args()

    if not os.getenv("ANTHROPIC_API_KEY") and args.stage in ("identify", "all"):
        print("WARNING: ANTHROPIC_API_KEY not set — 'identify' stage will fail")

    trace = _load_trace()
    print(f"\nTrace file: {TRACE_FILE}")
    completed = [k for k, v in trace.get("stages", {}).items() if v.get("status") == "done"]
    if completed:
        print(f"Already completed stages: {', '.join(completed)}")

    stages = {
        "msrc":      lambda: stage_msrc(trace, args.force),
        "winbindex": lambda: stage_winbindex(trace, args.force),
        "ghidriff":  lambda: stage_ghidriff(trace, args.force),
        "identify":  lambda: stage_identify(trace, args.force),
    }

    if args.stage == "all":
        order = ["msrc", "windbindex", "ghidriff", "identify"]
        order = ["msrc", "winbindex", "ghidriff", "identify"]
        for name in order:
            ok = stages[name]()
            if not ok:
                print(f"\n  Pipeline stopped at stage '{name}'. Fix the issue and re-run.")
                sys.exit(1)
        print("\n\033[32m✓ All stages passed.\033[0m")
    else:
        ok = stages[args.stage]()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
