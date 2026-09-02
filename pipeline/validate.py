"""CVE↔patch validation gate.

After identify_patch proposes a function, this gate checks the proposal against the CVE's
authoritative ground truth (MSRC SUG API): the CWE bug class, the CVSS attack vector, and
that the diff contains a real security-relevant change. If it does not match, the pipeline
treats the CVE as unresolved and keeps researching rather than publishing a wrong report.

This is the missing check that let the relocation-only WmipUpdateModifyGuid "patch" be
published for CVE-2026-45657.
"""
from __future__ import annotations

import logging
import re

from pipeline.patch_identifier import (
    PatchResult, _real_change_counts, _SECURITY_FIX_PATTERNS, _extract_feature_flags,
    _cve_primary_classes,
)

log = logging.getLogger(__name__)

# agent patch_type -> acceptable CWE numbers for that class
_PATCH_TYPE_CWES: dict[str, set[int]] = {
    "use_after_free": {416, 415, 825},
    "buffer_overflow": {122, 121, 787, 788, 120, 680, 190, 191, 125},
    "info_leak": {200, 908, 457, 125, 908},
    "TOCTOU": {367},
    "null_deref": {476},
    "EoP": {269, 266, 264, 268, 250},
    "other": set(),   # matches anything
}


def _cwe_numbers(cwe_list: list[str]) -> set[int]:
    nums: set[int] = set()
    for c in cwe_list or []:
        m = re.search(r"CWE-(\d+)", str(c))
        if m:
            nums.add(int(m.group(1)))
    return nums


def _cwe_consistent(patch_type: str, cve_cwes: set[int]) -> bool:
    if not cve_cwes:
        return True  # no ground-truth CWE available — cannot contradict
    allowed = _PATCH_TYPE_CWES.get(patch_type, set())
    if not allowed:
        return True  # "other"/unknown patch_type — don't reject on CWE grounds
    return bool(allowed & cve_cwes)


def _has_security_signal(diff_text: str) -> bool:
    """True if the diff shows a recognizable security fix (not a benign refactor)."""
    if _SECURITY_FIX_PATTERNS.search(diff_text):
        return True
    if _extract_feature_flags(diff_text):
        return True  # a newly added Feature_* gate is the staged-rollout fix signature
    return False


def validate_patch(cve: dict, ground_truth: dict, patch: PatchResult) -> tuple[bool, list[str]]:
    """Return (ok, reasons). ok=False means the proposal does not match the CVE."""
    reasons: list[str] = []
    ok = True

    # 1. Real change present (defence in depth — candidates are pre-filtered, but a
    #    fallback-confidence match could still be relocation noise).
    added, removed = _real_change_counts(patch.full_diff)
    if added == 0 and removed == 0:
        ok = False
        reasons.append("FAIL real-change: diff is relocation/metadata only")
    else:
        reasons.append(f"ok real-change: +{added}/-{removed} normalized")

    # 2. Bug-class consistency. Prefer the CVE's *stated* class (from the MSRC description),
    #    which disambiguates when one build's diff carries several co-shipped fixes — e.g.
    #    22621 tcpip.sys has both the 45657 UAF and the 42904 overflow, and 45657 lists BOTH
    #    CWE-416 and CWE-122, so the broad CWE check alone would wrongly accept the overflow.
    #    Falls back to the broad CWE map only when the description does not name a class.
    primary = _cve_primary_classes({**cve, "cwe_list": ground_truth.get("cwe_list", [])})
    cve_cwes = _cwe_numbers(ground_truth.get("cwe_list", []))
    if primary:
        if patch.patch_type in primary:
            reasons.append(f"ok class: patch_type={patch.patch_type} matches stated {sorted(primary)}")
        else:
            ok = False
            reasons.append(
                f"FAIL class: patch_type={patch.patch_type} != CVE stated class {sorted(primary)}"
            )
    elif _cwe_consistent(patch.patch_type, cve_cwes):
        reasons.append(f"ok cwe: patch_type={patch.patch_type} vs {sorted(cve_cwes) or 'n/a'}")
    else:
        ok = False
        reasons.append(
            f"FAIL cwe: patch_type={patch.patch_type} inconsistent with CVE CWEs {sorted(cve_cwes)}"
        )

    # 3. Security-fix signal (soft — recorded, not fatal, to avoid rejecting real fixes
    #    whose pattern we don't recognize).
    if _has_security_signal(patch.full_diff):
        reasons.append("ok signal: security-fix pattern / Feature_* gate present")
    else:
        reasons.append("warn signal: no recognized security-fix pattern (soft)")

    # 4. Attack-vector plausibility (soft). AV:N/AV:A CVEs should land in reachable code;
    #    we only warn because callgraph reachability isn't available at this layer.
    vec = ground_truth.get("vector_string", "")
    if "AV:N" in vec or "AV:A" in vec:
        reasons.append(f"note vector: {vec.split('/')[0:2]} (remote/adjacent)")

    log.info("validate %s -> %s: %s", patch.function_name, "PASS" if ok else "FAIL",
             "; ".join(reasons))
    return ok, reasons
