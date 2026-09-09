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
    PatchResult, _real_change_counts, _SECURITY_FIX_PATTERNS,
    _cve_primary_classes, _cve_acceptable_classes, _class_compatible,
)

log = logging.getLogger(__name__)

# A published report drives an unattended commit+push to the live site, so a
# low-confidence identify result must not reach it. 60 mirrors the pipeline's own
# FALLBACK_CONFIDENCE_THRESHOLD (the floor at which identify accepts a best guess).
MIN_PUBLISH_CONFIDENCE = 60

_FEATURE_GATE_RE = re.compile(r"Feature_\d+__private_IsEnabled", re.I)


def _diff_added_removed(diff_text: str) -> tuple[list[str], list[str]]:
    """Split a unified diff into its added and removed source lines (markers stripped)."""
    added, removed = [], []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("--"):
            removed.append(line[1:])
    return added, removed


def _gate_direction(diff_text: str) -> tuple[bool, bool]:
    """Return (gate_added, gate_removed) for CFR Feature_* killswitches in the diff.

    Direction is the whole point (see docs/agent-memory.md, Feature_* rules): a gate
    *added* around new logic is the live fix (Rule 2); a gate *removed* is rollout
    completion / cleanup of a fix that shipped earlier (Rule 1), not a fix itself.
    """
    added, removed = _diff_added_removed(diff_text)
    gate_added = any(_FEATURE_GATE_RE.search(l) for l in added)
    gate_removed = any(_FEATURE_GATE_RE.search(l) for l in removed)
    return gate_added, gate_removed

# agent patch_type -> acceptable CWE numbers for that class
# A race condition (CWE-362) is a root cause whose fix commonly reads as a UAF/double-free
# repair, so both TOCTOU and use_after_free are consistent with a CVE that carries CWE-362.
# This only governs the fallback path below, used when the MSRC description does not name a
# class; the description path uses the richer _cve_acceptable_classes relation.
_PATCH_TYPE_CWES: dict[str, set[int]] = {
    "use_after_free": {416, 415, 825, 362},
    "buffer_overflow": {122, 121, 787, 788, 120, 680, 190, 191, 125},
    "info_leak": {200, 908, 457, 125, 908},
    "TOCTOU": {367, 362},
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
    """True if the *added* code shows a recognizable security fix (not a benign refactor).

    Evaluated on added lines only: the fix is what the patch introduces. A gate merely
    *present* in the diff is not enough — an added gate counts (Rule 2), a removed one
    does not (Rule 1, handled by the cleanup-only check in validate_patch).
    """
    added, _ = _diff_added_removed(diff_text)
    added_text = "\n".join(added)
    if _SECURITY_FIX_PATTERNS.search(added_text):
        return True
    if _FEATURE_GATE_RE.search(added_text):
        return True  # a newly added Feature_* gate is the staged-rollout fix signature
    return False


def validate_patch(cve: dict, ground_truth: dict, patch: PatchResult) -> tuple[bool, list[str]]:
    """Return (ok, reasons). ok=False means the proposal does not match the CVE."""
    reasons: list[str] = []
    ok = True

    # 0. Confidence floor. A published report is pushed to the live site unattended,
    #    so a low-confidence guess must never reach it. Applies to every identify path
    #    (the MCP path had no floor of its own — a 45% pick reached publish once).
    if patch.confidence < MIN_PUBLISH_CONFIDENCE:
        ok = False
        reasons.append(
            f"FAIL confidence: {patch.confidence}% < {MIN_PUBLISH_CONFIDENCE}% publish floor"
        )
    else:
        reasons.append(f"ok confidence: {patch.confidence}%")

    # 1. Real change present (defence in depth — candidates are pre-filtered, but a
    #    fallback-confidence match could still be relocation noise).
    added, removed = _real_change_counts(patch.full_diff)
    if added == 0 and removed == 0:
        ok = False
        reasons.append("FAIL real-change: diff is relocation/metadata only")
    else:
        reasons.append(f"ok real-change: +{added}/-{removed} normalized")

    # 1b. Cleanup-only delta: the change only *removes* a Feature_* killswitch, with no
    #     gate added and no recognizable fix pattern in the added lines. That is CFR
    #     rollout completion (Rule 1) — the real fix shipped earlier or in another binary,
    #     so this binary carries no fix to publish. (This is what let a gate-removal in
    #     ntoskrnl.exe be published while the real UAF fix sat in an undiffed driver.)
    gate_added, gate_removed = _gate_direction(patch.full_diff)
    has_signal = _has_security_signal(patch.full_diff)
    if gate_removed and not gate_added and not has_signal:
        ok = False
        reasons.append(
            "FAIL cleanup-only: diff only removes a Feature_* killswitch (CFR rollout "
            "completion), no fix added — the real fix is elsewhere (earlier build or "
            "another binary)"
        )

    # 2. Bug-class consistency. Prefer the CVE's *stated* class (from the MSRC description),
    #    which disambiguates when one build's diff carries several co-shipped fixes — e.g.
    #    22621 tcpip.sys has both the 45657 UAF and the 42904 overflow, and 45657 lists BOTH
    #    CWE-416 and CWE-122, so the broad CWE check alone would wrongly accept the overflow.
    #    Falls back to the broad CWE map only when the description does not name a class.
    cve_for_class = {**cve, "cwe_list": ground_truth.get("cwe_list", [])}
    primary = _cve_primary_classes(cve_for_class)
    acceptable = _cve_acceptable_classes(cve_for_class)
    cve_cwes = _cwe_numbers(ground_truth.get("cwe_list", []))
    if primary:
        # Accept the stated class *or* a fix manifestation compatible with it (e.g. a race
        # patched as a UAF), while still rejecting an unrelated co-shipped fix (an overflow).
        if _class_compatible(patch.patch_type, acceptable):
            reasons.append(
                f"ok class: patch_type={patch.patch_type} matches stated {sorted(primary)}"
                + (f" (as manifestation; accepts {sorted(acceptable)})"
                   if patch.patch_type not in primary else "")
            )
        else:
            ok = False
            reasons.append(
                f"FAIL class: patch_type={patch.patch_type} != CVE stated class {sorted(primary)} "
                f"(accepts {sorted(acceptable)})"
            )
    elif _cwe_consistent(patch.patch_type, cve_cwes):
        reasons.append(f"ok cwe: patch_type={patch.patch_type} vs {sorted(cve_cwes) or 'n/a'}")
    else:
        ok = False
        reasons.append(
            f"FAIL cwe: patch_type={patch.patch_type} inconsistent with CVE CWEs {sorted(cve_cwes)}"
        )

    # 3. Positive security-fix signal in the added code. Soft on its own (recorded, not
    #    fatal) so we don't reject a real fix whose pattern we simply don't recognize —
    #    but it feeds the cleanup-only gate above, and "an added gate" now requires the
    #    gate to be *added*, not merely mentioned. (has_signal computed in 1b.)
    if has_signal:
        reasons.append("ok signal: security-fix pattern / added Feature_* gate in added code")
    else:
        reasons.append("warn signal: no recognized security-fix pattern in added code (soft)")

    # 4. Attack-vector plausibility (soft). AV:N/AV:A CVEs should land in reachable code;
    #    we only warn because callgraph reachability isn't available at this layer.
    vec = ground_truth.get("vector_string", "")
    if "AV:N" in vec or "AV:A" in vec:
        reasons.append(f"note vector: {vec.split('/')[0:2]} (remote/adjacent)")

    log.info("validate %s -> %s: %s", patch.function_name, "PASS" if ok else "FAIL",
             "; ".join(reasons))
    return ok, reasons
