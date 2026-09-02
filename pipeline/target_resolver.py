"""Resolve which build lineage(s) to diff for a CVE, from MSRC affected-product data.

The Security Update Guide reports the *OS* build a fix shipped in (e.g. 10.0.22631.7219),
but the kernel binaries carry a *file-version* lineage that differs for some releases
(23H2's ntoskrnl is 10.0.22621.7219, not 22631; Win10 22H2 is 10.0.19041.x, not 19045).
The revision (4th component) is shared within a lineage. We translate each affected OS
build to its file lineage, keep only the lineages the CVE actually affects, and order them
by preference so the pipeline diffs the smallest/most-available base first.

This is the fix for the root cause where a hardcoded TARGET_WINDOWS_BUILD=19041 made the
pipeline diff a lineage the CVE did not even affect (CVE-2026-45657 does not touch 19041).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from pipeline.config import PREFERRED_BUILD_LINEAGES

log = logging.getLogger(__name__)

# OS build (3rd component reported by MSRC) -> kernel file-version lineage (3rd component).
# Only entries that actually differ need listing; unknown builds map to themselves.
_OS_TO_FILE_LINEAGE = {
    19045: 19041,  # Win10 22H2
    19044: 19041,  # Win10 21H2
    19043: 19041,  # Win10 21H1
    19042: 19041,  # Win10 20H2
    22631: 22621,  # Win11 23H2
    22635: 22621,  # Win11 dev/beta on 23H2 base
}


@dataclass(frozen=True)
class Target:
    """One (lineage, fixed revision) the CVE shipped a fix in."""
    lineage: int          # file-version 3rd component, e.g. 22621
    revision: int         # file-version 4th component, e.g. 7219 (== fixed build revision)
    os_build: str         # original MSRC fixed build string, e.g. "10.0.22631.7219"
    kb: str               # KB article for this product row


def _parse_build(s: str) -> tuple[int, int] | None:
    """Return (os_lineage, revision) from a build string like '10.0.22631.7219'."""
    nums = re.findall(r"\d+", s)
    if len(nums) < 4:
        return None
    return int(nums[2]), int(nums[3])


def resolve_targets(ground_truth: dict) -> list[Target]:
    """Return the CVE's fix targets, de-duplicated and ordered by lineage preference.

    Empty list means the CVE has no resolvable Windows fixed-build (e.g. Mariner-only,
    or SUG data unavailable) — the caller should mark the CVE unresolved rather than guess.
    """
    seen: dict[tuple[int, int], Target] = {}
    for row in ground_truth.get("affected_products", []):
        parsed = _parse_build(row.get("fixed_build", ""))
        if not parsed:
            continue
        os_lineage, revision = parsed
        file_lineage = _OS_TO_FILE_LINEAGE.get(os_lineage, os_lineage)
        key = (file_lineage, revision)
        if key not in seen:
            seen[key] = Target(
                lineage=file_lineage,
                revision=revision,
                os_build=row.get("fixed_build", ""),
                kb=row.get("kb", ""),
            )

    def _order(t: Target) -> tuple[int, int]:
        try:
            pref = PREFERRED_BUILD_LINEAGES.index(t.lineage)
        except ValueError:
            pref = len(PREFERRED_BUILD_LINEAGES)  # unknown lineages last
        return (pref, t.lineage)

    targets = sorted(seen.values(), key=_order)
    if targets:
        log.info("Resolved %d fix target(s): %s", len(targets),
                 ", ".join(f"{t.lineage}.{t.revision}" for t in targets))
    else:
        log.warning("No Windows fixed-build resolved from affected-product data")
    return targets
