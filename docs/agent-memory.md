# Agent memory (kernel-cve-pipeline / patchbook)

Notes accumulated across Claude Code sessions working on this repo. Point-in-time
observations, not live state — verify file:line citations against current code
before treating them as fact.

## Feature_* flag semantics for patch identification

`Feature_XXXXXXXXX__private_IsEnabledDeviceUsage()` functions (Microsoft CFR /
Controlled Feature Rollout killswitches) **return true (non-zero) by default**.

- **Rule 1 — Removing a `Feature_*` gate is NOT the primary patch.** If pre-patch
  has `if (Feature_X() != 0 && (check))` and post-patch has just `if (check)`,
  behavior is identical (the flag was already true). This is a follow-up cleanup
  commit removing the killswitch after the fix proved stable — the real security
  fix shipped in a prior update. Don't identify this commit as the CVE patch.
- **Rule 2 — Adding a `Feature_*` gate around new code IS a new change.** If
  post-patch wraps new logic in `if (Feature_X() != 0) { new_safe_behavior } else
  { old_behavior }`, `new_safe_behavior` is the active fix (on by default).
  Evaluate whether it closes the CVE's bug class.

**Why:** the pipeline misidentified `FsRtlAddBaseMcbEntryEx` (which only removed
a `Feature_*` gate) as the patch for CVE-2026-26180. The real patch was
`WheapLogInitEvent`, which added `Feature_*` gates around new safety logic.

**How to apply:** encoded in `pipeline/patch_identifier.py`'s
`identify_patch_with_mcp` system prompt under "Feature_* flag semantics", and
should also apply to the non-MCP `_AGENT_SYSTEM` prompt for future changes.

## Pipeline build/binary selection

Two recurring selection bugs, both seen on CVE-2026-45657:

1. **Wrong build pair.** Build selection can resolve two *post*-patch
   revisions. Diffing those yields only relocation noise, which the agent then
   narrates as a real finding (a fabricated UAF report, in that case).
2. **Wrong binary.** The pipeline only diffs `ntoskrnl.exe`, so fixes that
   ship in a driver (`tcpip.sys`, etc.) are missed entirely.

**How to apply:** before trusting a report, confirm (a) the two diffed builds
straddle the CVE's release date (winbindex `releaseDate`), and (b) the CVE's
component maps to the binary actually diffed.

When one month's update fixes several CVEs in the same binary, disambiguate by
**build delta across branches**: intersect each branch's changed-function set
with the MSRC affected-build list, and the CVE that only affects some branches
is the function that only appears in those branches' deltas. Combine with the
`Feature_*` rule above — the newly added gate marks the real fix.

## Cleanup-only delta ⇒ the fix is in another binary

If a binary's entire changed-function set for a month normalizes to relocation
noise plus `Feature_*` gate **removals** (Rule 1), there is no security fix in
that binary that month — do not identify or publish a patch from it. Retiring a
killswitch is rollout completion, not the fix; the real change shipped earlier
(when the gate was added) or in a different binary.

When this happens for `ntoskrnl.exe` (the only binary the pipeline diffs by
default), fall back to the other candidate binaries the resolver already lists
for the CVE, and diff those too. Strongest signal for which one: the binary
**serviced this month but not last month** (a winbindex build dated the CVE's
release date, with no build the prior month) that carries a **newly added**
`Feature_*` gate around new logic (Rule 2). MSRC's "Windows Kernel" product
label covers kernel drivers (e.g. `clfs.sys`), not just `ntoskrnl.exe`.

**Why the validator misses this:** treating *any* `Feature_*` mention in a diff
as a security signal scores gate-**removal** cleanup as if it were a fix. The
signal must distinguish an added gate (fix) from a removed one (cleanup), and a
low-confidence identify result should never auto-publish.
