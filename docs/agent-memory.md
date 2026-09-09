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

## CVE-2026-49798 — real patch is clfs.sys, not the published ntoskrnl pick

The pipeline published `ntoskrnl.exe!WheaRemoveErrorSource` (45% conf) for
CVE-2026-49798 (CWE-416 UAF, "Windows Kernel" local EoP, KB5099539). **That is
wrong.** Verified via IDA + ghidriff:

- The `ntoskrnl.exe` 7417→7548 delta (correct June→July pair; 7548=2026-07-14)
  is 99.99% identical: 4 code-changed functions, all just *removing* the WHEA
  killswitches `Feature_2504257848 / 1162080569 / 3858493753` (introduced back
  in 7181/April). Pure CFR cleanup — see the `Feature_*` Rule 1 above. No July
  UAF fix exists in `ntoskrnl.exe`.
- The real fix is in **`clfs.sys`**, which the pipeline never diffs (Rule 2 of
  build/binary selection). `clfs.sys` was serviced in July (7548) but **not**
  June — its 7291→7548 delta is one tight change: 4 modified + 3 added
  functions, all gated by a **newly added** `Feature_796637497`.
- Patch function: **`CClfsBaseFileSnapshot::CopyImage`** (co-patches
  `CClfsLogFcbPhysical::AppendLog`, new helper `RawSectorAlign`). The gated
  logic does a **save→NULL→restore** of each `_CLFS_CONTAINER_CONTEXT` pointer
  at offset **+0x18** around the `ClfsEncodeBlock`/`memmove`/`ClfsDecodeBlock`
  image copy, so the dangling container-context pointer is not dereferenceable
  during the snapshot copy — the UAF-lifetime fix.

**Why the pipeline failed here:** (1) it diffs only `ntoskrnl.exe` so it never
saw `clfs.sys`; (2) `validate._has_security_signal` treats *any* `Feature_*`
gate in the diff as a fix signal, so it rewarded the WHEA gate-*removal* noise
(Rule 1) and the MCP path accepted a 45%-confidence pick with no confidence
floor. **How to apply:** for a "Windows Kernel" UAF whose `ntoskrnl.exe` delta
is only gate-removal/relocation, diff the kernel drivers too (`clfs.sys`,
`cng.sys`, …); the binary serviced *this* month but not last month, carrying a
newly-added `Feature_*` gate, is the real fix.
