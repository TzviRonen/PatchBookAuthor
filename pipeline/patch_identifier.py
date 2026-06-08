"""Identify the specific function(s) patched for a CVE from noisy ghidriff output.

Flow:
  A) Parse ghidriff markdown → per-function FunctionSection list
  B) Heuristic scoring (no LLM) → ranked top-20 candidates
  C) Claude agent loop (one function at a time) → first match with confidence >= 75
  D) Return PatchResult with full diff section for blog generation
"""
import hashlib
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 75
NEGATIVE_CONFIDENCE_THRESHOLD = 90   # stop early if agent is this sure it's NOT the patch
MAX_CONSECUTIVE_NEGATIVES = 2        # require N in a row before stopping, not just one
MAX_CANDIDATES = 20

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FunctionSection:
    name: str
    diff_text: str          # raw diff lines for this function
    added_lines: int
    removed_lines: int
    has_signature_change: bool


@dataclass
class ScoredSection:
    section: FunctionSection
    score: float
    score_reasons: list[str] = field(default_factory=list)


@dataclass
class AgentEval:
    fn_name: str
    is_patch: bool
    confidence: int
    reasoning: str
    patch_type: str


@dataclass
class PatchResult:
    function_name: str
    confidence: int
    reasoning: str
    patch_type: str
    full_diff: str
    candidates_evaluated: int
    heuristic_scores: list[dict]
    agent_evals: list[dict]


class PatchNotFoundError(Exception):
    pass


# ---------------------------------------------------------------------------
# Step A: Parse ghidriff markdown
# ---------------------------------------------------------------------------

def parse_ghidriff_sections(diff_path: Path) -> list[FunctionSection]:
    """Parse ghidriff .md output into per-function diff sections.

    ghidriff output structure (verified from source):
      # Modified           ← category (level 1)
        ## FunctionName    ← function (level 2)
          ### Match Info
          ### Function Meta Diff
          ### FunctionName Diff
            ```diff ... ``` ← actual decompiled code diff
      # Added
        ## NewFunction
      # Deleted
        ## RemovedFunction

    We extract from Modified and Added sections (Deleted is rarely the security fix).
    """
    text = diff_path.read_text(encoding="utf-8", errors="replace")

    sections: list[FunctionSection] = []

    # Find level-1 category sections
    category_re = re.compile(
        r"^# (Modified|Added|Deleted)(?!\s+\(No Code)",  # skip "Modified (No Code Changes)"
        re.MULTILINE,
    )
    cat_matches = list(category_re.finditer(text))

    if not cat_matches:
        log.warning("No category headers found in diff — trying fallback parser")
        return _parse_fallback(text)

    for ci, cat_m in enumerate(cat_matches):
        cat_name = cat_m.group(1)
        cat_start = cat_m.end()
        cat_end = cat_matches[ci + 1].start() if ci + 1 < len(cat_matches) else len(text)
        cat_text = text[cat_start:cat_end]

        # Within category, split on level-2 function headers (## FunctionName)
        fn_re = re.compile(r"^## (.+)$", re.MULTILINE)
        fn_matches = list(fn_re.finditer(cat_text))

        for fi, fn_m in enumerate(fn_matches):
            fn_name = fn_m.group(1).strip()
            fn_start = fn_m.end()
            fn_end = fn_matches[fi + 1].start() if fi + 1 < len(fn_matches) else len(cat_text)
            fn_text = cat_text[fn_start:fn_end]

            # Extract diff content from ```diff blocks
            diff_blocks = re.findall(r"```diff\n(.*?)```", fn_text, re.DOTALL)
            diff_content = "\n".join(diff_blocks)

            added = len(re.findall(r"^\+(?!\+)", diff_content, re.MULTILINE))
            removed = len(re.findall(r"^-(?!-)", diff_content, re.MULTILINE))

            has_sig = bool(re.search(
                r"^\+.*\b(param|arg|__cdecl|__stdcall|NTSTATUS|VOID|HANDLE|PVOID)\b",
                diff_content, re.MULTILINE | re.IGNORECASE,
            ))

            # Include if there are actual code changes (skip pure metadata/empty sections)
            if added > 0 or removed > 0:
                sections.append(FunctionSection(
                    name=fn_name,
                    diff_text=fn_text,      # full section for context
                    added_lines=added,
                    removed_lines=removed,
                    has_signature_change=has_sig,
                ))

    log.info("Parsed %d changed function sections (%s)",
             len(sections), ", ".join(f"{c.group(1)}" for c in cat_matches))
    return sections


def _parse_fallback(text: str) -> list[FunctionSection]:
    """Fallback: find any ```diff blocks with a preceding identifier as the name."""
    sections = []
    for block_m in re.finditer(r"```diff\n(.*?)```", text, re.DOTALL):
        block = block_m.group(1)
        before = text[:block_m.start()]
        name_m = re.search(r"[`*]{0,2}([A-Za-z_][A-Za-z0-9_:]{4,})[`*]{0,2}\s*$", before)
        name = name_m.group(1) if name_m else f"block_{len(sections)}"
        added = len(re.findall(r"^\+(?!\+)", block, re.MULTILINE))
        removed = len(re.findall(r"^-(?!-)", block, re.MULTILINE))
        if added or removed:
            sections.append(FunctionSection(name, block, added, removed, False))
    log.info("Fallback parser found %d sections", len(sections))
    return sections


# ---------------------------------------------------------------------------
# Step B: Heuristic ranking
# ---------------------------------------------------------------------------

_BUG_CLASS_KEYWORDS = {
    "toctou":        ["copy", "capture", "snap", "lock", "probe", "stack", "local"],
    "race":          ["copy", "capture", "lock", "atomic", "sequence", "stack"],
    "eop":           ["privilege", "token", "access", "check", "elevat", "restrict"],
    "buffer":        ["size", "length", "alloc", "copy", "overflow", "bound", "limit"],
    "uaf":           ["free", "ref", "count", "release", "dereference", "lifetime"],
    "null":          ["null", "check", "valid", "deref", "ptr", "pointer"],
    "info_leak":     ["leak", "copy", "write", "output", "disclose"],
}

_GENERIC_UTIL_PREFIXES = re.compile(r"^(Rtl|ExAllocate|ExFree|KeAcquire|KeRelease|Mm|Io|Zw)", re.I)
_SECURITY_FIX_PATTERNS = re.compile(
    r"STATUS_ACCESS_DENIED|STATUS_INVALID|ProbeFor|AcquireLock|ReleaseLock"
    r"|ExAcquire|ExRelease|if \(.*== NULL\)|if \(!|RtlCopyMemory|SafeCopy"
    r"|__try|ASSERT\(|STATUS_BUFFER|STATUS_INSUF",
    re.IGNORECASE,
)
_DEFENSIVE_NAME_PATTERNS = re.compile(r"Check|Validate|Verify|Guard|Probe|Sanitize", re.I)


def _extract_cve_keywords(cve: dict) -> list[str]:
    """Pull meaningful words from CVE title + description.

    Also performs semantic expansion based on CVE type so that relevant kernel
    function naming conventions score highly even when MSRC descriptions are vague.
    """
    text = f"{cve.get('title', '')} {cve.get('description', '')}"
    stop = {"the", "a", "an", "is", "in", "of", "for", "to", "and", "or",
            "this", "that", "on", "by", "be", "are", "was", "it", "with",
            "can", "could", "may", "vulnerability", "windows", "microsoft"}
    base_keywords = [w.lower() for w in re.findall(r"[A-Za-z]{4,}", text) if w.lower() not in stop]

    # Semantic expansion: for each detected CVE type, add subsystem-specific
    # keyword expansions that appear in kernel function names for that class
    tl = text.lower()
    expanded: list[str] = list(base_keywords)

    if "elevation" in tl or "privilege" in tl or "eop" in tl:
        # Kernel EoP functions: token/auth/access management
        expanded += ["token", "authz", "privilege", "access", "security",
                     "check", "valid", "restrict", "permission"]

    if "race" in tl or "toctou" in tl or "time-of-check" in tl:
        # TOCTOU functions: copy/capture before use
        expanded += ["copy", "copyout", "capture", "snapshot", "probe",
                     "stack", "local", "cache", "clone"]

    if "information" in tl or "disclosure" in tl:
        expanded += ["copy", "write", "read", "output", "return", "leak"]

    if "remote code" in tl or "rce" in tl:
        expanded += ["parse", "process", "input", "buffer", "alloc", "recv"]

    if "kernel" in tl:
        # Generic kernel security terms
        expanded += ["security", "attribute", "descriptor", "context", "subject"]

    # Deduplicate preserving insertion order
    seen: set[str] = set()
    result: list[str] = []
    for kw in expanded:
        if kw not in seen:
            seen.add(kw)
            result.append(kw)
    return result


def _detect_bug_class(cve: dict) -> list[str]:
    """Return likely bug class keywords from CVE info."""
    text = f"{cve.get('title', '')} {cve.get('description', '')}".lower()
    if "time-of-check" in text or "toctou" in text or "race" in text:
        return _BUG_CLASS_KEYWORDS["toctou"] + _BUG_CLASS_KEYWORDS["race"]
    if "use after free" in text or "use-after-free" in text:
        return _BUG_CLASS_KEYWORDS["uaf"]
    if "buffer" in text or "overflow" in text:
        return _BUG_CLASS_KEYWORDS["buffer"]
    if "null" in text:
        return _BUG_CLASS_KEYWORDS["null"]
    if "information" in text or "disclosure" in text:
        return _BUG_CLASS_KEYWORDS["info_leak"]
    # default EoP (applies to "Elevation of Privilege" CVEs)
    return _BUG_CLASS_KEYWORDS["eop"]


def _extract_calling_names(diff_text: str) -> set[str]:
    """Parse the ghidriff Function Meta Diff table to find functions that CALL this one."""
    calling: set[str] = set()
    for m in re.finditer(r"\|`?calling`?\|\s*([^|]+)\|", diff_text):
        for name in re.split(r"<br>|\s*,\s*|\s+", m.group(1)):
            name = name.strip()
            if name and re.match(r"[A-Za-z_]\w{3,}", name):
                calling.add(name)
    return calling


def rank_by_heuristics(sections: list[FunctionSection], cve: dict) -> list[ScoredSection]:
    cve_keywords = _extract_cve_keywords(cve)
    bug_keywords = _detect_bug_class(cve)

    scored: list[ScoredSection] = []
    for sec in sections:
        score = 0.0
        reasons: list[str] = []
        fn_lower = sec.name.lower()
        change_size = sec.added_lines + sec.removed_lines

        # CVE keyword match in function name (+25 each)
        for kw in cve_keywords:
            if kw in fn_lower:
                score += 25
                reasons.append(f"name:{kw}")

        # Bug-class keyword match (+5 each)
        for kw in bug_keywords:
            if kw in fn_lower:
                score += 5
                reasons.append(f"bugclass:{kw}")

        # Small targeted change (+30)
        if 5 <= change_size <= 30:
            score += 30
            reasons.append("fix:small")
        elif change_size > 300:
            score -= 30
            reasons.append("penalty:large")

        # Security patterns in diff body (+10 each, cap at +40)
        sec_hits = len(_SECURITY_FIX_PATTERNS.findall(sec.diff_text))
        if sec_hits:
            bonus = min(sec_hits * 10, 40)
            score += bonus
            reasons.append(f"secpat:{sec_hits}")

        # Defensive name patterns (+8)
        if _DEFENSIVE_NAME_PATTERNS.search(sec.name):
            score += 8
            reasons.append("name:defensive")

        # Generic utility prefix penalty (-5)
        if _GENERIC_UTIL_PREFIXES.match(sec.name) and not any(kw in fn_lower for kw in cve_keywords):
            score -= 5
            reasons.append("penalty:util")

        scored.append(ScoredSection(section=sec, score=score, score_reasons=reasons))

    scored.sort(key=lambda s: s.score, reverse=True)

    # Post-process: penalize callees of other top candidates (-50).
    # ghidriff records the calling function(s) in the Function Meta Diff table.
    # If this function is called BY another candidate, it is a helper updated as a
    # consequence of the fix — not the fix entry point itself.
    candidate_names = {s.section.name for s in scored[:MAX_CANDIDATES]}
    for ss in scored[:MAX_CANDIDATES]:
        callers_in_diff = _extract_calling_names(ss.section.diff_text)
        overlap = callers_in_diff & candidate_names - {ss.section.name}
        if overlap:
            ss.score -= 50
            ss.score_reasons.append(f"penalty:callee_of({next(iter(overlap))})")

    scored.sort(key=lambda s: s.score, reverse=True)
    return scored


# ---------------------------------------------------------------------------
# Step C: Claude agent loop
# ---------------------------------------------------------------------------

_AGENT_SYSTEM = """\
You are a Windows kernel security researcher specializing in binary patch analysis.

Your task: determine whether a specific changed function (shown as a ghidriff decompiled diff) \
is the security fix for a given CVE.

## How to reason about this

Internalize the CVE bug class and match it to diff patterns:

**TOCTOU (Time-of-Check-to-Time-of-Use):**
- The fix typically adds a local kernel-stack copy of data that was previously accessed \
via a pointer (user-mode or shared) twice — once to check, once to use.
- Look for: new local variable holding a captured copy, ProbeForRead before the copy, \
loop/iteration over the local copy instead of the original pointer.

**Elevation of Privilege (EoP):**
- The fix adds an explicit privilege or token validity check before a sensitive operation.
- Look for: SePrivilegeCheck, PsGetCurrentProcess, token handle validation, new STATUS_ACCESS_DENIED return.

**Buffer overflow / out-of-bounds write:**
- The fix adds a size or bounds check before a copy/allocation.
- Look for: new `if (size > MAX)`, length validation, RtlSafeAdd*, guarded copy wrapper.

**Use-after-free:**
- The fix adds a reference count increment before use or a lock around the free path.
- Look for: ObReferenceObject, ExInterlockedIncrement, new lock acquire before dereference.

## What a security fix looks like vs. a refactor

A **security fix** is typically:
- Small and targeted (5–30 lines changed)
- Adds a STATUS_* error return path that wasn't there before
- Adds a null/bounds check near a pointer dereference or copy
- Copies data to a local (stack) buffer before trusting it

A **refactor** is typically:
- Large (100+ lines)
- Restructures control flow without changing its fundamental semantics
- Renames variables or reorders code

## Common mistakes to avoid

- **Do NOT flag inner helper functions** that are called by another changed function that is also \
a candidate. If the prompt shows "Functions that call this one: X" and X is also a changed function, \
then X is likely the real fix — this function was just updated as a consequence.
- The correct answer is almost always the **outermost** changed function in the call chain — the one \
that is not itself called by another changed candidate.
- Don't flag cosmetic changes (renamed variables, re-ordered constants).
- Large surrounding context changes don't make a function the fix — focus on the 5–30 changed lines.

## Output format

You MUST end your response with a JSON block on its own line:
```json
{"is_patch": <true|false>, "confidence": <0-100>, "reasoning": "<one concise sentence>", "patch_type": "<TOCTOU|EoP|buffer_overflow|use_after_free|null_deref|other>"}
```
"""


def _eval_cache_path(cve_id: str, fn_name: str, diff_text: str) -> Path:
    from pipeline.config import DATA_DIR
    diff_hash = hashlib.sha256(diff_text.encode()).hexdigest()[:12]
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", fn_name)
    return DATA_DIR / "cache" / "agent_evals" / cve_id / f"{safe_fn}_{diff_hash}.json"


def _load_eval_cache(cve_id: str, fn_name: str, diff_text: str) -> "AgentEval | None":
    path = _eval_cache_path(cve_id, fn_name, diff_text)
    if path.exists():
        try:
            return AgentEval(**json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            pass
    return None


def _save_eval_cache(cve_id: str, fn_name: str, diff_text: str, result: "AgentEval") -> None:
    path = _eval_cache_path(cve_id, fn_name, diff_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "fn_name": result.fn_name,
        "is_patch": result.is_patch,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "patch_type": result.patch_type,
    }), encoding="utf-8")


def _call_claude_cli(system_prompt: str, user_message: str, timeout: int = 180) -> str:
    """Call `claude -p` via subprocess and return stdout."""
    result = subprocess.run(
        ["claude", "-p", "--system-prompt", system_prompt],
        input=user_message,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"claude CLI exited {result.returncode}: {result.stderr[:500]}"
        )
    return result.stdout


def _call_agent(cve: dict, section: FunctionSection, sections_by_name: dict[str, FunctionSection]) -> AgentEval:
    # Pre-compute caller/callee context so Claude has it without needing tool calls
    callers = [
        s.name for s in sections_by_name.values()
        if section.name in s.diff_text and s.name != section.name
    ]
    callees = [
        s.name for s in sections_by_name.values()
        if s.name in section.diff_text and s.name != section.name
    ]

    caller_block = ""
    if callers:
        caller_block = f"\n**Other changed functions that call this one**: {', '.join(callers[:8])}\n"
    if callees:
        caller_block += f"**Changed functions this one calls**: {', '.join(callees[:8])}\n"

    cve_desc = cve.get("description", "(no description)")
    if len(cve_desc) > 1500:
        cve_desc = cve_desc[:1500] + "..."

    user_msg = f"""\
## CVE Information

- **CVE ID**: {cve['id']}
- **Title**: {cve.get('title', '')}
- **KB**: {', '.join(cve.get('kb_numbers', []))}
- **Description**: {cve_desc}
{caller_block}
## Changed function to evaluate: `{section.name}`

Lines added: {section.added_lines}  |  Lines removed: {section.removed_lines}

```diff
{section.diff_text[:8000]}
```
{"*(truncated)*" if len(section.diff_text) > 8000 else ""}

Is this the security patch for {cve['id']}? End your response with the JSON verdict block.
"""

    response_text = _call_claude_cli(_AGENT_SYSTEM, user_msg)

    json_m = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL)
    if not json_m:
        json_m = re.search(r"\{[^{}]*\"is_patch\"[^{}]*\}", response_text, re.DOTALL)

    if json_m:
        try:
            raw = json_m.group(1) if "```" in json_m.group(0) else json_m.group(0)
            verdict = json.loads(raw)
            return AgentEval(
                fn_name=section.name,
                is_patch=bool(verdict.get("is_patch", False)),
                confidence=int(verdict.get("confidence", 0)),
                reasoning=str(verdict.get("reasoning", "")),
                patch_type=str(verdict.get("patch_type", "other")),
            )
        except Exception as e:
            log.warning("Failed to parse agent JSON for %s: %s | text: %s",
                        section.name, e, response_text[-300:])

    log.warning("Agent did not return JSON verdict for %s — raw: %s",
                section.name, response_text[-300:])
    return AgentEval(
        fn_name=section.name,
        is_patch=False,
        confidence=0,
        reasoning="No structured verdict returned by agent",
        patch_type="other",
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def identify_patch(cve: dict, diff_path: Path) -> PatchResult:
    """Identify the patched function in a ghidriff diff for a given CVE.

    Raises PatchNotFoundError if no candidate reaches CONFIDENCE_THRESHOLD.
    """
    sections = parse_ghidriff_sections(diff_path)
    if not sections:
        raise PatchNotFoundError(f"No changed functions found in {diff_path}")

    scored = rank_by_heuristics(sections, cve)
    candidates = scored[:MAX_CANDIDATES]

    sections_by_name = {s.section.name: s.section for s in scored}

    heuristic_log = [
        {"rank": i + 1, "name": s.section.name, "score": s.score,
         "added": s.section.added_lines, "removed": s.section.removed_lines,
         "reasons": s.score_reasons}
        for i, s in enumerate(candidates)
    ]

    log.info("Heuristic top-5 (of %d sections):", len(sections))
    for entry in heuristic_log[:5]:
        log.info("  %d. %-55s  score=%.0f  (+%d/-%d)  %s",
                 entry["rank"], entry["name"], entry["score"],
                 entry["added"], entry["removed"],
                 ", ".join(entry["reasons"][:4]))

    agent_evals: list[AgentEval] = []
    consecutive_negatives = 0
    cve_id = cve.get("id", "unknown")

    for i, scored_sec in enumerate(candidates):
        sec = scored_sec.section
        log.info("Evaluating candidate #%d: %s", i + 1, sec.name)

        cached = _load_eval_cache(cve_id, sec.name, sec.diff_text)
        if cached:
            log.info("  (cache hit)")
            eval_result = cached
        else:
            eval_result = _call_agent(cve, sec, sections_by_name)
            _save_eval_cache(cve_id, sec.name, sec.diff_text, eval_result)
        agent_evals.append(eval_result)

        log.info("  Agent: is_patch=%s confidence=%d  — %s",
                 eval_result.is_patch, eval_result.confidence, eval_result.reasoning[:120])

        if eval_result.is_patch and eval_result.confidence >= CONFIDENCE_THRESHOLD:
            log.info("IDENTIFIED patch: %s (confidence=%d) after evaluating %d candidate(s)",
                     sec.name, eval_result.confidence, i + 1)
            return PatchResult(
                function_name=sec.name,
                confidence=eval_result.confidence,
                reasoning=eval_result.reasoning,
                patch_type=eval_result.patch_type,
                full_diff=sec.diff_text,
                candidates_evaluated=i + 1,
                heuristic_scores=heuristic_log,
                agent_evals=[{"fn": e.fn_name, "is_patch": e.is_patch,
                               "confidence": e.confidence, "reasoning": e.reasoning,
                               "patch_type": e.patch_type}
                              for e in agent_evals],
            )

        if not eval_result.is_patch and eval_result.confidence >= NEGATIVE_CONFIDENCE_THRESHOLD:
            consecutive_negatives += 1
            if consecutive_negatives >= MAX_CONSECUTIVE_NEGATIVES:
                log.info(
                    "Stopping early after %d consecutive high-confidence negatives "
                    "(≥%d%%) — patch unlikely in remaining candidates",
                    consecutive_negatives, NEGATIVE_CONFIDENCE_THRESHOLD,
                )
                break
        else:
            consecutive_negatives = 0

    raise PatchNotFoundError(
        f"No patch identified in top-{min(i + 1, len(candidates))} candidates for {cve.get('id')}. "
        f"Best confidence: {max((e.confidence for e in agent_evals), default=0)}"
    )
