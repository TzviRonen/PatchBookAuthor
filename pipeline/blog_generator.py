"""Generate a kernel-developer blog post from a ghidriff diff using Claude."""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.config import CLAUDE_MODEL, DIFF_INPUT_CHAR_LIMIT, TARGET_WINDOWS_BUILD

if TYPE_CHECKING:
    from pipeline.patch_identifier import PatchResult

log = logging.getLogger(__name__)

# The blog agent writes prose from the context it is handed; it must not read local
# files. The pipeline runs from the repo root, which holds this CVE's own prior
# writeups (patchbook/_reports/, data/blogs/), so allowing filesystem tools would let
# the model recycle an earlier writeup instead of working from the supplied
# decompilation.
_DENY_LOCAL_TOOLS = ["Read", "Edit", "Write", "NotebookEdit", "Glob", "Grep", "Bash", "Task"]

_SYSTEM_PROMPT = """\
You are a Windows kernel security researcher and technical writer with deep expertise in \
low-level Windows internals, exploit development, and binary patch analysis.

Your job is to write an in-depth technical blog post for a security research audience. \
You will be given: the CVE metadata, a structured analysis of the patched functions \
(vulnerability description, fix description, attack vector), the actual decompiled pseudo-C \
for the patched functions (pre-patch and post-patch), and the binary diff.

## Output format

Begin your response with a metadata block, exactly in this form and nothing before it:

<!--meta
title: <the post title — see rules below>
excerpt: <one or two plain-text sentences, no Markdown, no code, that state the affected \
component, the bug class, and the impact; 200-300 characters>
-->

Immediately after the block, write the post. Start with an H1 that repeats the title \
(`# <title>`), then the sections below.

A metadata box (affected binary + version transition, CVE, CVSS, class, patch KB) is \
inserted automatically right under the H1 — do **not** write your own summary table, \
metadata list, or "affected binary / CVSS / KB" line. Begin directly with `## TL;DR`.

### Title rules

- Format: `CVE-YYYY-NNNNN: <Concise Technical Description>`.
- The description names the **bug class** and the **component or function** it lives in, \
e.g. `Use-After-Free in the Windows IPv4 Source-Routing Path`.
- Title Case, no trailing period, at most ~80 characters after the colon.
- Prefer the precise vulnerability class (Use-After-Free, Out-of-Bounds Write, Type \
Confusion, Race Condition, Integer Overflow, Info Leak) over the generic MSRC category.

### Required sections (use these exact H2 headings, in this order)

1. `## TL;DR` — 3-6 sentences: the subsystem, the root cause, the primitive an attacker \
gains, and what the patch changed. Someone should be able to read only this and understand \
the bug.
2. `## Background` — the subsystem, data structures, and code path a reader needs before \
the bug makes sense. Keep it tight and specific to this vulnerability.
3. `## Root Cause` — the exact defect. Use the pre-patch decompiled code as primary \
evidence: quote variable names, pointer arithmetic, reference-count and locking patterns, \
and control flow directly.
4. `## The Patch` — walk through every changed function. Explain each added check, new \
helper, restructured operation, or probe, showing before/after from the decompiled code and \
diff together. Note any `Feature_*` gating.
5. `## Exploitability` — the attack primitive obtained (arbitrary write, info-leak, UAF, \
etc.), the trigger condition or race window, reachability (local vs remote, required \
privileges), and why it is practical despite the complexity rating.

You may add further H2 sections after these if the material warrants (e.g. \
`## Affected Versions`, `## Detection`), but the five above are mandatory and must appear \
in that order.

## Style

Write in an authoritative but conversational style. Every paragraph must add new technical \
information — do not pad or repeat yourself. Do not include a "lessons", "takeaways", or \
"conclusion" section. Assume the reader understands C, Windows kernel architecture, and \
common vulnerability classes but may not be familiar with this specific subsystem.\
"""


_PATCH_TYPE_LABELS = {
    "TOCTOU": "TOCTOU race condition",
    "EoP": "Elevation of privilege",
    "buffer_overflow": "Buffer overflow",
    "use_after_free": "Use-after-free",
    "null_deref": "Null-pointer dereference",
    "info_leak": "Information disclosure",
    "other": "",
}


def _metadata_box(
    cve: dict,
    binary_name: str,
    patch_result: "PatchResult | None",
    versions: dict | None,
) -> str:
    """Build the deterministic metadata block shown at the top of every post.

    Assembled from pipeline data (not the LLM) so it is present and consistent in
    every post regardless of what the model chooses to write.
    """
    lines: list[str] = []

    if versions and versions.get("pre_build") and versions.get("post_build"):
        pre = f"10.0.{TARGET_WINDOWS_BUILD}.{versions['pre_build']}"
        post = f"10.0.{TARGET_WINDOWS_BUILD}.{versions['post_build']}"
        lines.append(f"- **Affected binary:** `{binary_name}` {pre} → {post}")
    elif binary_name:
        lines.append(f"- **Affected binary:** `{binary_name}`")

    lines.append(f"- **CVE:** {cve['id']}")

    if cve.get("cvss"):
        lines.append(f"- **CVSS:** {cve['cvss']}")

    if patch_result is not None:
        label = _PATCH_TYPE_LABELS.get(patch_result.patch_type, "")
        if label:
            lines.append(f"- **Class:** {label}")

    kbs = [kb for kb in cve.get("kb_numbers", []) if kb]
    if kbs:
        kb_str = kbs[0] if len(kbs) == 1 else f"{kbs[0]} and related"
        lines.append(f"- **Patch KB:** {kb_str}")

    return "\n".join(lines)


def _prepend_metadata_box(blog_text: str, box: str) -> str:
    """Insert *box* immediately after the post's first H1 heading.

    Falls back to prepending if the model produced no H1.
    """
    if not box:
        return blog_text
    lines = blog_text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("# "):
            rest = lines[i + 1:]
            # skip any blank lines right after the H1 so the box sits flush under it
            while rest and not rest[0].strip():
                rest = rest[1:]
            return "\n".join(lines[: i + 1] + ["", box, ""] + rest)
    return box + "\n\n" + blog_text


def _truncate_diff(diff_text: str, char_limit: int) -> str:
    """Keep the most security-relevant sections of the ghidriff output."""
    if len(diff_text) <= char_limit:
        return diff_text

    # Split into sections by Markdown heading
    sections = re.split(r"(?=^#{1,3} )", diff_text, flags=re.MULTILINE)

    security_keywords = re.compile(
        r"check|valid|bound|overflow|size|length|alloc|free|ref|count|lock|race"
        r"|access|priv|elevat|exploit|vuln|patch|fix|change",
        re.I,
    )

    # Score each section: higher score = more security-relevant
    scored: list[tuple[int, str]] = []
    for section in sections:
        score = len(security_keywords.findall(section))
        scored.append((score, section))

    # Always keep the preamble (first section) and sort the rest by score
    preamble = scored[0][1] if scored else ""
    rest = sorted(scored[1:], key=lambda x: x[0], reverse=True)

    result = preamble
    for _, section in rest:
        if len(result) + len(section) > char_limit:
            break
        result += section

    result += f"\n\n*[Diff truncated to fit context window — {len(diff_text):,} characters total]*\n"
    return result


def generate_blog_post(
    cve: dict,
    binary_name: str,
    patch_result: "PatchResult | None" = None,
    diff_path: "Path | None" = None,
    versions: dict | None = None,
) -> str:
    """Call Claude to generate a blog post and return the Markdown text.

    Prefers *patch_result* (from patch_identifier) which has clean, focused signal.
    Falls back to reading the full *diff_path* if no patch_result provided.
    """
    if patch_result is not None:
        co_patches = getattr(patch_result, "co_patches", []) or []
        n_co = len(co_patches)

        # Char budget for diffs: primary gets 60%, co-patches share 40%
        primary_diff_limit = int(DIFF_INPUT_CHAR_LIMIT * 0.60) if co_patches else DIFF_INPUT_CHAR_LIMIT
        co_diff_limit = max(1000, int(DIFF_INPUT_CHAR_LIMIT * 0.40) // n_co) if co_patches else 0

        def _section(label: str, text: str, lang: str = "") -> str:
            if not text or text.startswith("["):
                return ""
            fence = f"```{lang}"
            return f"\n{label}\n{fence}\n{text}\n```\n"

        # ── Primary function ──────────────────────────────────────────────
        patch_context = f"## Primary Patch — `{patch_result.function_name}` ({patch_result.confidence}% confidence)\n\n"
        patch_context += f"**Bug class**: {patch_result.patch_type}\n"
        patch_context += f"**Reasoning**: {patch_result.reasoning}\n"

        if patch_result.vulnerability_description:
            patch_context += f"\n**Vulnerability**: {patch_result.vulnerability_description}\n"
        if patch_result.fix_description:
            patch_context += f"\n**Fix**: {patch_result.fix_description}\n"
        if patch_result.attack_vector:
            patch_context += f"\n**Attack vector**: {patch_result.attack_vector}\n"
        if patch_result.callers:
            patch_context += f"\n**Called by** (post-patch): {', '.join(patch_result.callers[:10])}\n"

        patch_context += _section("\n### Pre-patch decompilation", patch_result.decompiled_pre, "c")
        patch_context += _section("\n### Post-patch decompilation", patch_result.decompiled_post, "c")
        patch_context += f"\n### Diff\n```diff\n{patch_result.full_diff[:primary_diff_limit]}\n```\n"
        if len(patch_result.full_diff) > primary_diff_limit:
            patch_context += "*(diff truncated)*\n"

        # ── Co-patched functions ──────────────────────────────────────────
        for co in co_patches:
            patch_context += f"\n---\n\n## Co-patched — `{co['name']}` ({co['confidence']}% confidence)\n\n"
            patch_context += f"**Bug class**: {co.get('patch_type', 'other')}\n"
            patch_context += f"**Reasoning**: {co['reasoning']}\n"
            patch_context += _section("\n### Pre-patch decompilation", co.get("decompiled_pre", ""), "c")
            patch_context += _section("\n### Post-patch decompilation", co.get("decompiled_post", ""), "c")
            co_diff = co.get("diff", "")
            if co_diff:
                patch_context += f"\n### Diff\n```diff\n{co_diff[:co_diff_limit]}\n```\n"
                if len(co_diff) > co_diff_limit:
                    patch_context += "*(diff truncated)*\n"

        if co_patches:
            names = ", ".join(f"`{c['name']}`" for c in co_patches)
            patch_context += (
                f"\n---\n\n*`{patch_result.function_name}` is the primary patch. "
                f"{names} {'is' if n_co == 1 else 'are'} co-patched — Microsoft applied the same "
                f"fix consistently across multiple related code paths.*\n"
            )
    elif diff_path is not None:
        raw_diff = diff_path.read_text(encoding="utf-8", errors="replace")
        diff_content = _truncate_diff(raw_diff, DIFF_INPUT_CHAR_LIMIT)
        patch_context = f"## Binary Diff (ghidriff output — full, {len(raw_diff):,} chars)\n\n{diff_content}"
    else:
        raise ValueError("Either patch_result or diff_path must be provided")

    cvss_str = f"CVSS {cve['cvss']}" if cve.get("cvss") else "CVSS unknown"
    kb_str = ", ".join(cve.get("kb_numbers", [])) or "unknown"

    user_message = f"""\
## CVE Details

- **CVE ID**: {cve['id']}
- **Title**: {cve.get('title', '')}
- **Severity**: {cvss_str}
- **Patch KB**: {kb_str}
- **Affected binary**: `{binary_name}`

### Description from MSRC

{cve.get('description', '(none)')}

---

{patch_context}
"""

    log.info("→ claude -p  blog post for %s (input=%d chars, timeout=600s)",
             cve["id"], len(user_message))
    print(f"  → claude [blog:{cve['id']}]  ({len(user_message)} chars, timeout=600s) ...", flush=True)
    result = subprocess.run(
        ["claude", "-p", "--system-prompt", _SYSTEM_PROMPT, "--model", CLAUDE_MODEL,
         "--disallowedTools", ",".join(_DENY_LOCAL_TOOLS)],
        input=user_message,
        capture_output=True,
        text=True,
        timeout=600,
    )
    print(f"  ← claude [blog:{cve['id']}]  returned {len(result.stdout)} chars  (exit {result.returncode})",
          flush=True)
    log.info("← claude -p  blog returned %d chars (exit %d)", len(result.stdout), result.returncode)
    if result.returncode != 0:
        raise RuntimeError(
            f"claude CLI exited {result.returncode}: {result.stderr[:500]}"
        )

    blog_text = result.stdout.strip()
    if not blog_text:
        raise RuntimeError("Claude CLI returned an empty response")

    box = _metadata_box(cve, binary_name, patch_result, versions)
    blog_text = _prepend_metadata_box(blog_text, box)

    return blog_text, user_message


def _title_slug(title: str) -> str:
    """Convert a CVE title to a short filename-safe slug (max 60 chars)."""
    drop = {"vulnerability", "windows", "microsoft", "the", "a", "an", "of", "in", "and", "for"}
    words = re.sub(r"[^a-z0-9 ]", "", title.lower()).split()
    slug = "-".join(w for w in words if w not in drop)
    return slug[:60].rstrip("-")


def _versioned_path(base: Path) -> Path:
    """Return *base* unchanged if it doesn't exist, otherwise append a UTC timestamp."""
    if not base.exists():
        return base
    from datetime import datetime as _dt
    ts = _dt.utcnow().strftime("%Y%m%dT%H%M%S")
    return base.with_name(f"{base.stem}_{ts}{base.suffix}")


def save_blog_post(blog_text: str, cve_id: str, output_dir: Path,
                   title: str = "", prompt: str = "") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_id = cve_id.replace("/", "-")
    if title:
        slug = _title_slug(title)
        base_name = f"{safe_id}_{slug}.md" if slug else f"{safe_id}.md"
    else:
        base_name = f"{safe_id}.md"
    path = _versioned_path(output_dir / base_name)
    header = f"# {cve_id}\n\n*Generated by kernel-cve-pipeline*\n\n---\n\n"
    path.write_text(header + blog_text, encoding="utf-8")
    if prompt:
        path.with_suffix(".prompt.txt").write_text(prompt, encoding="utf-8")
    log.info("Blog post saved: %s", path)
    return path
