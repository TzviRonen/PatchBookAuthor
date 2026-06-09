"""Generate a kernel-developer blog post from a ghidriff diff using Claude."""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.config import DIFF_INPUT_CHAR_LIMIT

if TYPE_CHECKING:
    from pipeline.patch_identifier import PatchResult

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a Windows kernel security researcher and technical writer with deep expertise in \
low-level Windows internals, exploit development, and secure coding practices.

Your job is to write an in-depth technical blog post aimed at kernel developers. \
Given a CVE record and the binary diff between the vulnerable and patched versions, explain:

1. **What the bug was** — the exact root cause (buffer overflow, use-after-free, integer overflow, \
type confusion, missing check, race condition, etc.), the kernel code path it lived in, \
and what conditions triggered it.

2. **What the patch did** — walk through the changed functions, explain every added bounds check, \
new lock, corrected type, or restructured logic. Use the diff directly as evidence.

3. **What kernel developers should learn** — concrete, actionable coding lessons derived \
from this specific bug. Reference the changed code. Give code-level examples of the \
correct pattern versus the buggy pattern where relevant.

Write in an authoritative but conversational style. Use Markdown with clear section headers. \
Do not pad or repeat yourself — every paragraph should add new technical information. \
Assume the reader understands C, Windows kernel architecture, and common vulnerability classes \
but may not be familiar with this specific subsystem.\
"""


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
) -> str:
    """Call Claude to generate a blog post and return the Markdown text.

    Prefers *patch_result* (from patch_identifier) which has clean, focused signal.
    Falls back to reading the full *diff_path* if no patch_result provided.
    """
    if patch_result is not None:
        co_patches = getattr(patch_result, "co_patches", []) or []

        if co_patches:
            # Split char budget: primary gets 60%, co-patches share 40%
            n_co = len(co_patches)
            primary_limit = int(DIFF_INPUT_CHAR_LIMIT * 0.60)
            co_limit = max(1000, int(DIFF_INPUT_CHAR_LIMIT * 0.40) // n_co)
        else:
            primary_limit = DIFF_INPUT_CHAR_LIMIT
            co_limit = 0

        patch_context = f"""\
## Primary Patch — `{patch_result.function_name}` ({patch_result.confidence}% confidence)

**Bug class**: {patch_result.patch_type}
**Analysis**: {patch_result.reasoning}

```diff
{patch_result.full_diff[:primary_limit]}
```
{"*(truncated)*" if len(patch_result.full_diff) > primary_limit else ""}
"""
        for co in co_patches:
            co_diff = co.get("diff", "")
            patch_context += f"""
---

## Co-patched Function — `{co['name']}` ({co['confidence']}% confidence)

**Bug class**: {co.get('patch_type', 'other')}
**Analysis**: {co['reasoning']}

```diff
{co_diff[:co_limit]}
```
{"*(truncated)*" if len(co_diff) > co_limit else ""}
"""

        if co_patches:
            names = ", ".join(f"`{c['name']}`" for c in co_patches)
            patch_context += f"""
---

*Note: `{patch_result.function_name}` is the primary patch. {names} \
{"is" if n_co == 1 else "are"} co-patched — Microsoft applied the same fix consistently \
across multiple related code paths. Describe all functions and how together they form a \
complete, coherent security fix.*
"""
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
    result = subprocess.run(
        ["claude", "-p", "--system-prompt", _SYSTEM_PROMPT],
        input=user_message,
        capture_output=True,
        text=True,
        timeout=600,
    )
    log.info("← claude -p  blog returned %d chars (exit %d)", len(result.stdout), result.returncode)
    if result.returncode != 0:
        raise RuntimeError(
            f"claude CLI exited {result.returncode}: {result.stderr[:500]}"
        )

    blog_text = result.stdout.strip()
    if not blog_text:
        raise RuntimeError("Claude CLI returned an empty response")

    return blog_text


def _title_slug(title: str) -> str:
    """Convert a CVE title to a short filename-safe slug (max 60 chars)."""
    drop = {"vulnerability", "windows", "microsoft", "the", "a", "an", "of", "in", "and", "for"}
    words = re.sub(r"[^a-z0-9 ]", "", title.lower()).split()
    slug = "-".join(w for w in words if w not in drop)
    return slug[:60].rstrip("-")


def save_blog_post(blog_text: str, cve_id: str, output_dir: Path, title: str = "") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_id = cve_id.replace("/", "-")
    if title:
        slug = _title_slug(title)
        filename = f"{safe_id}_{slug}.md" if slug else f"{safe_id}.md"
    else:
        filename = f"{safe_id}.md"
    path = output_dir / filename
    header = f"# {cve_id}\n\n*Generated by kernel-cve-pipeline*\n\n---\n\n"
    path.write_text(header + blog_text, encoding="utf-8")
    log.info("Blog post saved: %s", path)
    return path
