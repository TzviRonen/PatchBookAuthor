"""Maps CVE title/description to affected kernel binary filename."""
import json
import logging
import re
import subprocess

log = logging.getLogger(__name__)

# (pattern, binary_filename) — first match wins
_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bwin32kfull\b", re.I),              "win32kfull.sys"),
    (re.compile(r"\bwin32kbase\b", re.I),              "win32kbase.sys"),
    (re.compile(r"\bwin32k\b", re.I),                  "win32k.sys"),
    (re.compile(r"\bclfs\b|common log file", re.I),    "clfs.sys"),
    (re.compile(r"\bafd\.sys\b|\bafd driver\b|winsock auxiliary", re.I), "afd.sys"),
    (re.compile(r"\bndis\b|network driver interface", re.I), "ndis.sys"),
    (re.compile(r"\btcpip\b|tcp/ip", re.I),              "tcpip.sys"),
    (re.compile(r"\bntfs\b", re.I),                    "ntfs.sys"),
    (re.compile(r"\bfastfat\b", re.I),                 "fastfat.sys"),
    (re.compile(r"\bsrv2\b|smb server|smb2", re.I),   "srv2.sys"),
    (re.compile(r"\bcng\b|cryptographic next gen", re.I), "cng.sys"),
    (re.compile(r"\bhal\b|hardware abstraction layer", re.I), "hal.dll"),
    (re.compile(r"\bhyper.?v\b", re.I),                "hvix64.exe"),
    (re.compile(r"\bstorport\b", re.I),                "storport.sys"),
    (re.compile(r"\bbthport\b|bluetooth", re.I),       "bthport.sys"),
    (re.compile(r"\bnetio\b|windows filtering platform|wfp\b", re.I), "netio.sys"),
    (re.compile(r"\brmcast\b|reliable multicast|\bpgm\b", re.I), "rmcast.sys"),
    (re.compile(r"\bwindows kernel\b|kernel-mode driver|nt kernel", re.I), "ntoskrnl.exe"),
]

# Filenames the LLM fallback is allowed to return: a bare PE module name.
_BINARY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}\.(sys|exe|dll)$")

# Titles that clearly indicate non-kernel userspace components
_SKIP_PATTERNS = re.compile(
    r"\b(edge|chrome|office|excel|word|outlook|sharepoint|teams|visual studio"
    r"|directx|opengl|media player|windows media|iis|sql server"
    r"|hyper-v guest|rdp client|terminal services client"
    r"|print spooler|windows installer|msi)\b",
    re.I,
)


def classify_cve(cve: dict) -> str | None:
    """Return the single best-guess binary filename, else None. Kept for back-compat."""
    cands = candidate_binaries(cve)
    return cands[0] if cands else None


# Binaries to try (in order) when the title/description names a subsystem only generically,
# e.g. "Windows Kernel Remote Code Execution". A network-reachable kernel bug is frequently
# fixed in a transport/driver (tcpip.sys, netio.sys, afd.sys), not ntoskrnl.exe — the single
# keyword guess is exactly why CVE-2026-45657's tcpip.sys fix was missed.
_GENERIC_KERNEL_FALLBACK = [
    "ntoskrnl.exe", "tcpip.sys", "netio.sys", "afd.sys", "fwpkclnt.sys",
]
_NETWORK_HINT = re.compile(r"over a network|network|remote|tcp/?ip|udp|packet|ipv[46]", re.I)

# Fallback set for a generic *local* kernel CVE ("Windows Kernel ... elevate privileges
# locally"). These EoP/UAF bugs frequently live in a kernel driver rather than ntoskrnl.exe
# itself (clfs.sys is a perennial local-EoP UAF surface), and the ntoskrnl.exe delta for the
# month is often only CFR-gate cleanup. ntoskrnl.exe stays first, then the common drivers —
# the research loop moves on to these when ntoskrnl.exe does not validate.
_GENERIC_KERNEL_LOCAL_FALLBACK = [
    "ntoskrnl.exe", "clfs.sys", "cng.sys", "ntfs.sys", "fastfat.sys", "ksecdd.sys",
]


def candidate_binaries(cve: dict) -> list[str]:
    """Return a ranked list of candidate binaries to diff for *cve* (empty if not kernel).

    Keyword-rule matches come first (most specific), then a generic kernel/network fallback
    set so the research loop can try alternatives when the first guess does not validate.
    """
    text = f"{cve.get('title', '')} {cve.get('description', '')}"
    if _SKIP_PATTERNS.search(text):
        return []

    ranked: list[str] = []
    for pattern, binary in _RULES:
        if pattern.search(text) and binary not in ranked:
            ranked.append(binary)

    if not ranked:
        # No keyword rule fired. Rather than give up (which drops real kernel CVEs whose
        # component we simply don't have a rule for — e.g. rmcast.sys before it was added),
        # ask a Claude Code agent to name the likely binary from the CVE text.
        ranked = _llm_candidate_binaries(cve)
        if not ranked:
            return []

    # If the CVE is network-reachable, the fix is more likely in a transport/driver than in
    # core ntoskrnl.exe. Add the transport fallbacks AND demote ntoskrnl.exe below them, so
    # a generic "Windows Kernel" network CVE tries tcpip.sys/netio.sys first (this is what
    # separated CVE-2026-45657's real tcpip.sys fix from a UAF-shaped ntoskrnl change).
    if _NETWORK_HINT.search(text):
        for b in _GENERIC_KERNEL_FALLBACK:
            if b not in ranked:
                ranked.append(b)
        if "ntoskrnl.exe" in ranked:
            ranked = [b for b in ranked if b != "ntoskrnl.exe"] + ["ntoskrnl.exe"]
    elif ranked == ["ntoskrnl.exe"]:
        # Only the generic "Windows Kernel" rule matched (no specific driver, not network):
        # a local kernel EoP/UAF whose fix may sit in a driver. Keep ntoskrnl.exe first, then
        # the common local-EoP drivers so the loop can try them when ntoskrnl.exe declines.
        for b in _GENERIC_KERNEL_LOCAL_FALLBACK:
            if b not in ranked:
                ranked.append(b)
    return ranked


_LLM_SYSTEM_PROMPT = (
    "You map a Microsoft Windows CVE to the kernel-mode PE module (driver or the kernel "
    "itself) whose binary most likely contains the fix. You are given the CVE title and "
    "description. Reply with ONLY a JSON array of candidate PE filenames, most-likely "
    "first, lowercase, with extension (e.g. [\"rmcast.sys\", \"tcpip.sys\"]). Rules:\n"
    "- Map the named component/subsystem to its shipping driver filename (e.g. \"Reliable "
    "Multicast Transport Driver (RMCAST)\" -> rmcast.sys; \"Ancillary Function Driver for "
    "WinSock\" -> afd.sys; \"Common Log File System\" -> clfs.sys).\n"
    "- If it is a generic \"Windows Kernel\" bug with no specific component, return "
    "[\"ntoskrnl.exe\"].\n"
    "- If it is NOT a kernel-mode/driver vulnerability (a user-mode app, cloud service, "
    "Edge, Office, etc.), return [].\n"
    "- Output the JSON array and nothing else — no prose, no code fences."
)


def _llm_candidate_binaries(cve: dict) -> list[str]:
    """Fallback binary resolver: ask a Claude Code agent when no keyword rule matched.

    Best-effort. Any failure (CLI missing, timeout, unparseable/implausible output) returns
    an empty list so the caller falls back to treating the CVE as non-kernel rather than
    crashing the pipeline.
    """
    from pipeline.config import CLAUDE_MODEL

    title = cve.get("title", "")
    description = cve.get("description", "")
    user_message = f"Title: {title}\n\nDescription: {description}\n"
    try:
        result = subprocess.run(
            ["claude", "-p", "--system-prompt", _LLM_SYSTEM_PROMPT,
             "--model", CLAUDE_MODEL],
            input=user_message,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning("LLM binary-resolver unavailable (%s); treating CVE as non-kernel", e)
        return []
    if result.returncode != 0:
        log.warning("LLM binary-resolver exited %d: %s", result.returncode,
                    (result.stderr or "")[:200])
        return []

    raw = (result.stdout or "").strip()
    m = re.search(r"\[.*\]", raw, re.S)   # tolerate stray prose/fences around the array
    if not m:
        log.warning("LLM binary-resolver returned no JSON array: %r", raw[:200])
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        log.warning("LLM binary-resolver returned invalid JSON: %r", m.group(0)[:200])
        return []

    out: list[str] = []
    for item in items if isinstance(items, list) else []:
        name = str(item).strip().lower()
        if _BINARY_NAME_RE.match(name) and name not in out:
            out.append(name)
    if out:
        log.info("LLM binary-resolver -> %s for %s", out, cve.get("id", "?"))
    return out

