"""Maps CVE title/description to affected kernel binary filename."""
import re

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
    (re.compile(r"\bwindows kernel\b|kernel-mode driver|nt kernel", re.I), "ntoskrnl.exe"),
]

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
    return ranked

