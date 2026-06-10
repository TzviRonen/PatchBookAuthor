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
    """Return the binary filename if *cve* is a kernel CVE, else None."""
    text = f"{cve.get('title', '')} {cve.get('description', '')}"

    if _SKIP_PATTERNS.search(text):
        return None

    for pattern, binary in _RULES:
        if pattern.search(text):
            return binary

    return None
