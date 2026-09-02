import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", str(Path(__file__).parent.parent / "data")))
BINARIES_DIR = DATA_DIR / "binaries"
DIFFS_DIR = DATA_DIR / "diffs"
BLOGS_DIR = DATA_DIR / "blogs"
DB_PATH = DATA_DIR / "db" / "pipeline.db"

# No ANTHROPIC_API_KEY: LLM calls go through the `claude -p` CLI's own OAuth login.
POLL_INTERVAL_HOURS = int(os.getenv("POLL_INTERVAL_HOURS", "24"))
# Target Windows build number (3rd component of PE file version, e.g. 19041 for Win10 22H2).
# Winbindex has multiple ntoskrnl.exe versions per Patch Tuesday (one per Windows release).
# 19041 = Win10 21H2/22H2 | 22621 = Win11 22H2/23H2 | 26100 = Win11 24H2 | 17763 = LTSC 2019
#
# NOTE: a CVE only ships a fix on the lineages it actually affects. We no longer assume every
# CVE touches 19041 — the target lineage is resolved per-CVE from MSRC affected-product data
# (see pipeline/target_resolver.py). PREFERRED_BUILD_LINEAGES only orders which affected
# lineage we diff first (smallest/most-available base first). TARGET_WINDOWS_BUILD remains as
# a legacy default for the deterministic blog metadata box when no target lineage is supplied.
TARGET_WINDOWS_BUILD = int(os.getenv("TARGET_WINDOWS_BUILD", "19041"))
PREFERRED_BUILD_LINEAGES = [
    int(x) for x in os.getenv(
        "PREFERRED_BUILD_LINEAGES", "19041,22621,26100,26200,28000"
    ).split(",") if x.strip()
]
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"
# Security Update Guide API — authoritative per-CVE CWE list, CVSS vector, impact, and
# per-product fixedBuildNumber. Used to resolve the correct affected build lineage.
MSRC_SUG_BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
WINBINDEX_BASE_URL = "https://winbindex.m417z.com/data/by_filename_compressed"
SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"

GHIDRA_INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
GHIDRIFF_TIMEOUT = 3600  # 1 hour per binary pair

# ── IDA Pro backend (--backend ida) ───────────────────────────────────────
# IDA runs on a Windows VM; the pipeline reaches its MCP server over an SSH
# tunnel opened by scripts/start_ida_tunnel.sh. Defaults mirror that script — keep
# the two in sync.
IDA_VM_HOST = os.getenv("IDA_VM_HOST", "192.168.10.128")
IDA_VM_USER = os.getenv("IDA_VM_USER", "auto")
IDA_VM_KEY = os.getenv(
    "IDA_VM_KEY", str(Path(__file__).parent.parent / "auto_vm_key.pub")
)
# Persistent work dir on the VM. Uploaded binaries and their .i64 databases
# are kept so repeat runs can reuse the analysis.
IDA_WORK_DIR = os.getenv("IDA_WORK_DIR", r"C:\ida_work")
IDA_INSTALL_DIR = os.getenv("IDA_INSTALL_DIR", r"C:\Program Files\IDA Professional 9.3")
# Auto-analysis of a kernel-sized binary is slow (matches Ghidra's budget).
IDA_MCP_STARTUP_TIMEOUT = int(os.getenv("IDA_MCP_STARTUP_TIMEOUT", "900"))

CLAUDE_MODEL = "claude-opus-4-8"
BLOG_MAX_TOKENS = 8192
DIFF_INPUT_CHAR_LIMIT = 400_000  # ~100k tokens of diff content
