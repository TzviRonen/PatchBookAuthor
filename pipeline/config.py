import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", str(Path(__file__).parent.parent / "data")))
BINARIES_DIR = DATA_DIR / "binaries"
DIFFS_DIR = DATA_DIR / "diffs"
BLOGS_DIR = DATA_DIR / "blogs"
DB_PATH = DATA_DIR / "db" / "pipeline.db"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
POLL_INTERVAL_HOURS = int(os.getenv("POLL_INTERVAL_HOURS", "24"))
# Target Windows build number (3rd component of PE file version, e.g. 19041 for Win10 22H2).
# Winbindex has multiple ntoskrnl.exe versions per Patch Tuesday (one per Windows release).
# 19041 = Win10 21H2/22H2 | 22621 = Win11 22H2 | 17763 = Win10 LTSC 2019
TARGET_WINDOWS_BUILD = int(os.getenv("TARGET_WINDOWS_BUILD", "19041"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"
WINBINDEX_BASE_URL = "https://winbindex.m417z.com/data/by_filename_compressed"
SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"

GHIDRA_INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR", "/opt/ghidra")
GHIDRIFF_TIMEOUT = 3600  # 1 hour per binary pair

CLAUDE_MODEL = "claude-opus-4-8"
BLOG_MAX_TOKENS = 8192
DIFF_INPUT_CHAR_LIMIT = 400_000  # ~100k tokens of diff content
