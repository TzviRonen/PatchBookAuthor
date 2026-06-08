"""Run ghidriff on a binary pair and return the path to the Markdown output."""
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from pipeline.config import GHIDRA_INSTALL_DIR, GHIDRIFF_TIMEOUT

log = logging.getLogger(__name__)

# Symbol cache shared across runs to avoid re-downloading PDBs
_SYMBOLS_DIR = Path(os.getenv("DATA_DIR", "/data")) / "symbols"


def run_ghidriff(old_binary: Path, new_binary: Path, output_dir: Path, name: str) -> Path:
    """Diff *old_binary* against *new_binary* with ghidriff.

    Returns the path to the generated Markdown file.
    Raises RuntimeError on non-zero exit or timeout.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    _SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)

    # Check if output already exists (any .md matching the name pattern)
    existing = list(output_dir.glob(f"*{old_binary.name}*{new_binary.name}*.md"))
    if not existing:
        existing = list(output_dir.glob(f"*{name}*.md"))
    if existing:
        log.info("ghidriff output already exists: %s", existing[0])
        return existing[0]

    # Ghidra projects are large; use a temp dir scoped to this run
    with tempfile.TemporaryDirectory(prefix="ghidra_proj_") as proj_dir:
        env = {
            **os.environ,
            "GHIDRA_INSTALL_DIR": GHIDRA_INSTALL_DIR,
            "JAVA_HOME": os.getenv("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64"),
        }

        cmd = [
            "ghidriff",
            str(old_binary),
            str(new_binary),
            "--output-path", str(output_dir),
            "--project-location", proj_dir,
            "--project-name", f"ghidriff_{name}",
            "--symbols-path", str(_SYMBOLS_DIR),
            "--log-level", "WARNING",
        ]

        log.info("Running ghidriff:\n  %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=GHIDRIFF_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"ghidriff timed out after {GHIDRIFF_TIMEOUT}s for {old_binary.name}"
            )

        if result.returncode != 0:
            log.error("ghidriff stderr (last 6000 chars):\n%s", result.stderr[-6000:])
            raise RuntimeError(
                f"ghidriff exited {result.returncode} for {old_binary.name}: "
                f"{result.stderr[-500:]}"
            )

    # Find output file — ghidriff names it based on binary filenames
    md_files = sorted(output_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not md_files:
        raise RuntimeError(
            f"ghidriff succeeded (exit 0) but no .md found in {output_dir}"
        )

    output_path = md_files[0]
    log.info("ghidriff finished: %s (%d KB)", output_path.name, output_path.stat().st_size // 1024)
    return output_path
