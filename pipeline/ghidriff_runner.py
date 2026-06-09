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
        print(f"  [ghidriff] starting — this takes 20-40 min", flush=True)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                bufsize=1,
            )
            output_lines: list[str] = []
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                output_lines.append(stripped)
                print(f"  [ghidriff] {stripped}", flush=True)
            try:
                proc.wait(timeout=GHIDRIFF_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                raise RuntimeError(
                    f"ghidriff timed out after {GHIDRIFF_TIMEOUT}s for {old_binary.name}"
                )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"ghidriff timed out after {GHIDRIFF_TIMEOUT}s for {old_binary.name}"
            )

        if proc.returncode != 0:
            tail = "\n".join(output_lines[-100:])
            log.error("ghidriff output (last 100 lines):\n%s", tail)
            raise RuntimeError(
                f"ghidriff exited {proc.returncode} for {old_binary.name}: "
                f"{chr(10).join(output_lines[-5:])}"
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
