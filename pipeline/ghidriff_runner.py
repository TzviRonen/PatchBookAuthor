"""Run ghidriff on a binary pair and return the path to the Markdown output."""
from __future__ import annotations

import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.config import GHIDRA_INSTALL_DIR, GHIDRIFF_TIMEOUT, DATA_DIR

if TYPE_CHECKING:
    from pipeline.ghidra_mcp import GhidraMCPServer

log = logging.getLogger(__name__)

# Symbol cache shared across runs to avoid re-downloading PDBs
_SYMBOLS_DIR = DATA_DIR / "symbols"

# Persistent Ghidra project directory — allows the MCP server to reuse PDB-analyzed binaries
_GHIDRA_PROJECTS_DIR = DATA_DIR / "ghidra_projects"


def run_ghidriff(
    old_binary: Path,
    new_binary: Path,
    output_dir: Path,
    name: str,
    start_mcp: bool = True,
) -> tuple[Path, "GhidraMCPServer | None"]:
    """Diff *old_binary* against *new_binary* with ghidriff.

    If *start_mcp* is True and the GhidraMCP JAR is built, starts a GhidraMCP
    headless server in the background while ghidriff is running so it is ready
    by the time the identify stage needs it.

    Returns (diff_path, mcp_server_or_None).
    Caller must call mcp_server.stop() when done (or use it as a context manager).
    Raises RuntimeError on non-zero exit or timeout.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    _SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Check for cached diff ───────────────────────────────────────────────
    existing = list(output_dir.glob(f"*{old_binary.name}*{new_binary.name}*.md"))
    if not existing:
        existing = list(output_dir.glob(f"*{name}*.md"))

    mcp_server: GhidraMCPServer | None = None

    # ghidriff always appends binary names to the project name:
    #   {base}-{pre.name}-{post.name}
    # We must match this convention exactly so both ghidriff and the MCP server
    # look at the same directory.
    project_base = f"ghidriff_{name}"
    project_name = f"{project_base}-{old_binary.name}-{new_binary.name}"
    proj_dir = _GHIDRA_PROJECTS_DIR / project_name
    # Do NOT pre-create proj_dir — ghidriff creates it internally

    # Check whether the project has been analysed already.
    # ghidriff always leaves {project_name}.gpr as a 0-byte marker file — the actual
    # analysis data lives in {project_name}.rep/idata/**/*.gbf (190 MB+ per binary).
    # A project is only usable if those databases are non-trivially large (> 10 MB),
    # which confirms ghidriff ran to completion rather than crashing mid-analysis.
    _rep_idata = proj_dir / f"{project_name}.rep" / "idata"
    _gbf_files = list(_rep_idata.rglob("*.gbf")) if _rep_idata.is_dir() else []
    project_ready = bool(_gbf_files) and any(f.stat().st_size > 10 * 1024 * 1024 for f in _gbf_files)

    if existing and project_ready:
        log.info("ghidriff output already exists: %s", existing[0])
        # Diff already cached — still start MCP if requested (identify stage needs it)
        if start_mcp:
            mcp_server = _start_mcp_background(
                old_binary, new_binary,
                project_dir=proj_dir if project_ready else None,
                project_name=project_name,
            )
        return existing[0], mcp_server

    if existing and not project_ready:
        log.info(
            "Diff exists (%s) but Ghidra project missing — re-running ghidriff "
            "to create persistent project with PDB symbols.", existing[0].name
        )
        print(f"  [ghidriff] project not found — re-running to create it (20-40 min)", flush=True)

    # ── Start MCP server concurrently with ghidriff ─────────────────────────
    # (MCP will start with --file mode; after ghidriff finishes, the project
    #  will exist and future runs will use --project mode with PDB symbols)
    mcp_error: list[str] = []
    if start_mcp:
        mcp_server = _start_mcp_background(
            old_binary, new_binary,
            project_dir=proj_dir if project_ready else None,
            project_name=project_name,
            error_sink=mcp_error,
        )

    # ── Run ghidriff ────────────────────────────────────────────────────────
    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": GHIDRA_INSTALL_DIR,
        "JAVA_HOME": os.getenv("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64"),
    }

    _venv_bin = Path(os.path.dirname(os.sys.executable)) / "ghidriff"
    ghidriff_bin = str(_venv_bin) if _venv_bin.exists() else "ghidriff"
    cmd = [
        ghidriff_bin,
        str(old_binary),
        str(new_binary),
        "--output-path", str(output_dir),
        "--project-location", str(_GHIDRA_PROJECTS_DIR),
        "--project-name", project_base,   # ghidriff appends -{pre}-{post} itself
        "--symbols-path", str(_SYMBOLS_DIR),
        "--log-level", "WARNING",
    ]

    log.info("Running ghidriff:\n  %s", " ".join(cmd))
    print("  [ghidriff] starting — this takes 20-40 min", flush=True)
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
        if mcp_server:
            mcp_server.stop()
        raise RuntimeError(
            f"ghidriff timed out after {GHIDRIFF_TIMEOUT}s for {old_binary.name}"
        )

    if proc.returncode != 0:
        tail = "\n".join(output_lines[-100:])
        log.error("ghidriff output (last 100 lines):\n%s", tail)
        if mcp_server:
            mcp_server.stop()
        raise RuntimeError(
            f"ghidriff exited {proc.returncode} for {old_binary.name}: "
            f"{chr(10).join(output_lines[-5:])}"
        )

    md_files = sorted(output_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not md_files:
        if mcp_server:
            mcp_server.stop()
        raise RuntimeError(
            f"ghidriff succeeded (exit 0) but no .md found in {output_dir}"
        )

    output_path = md_files[0]
    log.info("ghidriff finished: %s (%d KB)", output_path.name, output_path.stat().st_size // 1024)

    if mcp_error:
        log.warning("GhidraMCP server failed to start: %s — identify will run without MCP",
                    mcp_error[0])
        mcp_server = None

    return output_path, mcp_server


def _start_mcp_background(
    pre_binary: Path,
    post_binary: Path,
    project_dir: "Path | None" = None,
    project_name: str | None = None,
    error_sink: list[str] | None = None,
) -> "GhidraMCPServer | None":
    """
    Start a GhidraMCP server in a background thread and return it immediately.
    The server's start() call blocks until the server is ready; the caller can
    proceed with ghidriff while that happens.
    The returned server object is safe to use after ghidriff finishes.

    When *project_dir* is provided (persistent Ghidra project with PDB symbols),
    the server starts in --project mode so function names are resolved.
    """
    from pipeline.ghidra_mcp import GhidraMCPServer, _JAR

    if not _JAR.exists():
        log.warning(
            "GhidraMCP JAR not found at %s — skipping MCP server. "
            "Build with: cd vendor/ghidra-mcp && mvn clean package -DskipTests -q", _JAR
        )
        return None

    server = GhidraMCPServer(pre_binary, post_binary, project_dir=project_dir)
    ready_event = threading.Event()
    start_error: list[str] = []

    def _start():
        try:
            server.start()
            ready_event.set()
        except Exception as exc:
            log.warning("GhidraMCP start failed: %s", exc)
            server.stop()  # ensure the subprocess is cleaned up
            start_error.append(str(exc))
            if error_sink is not None:
                error_sink.append(str(exc))
            ready_event.set()  # unblock waiter

    t = threading.Thread(target=_start, daemon=True, name="ghidra-mcp-start")
    t.start()

    # Attach the ready event and error list to the server so run_cve can wait
    server._ready_event = ready_event  # type: ignore[attr-defined]
    server._start_error = start_error  # type: ignore[attr-defined]
    server._start_thread = t           # type: ignore[attr-defined]
    return server
