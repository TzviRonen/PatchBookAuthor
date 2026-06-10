"""
Lifecycle management and HTTP client for bethington/ghidra-mcp headless server.
The server runs as a background subprocess; all tool calls go over HTTP to localhost.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

_REPO = Path(__file__).parent.parent / "vendor" / "ghidra-mcp"
_JAR = _REPO / "target" / "GhidraMCP-5.13.1.jar"
_STARTUP_TIMEOUT = 900   # seconds to wait for server to be ready (ntoskrnl takes 5-10 min)
_HEALTH_CHECK_INTERVAL = 5


def _sha1_file(path: Path) -> str:
    """Return full SHA1 hex digest of a file (matches ghidriff's sha1_file)."""
    sha1 = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


def _program_name(path: Path) -> str:
    """Return the program name ghidriff assigns: '{filename}-{sha1[:6]}'."""
    return f"{path.name}-{_sha1_file(path)[:6]}"


def _clear_project_lock(project_dir: Path) -> None:
    """Remove any stale Ghidra project lock files so we can open the project.

    Ghidra's GhidraProject.openProject() uses a file-system lock ({name}.lock)
    that is NOT bypassed by the restore=True flag.  If a previous server process
    crashed without releasing the lock, the file remains and every subsequent
    open attempt raises LockException.
    """
    for lock_file in project_dir.glob("*.lock"):
        try:
            lock_file.unlink()
            log.info("Removed stale project lock: %s", lock_file.name)
        except Exception as e:
            log.debug("Could not remove lock %s: %s", lock_file, e)


def _kill_port(port: int) -> None:
    """Kill any process listening on *port* so we can bind cleanly."""
    killed = False
    try:
        result = subprocess.run(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5,
        )
        pids = result.stdout.strip().split()
        for pid in pids:
            try:
                subprocess.run(["kill", "-9", pid], timeout=3, capture_output=True)
                log.info("Killed stale process %s on port %d", pid, port)
                killed = True
            except Exception:
                pass
    except FileNotFoundError:
        pass  # lsof not available
    except Exception as e:
        log.debug("_kill_port(%d) error: %s", port, e)
    if killed:
        # Allow OS to fully release file locks held by the killed process
        time.sleep(1.0)


def _ghidra_classpath() -> str:
    from pipeline.config import GHIDRA_INSTALL_DIR
    ghidra = Path(GHIDRA_INSTALL_DIR)
    jars = sorted(ghidra.glob("Ghidra/Framework/*/lib/*.jar"))
    jars += sorted(ghidra.glob("Ghidra/Features/*/lib/*.jar"))
    return ":".join(str(j) for j in [_JAR] + jars)


class GhidraMCPServer:
    """
    Wraps a single bethington/ghidra-mcp headless server process.

    Usage:
        with GhidraMCPServer(pre_binary, post_binary) as mcp:
            mcp.decompile_function("PiSwDeviceFree", mcp.post)
    """

    def __init__(
        self,
        pre_binary: Path,
        post_binary: Path,
        port: int = 8089,
        project_dir: Path | None = None,
    ):
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.pre_binary = pre_binary
        self.post_binary = post_binary
        self.project_dir = project_dir  # if set, use --project mode with PDB symbols
        self.pre: str = ""   # program name as Ghidra knows it (set after start)
        self.post: str = ""
        self._proc: subprocess.Popen | None = None

    # ── context manager ────────────────────────────────────────────────────

    def __enter__(self) -> "GhidraMCPServer":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the headless server, load both binaries, and wait until ready.

        If any step fails after the Java subprocess has started, stop() is called
        automatically so the subprocess is terminated and its Ghidra project lock
        is released before the exception propagates to the caller.
        """
        if not _JAR.exists():
            raise RuntimeError(
                f"GhidraMCP JAR not found at {_JAR}. "
                "Build it with: cd vendor/ghidra-mcp && mvn clean package -DskipTests -q"
            )

        # If something is already listening on the port, kill it first so we
        # start fresh with the correct binary pair.
        _kill_port(self.port)

        from pipeline.config import GHIDRA_INSTALL_DIR
        env = {
            **os.environ,
            "JAVA_HOME": os.getenv("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64"),
            "GHIDRA_INSTALL_DIR": GHIDRA_INSTALL_DIR,
        }

        using_project = self.project_dir is not None
        if using_project:
            # Remove any stale lock files left by crashed server instances
            _clear_project_lock(self.project_dir)
            cmd = [
                "java", "-cp", _ghidra_classpath(),
                "com.xebyte.headless.GhidraMCPHeadlessServer",
                "--port", str(self.port),
                "--project", str(self.project_dir),
            ]
            print(f"  [mcp] starting GhidraMCP server (port {self.port}) with project {self.project_dir.name} ...", flush=True)
        else:
            cmd = [
                "java", "-cp", _ghidra_classpath(),
                "com.xebyte.headless.GhidraMCPHeadlessServer",
                "--port", str(self.port),
                "--file", str(self.pre_binary),
            ]
            print(f"  [mcp] starting GhidraMCP server (port {self.port}) loading {self.pre_binary.name} ...", flush=True)

        log.info("GhidraMCP start: %s", " ".join(cmd[:5]) + " ...")
        self._proc = subprocess.Popen(
            cmd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        # Drain stdout in a background thread — without this the pipe buffer fills
        # and the Java process blocks, causing the server to never become ready.
        self._stdout_drain = threading.Thread(
            target=self._drain_stdout, daemon=True, name="ghidra-mcp-stdout"
        )
        self._stdout_drain.start()

        try:
            self._wait_ready()

            if using_project:
                # Load both programs from the existing project (which has PDB symbols)
                pre_prog_name = _program_name(self.pre_binary)
                post_prog_name = _program_name(self.post_binary)
                print(f"  [mcp] loading pre-patch from project: {pre_prog_name} ...", flush=True)
                self.pre = self._load_program_from_project(pre_prog_name)
                print(f"  [mcp] pre-patch program loaded: {self.pre}", flush=True)
                print(f"  [mcp] loading post-patch from project: {post_prog_name} ...", flush=True)
                self.post = self._load_program_from_project(post_prog_name)
                print(f"  [mcp] post-patch program loaded: {self.post}", flush=True)
            else:
                # --file mode: pre-patch was loaded by the server during startup
                open_progs = self.list_open_programs()
                self.pre = open_progs[0] if open_progs else self.pre_binary.name
                print(f"  [mcp] pre-patch program loaded: {self.pre}", flush=True)
                print(f"  [mcp] loading post-patch binary: {self.post_binary.name} ...", flush=True)
                self.post = self._load_program(self.post_binary)
                print(f"  [mcp] post-patch program loaded: {self.post}", flush=True)
        except Exception:
            # Always stop the subprocess on failure so the Ghidra project lock
            # is released before the exception propagates.
            self.stop()
            raise

        log.info("GhidraMCP ready — pre=%s  post=%s", self.pre, self.post)

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            log.info("Stopping GhidraMCP server")
            self._proc.terminate()
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _drain_stdout(self) -> None:
        """Read and log server stdout so the pipe never blocks the Java process."""
        if not self._proc or not self._proc.stdout:
            return
        try:
            for line in self._proc.stdout:
                stripped = line.rstrip("\n")
                if stripped:
                    log.debug("[mcp-server] %s", stripped)
        except Exception:
            pass

    def _wait_ready(self) -> None:
        deadline = time.time() + _STARTUP_TIMEOUT
        dots = 0
        while time.time() < deadline:
            # Check if process died
            if self._proc and self._proc.poll() is not None:
                raise RuntimeError(
                    f"GhidraMCP server exited early (exit {self._proc.returncode})"
                )
            try:
                r = requests.get(f"{self.base_url}/check_connection", timeout=3)
                if r.status_code == 200:
                    print(f"  [mcp] server ready", flush=True)
                    return
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                log.debug("Health check error: %s", e)
            if dots % 6 == 0:
                elapsed = int(time.time() - (deadline - _STARTUP_TIMEOUT))
                print(f"  [mcp] waiting for server ... ({elapsed}s)", flush=True)
            dots += 1
            time.sleep(_HEALTH_CHECK_INTERVAL)
        # Timeout — kill the orphaned process before raising
        self.stop()
        raise RuntimeError(
            f"GhidraMCP server did not become ready within {_STARTUP_TIMEOUT}s"
        )

    def _load_program(self, path: Path) -> str:
        """POST /load_program and return the program name Ghidra assigned."""
        resp = self._post("/load_program", {"file": str(path)})
        name = resp.get("program", path.name)
        return name

    def _load_program_from_project(self, prog_name: str) -> str:
        """POST /load_program_from_project; return the program name or raise."""
        path = f"/{prog_name}" if not prog_name.startswith("/") else prog_name
        resp = self._post("/load_program_from_project", {"path": path})
        if isinstance(resp, dict):
            if resp.get("success"):
                return resp.get("program", prog_name)
            # Structured failure — include available paths in the error
            avail = resp.get("available_program_paths", [])
            raise RuntimeError(
                f"load_program_from_project failed for '{path}': "
                f"{resp}. Available: {avail}"
            )
        return prog_name

    # ── analysis tools (called by the agent) ──────────────────────────────

    def decompile_function(self, name: str, program: str, timeout: int = 45) -> str:
        """Return decompiled pseudo-C for *name* from *program*."""
        try:
            resp = self._get("/decompile_function",
                             {"address": name, "program": program, "timeout": timeout})
            return _extract_text(resp)
        except Exception as e:
            return f"[decompile error: {e}]"

    def get_callers(self, name: str, program: str) -> list[str]:
        """Return names of functions that call *name* in *program*."""
        try:
            resp = self._get("/get_function_callers",
                             {"name": name, "program": program, "limit": 50})
            return _extract_list(resp)
        except Exception as e:
            return [f"[error: {e}]"]

    def get_callees(self, name: str, program: str) -> list[str]:
        """Return names of functions called by *name* in *program*."""
        try:
            resp = self._get("/get_function_callees",
                             {"name": name, "program": program, "limit": 50})
            return _extract_list(resp)
        except Exception as e:
            return [f"[error: {e}]"]

    def get_xrefs(self, name: str, program: str) -> list[str]:
        """Return cross-reference addresses/names for *name* in *program*."""
        try:
            resp = self._get("/get_function_xrefs",
                             {"name": name, "program": program, "limit": 50})
            return _extract_list(resp)
        except Exception as e:
            return [f"[error: {e}]"]

    def search_functions(self, pattern: str, program: str) -> list[str]:
        """Search function names by pattern in *program*."""
        try:
            resp = self._get("/search_functions",
                             {"name_pattern": pattern, "program": program, "limit": 30})
            return _extract_list(resp)
        except Exception as e:
            return [f"[error: {e}]"]

    def diff_functions(self, name: str) -> str:
        """Return a structured diff of *name* between the pre and post binaries."""
        try:
            resp = self._get("/diff_functions", {
                "address_a": name, "address_b": name,
                "program_a": self.pre, "program_b": self.post,
            })
            return _extract_text(resp)
        except Exception as e:
            return f"[diff error: {e}]"

    def list_open_programs(self) -> list[str]:
        """Return names of all programs currently loaded in the server."""
        try:
            resp = self._get("/list_open_programs")
            raw = resp if isinstance(resp, list) else resp.get("programs", [])
            return [p.get("name", str(p)) if isinstance(p, dict) else str(p) for p in raw]
        except Exception as e:
            log.warning("list_open_programs error: %s", e)
            return []

    # ── HTTP helpers ───────────────────────────────────────────────────────

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = requests.get(f"{self.base_url}{path}", params=params, timeout=60)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return r.text

    def _post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        r = requests.post(f"{self.base_url}{path}", json=body, timeout=120)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return r.text


# ── response parsing helpers ───────────────────────────────────────────────

def _extract_text(resp: Any) -> str:
    """Pull the most useful text out of a varied GhidraMCP response."""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        for key in ("decompilation", "code", "text", "result", "output", "content"):
            if key in resp:
                return str(resp[key])
        return json.dumps(resp, indent=2)
    return str(resp)


def _extract_list(resp: Any) -> list[str]:
    """Flatten a varied GhidraMCP list response to a plain list of strings."""
    if isinstance(resp, list):
        return [_item_name(x) for x in resp]
    if isinstance(resp, dict):
        for key in ("functions", "callers", "callees", "xrefs", "results", "names"):
            if key in resp:
                val = resp[key]
                if isinstance(val, list):
                    return [_item_name(x) for x in val]
        # Some endpoints return {"name": ..., ...} directly
        if "name" in resp:
            return [str(resp["name"])]
    return []


def _item_name(item: Any) -> str:
    if isinstance(item, dict):
        return item.get("name", item.get("address", str(item)))
    return str(item)
