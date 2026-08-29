"""Translator layer over the binary-analysis backends (Ghidra MCP / IDA MCP).

The pipeline's use of a reverse-engineering backend is narrow: an agentic
`claude -p` session that needs MCP tools, plus a couple of direct Python calls
afterwards to collect decompilation for the blog stage.  Everything backend
specific lives behind `AnalysisBackend` so the rest of the pipeline never names
Ghidra or IDA.

Two backends:

* `GhidraBackend` — wraps the existing `GhidraMCPServer` (a REST client for the
  headless Java GhidraMCP server).  One server holds *both* the pre and post
  programs and disambiguates them with a `program=` argument.
* `IdaBackend`   — drives IDA Pro on a Windows VM via `ida-pro-mcp`.  One IDA
  instance serves exactly one database, so this runs *two* instances and
  exposes them as two MCP servers (`ida_pre` / `ida_post`).  Choosing the
  binary becomes choosing the server rather than passing an argument.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from pipeline.config import (
    IDA_INSTALL_DIR,
    IDA_MCP_STARTUP_TIMEOUT,
    IDA_VM_HOST,
    IDA_VM_KEY,
    IDA_VM_USER,
    IDA_WORK_DIR,
)

log = logging.getLogger(__name__)

Which = Literal["pre", "post"]

_REPO_ROOT = Path(__file__).parent.parent
_BRIDGE_SCRIPT = _REPO_ROOT / "vendor" / "ghidra-mcp" / "bridge_mcp_ghidra.py"
_VM_AGENT = Path(__file__).parent / "vm_agent.py"
_TUNNEL_SCRIPT = _REPO_ROOT / "start_ida_tunnel.sh"

BACKENDS = ("ghidra", "ida")


class BackendError(RuntimeError):
    """Raised when a backend cannot be brought up."""


class AnalysisBackend(ABC):
    """What the pipeline needs from a reverse-engineering backend."""

    name: str

    # ── identity ──────────────────────────────────────────────────────────
    @property
    @abstractmethod
    def pre_label(self) -> str:
        """How the vulnerable build is referred to in prompts."""

    @property
    @abstractmethod
    def post_label(self) -> str:
        """How the fixed build is referred to in prompts."""

    @property
    def binary_name(self) -> str:
        """Display name of the analysed binary, for prompt headings."""
        return Path(self.post_label).name or "the target binary"

    # ── lifecycle ─────────────────────────────────────────────────────────
    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def ready(self) -> bool:
        """True once both builds are loaded and answering queries."""

    def __enter__(self) -> "AnalysisBackend":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── what the LLM sees ─────────────────────────────────────────────────
    @abstractmethod
    def mcp_config(self) -> dict:
        """The `claude -p --mcp-config` JSON payload."""

    @abstractmethod
    def allowed_tools(self) -> list[str]:
        """`--allowedTools` values that grant this backend's tools."""

    @abstractmethod
    def tool_docs(self) -> str:
        """The '## Key tools' + investigation-strategy prompt section."""

    @abstractmethod
    def closing_instruction(self) -> str:
        """The closing line telling the agent how to start investigating."""

    # ── direct analysis calls (post-verdict, for the blog stage) ──────────
    @abstractmethod
    def decompile(self, name: str, which: Which) -> str:
        """Pseudo-C for *name*, or "" if it could not be decompiled."""

    @abstractmethod
    def callers(self, name: str, which: Which) -> list[str]:
        """Names of functions calling *name*."""


# ══ Ghidra ════════════════════════════════════════════════════════════════


class GhidraBackend(AnalysisBackend):
    """Adapter over an already-running `GhidraMCPServer`.

    `run_cve.py` starts the Ghidra server in the background concurrently with
    ghidriff, so this wraps a live server rather than owning its startup.
    """

    name = "ghidra"

    def __init__(self, server):
        self._mcp = server

    @property
    def server(self):
        """The underlying `GhidraMCPServer` (for callers that still need it)."""
        return self._mcp

    @property
    def pre_label(self) -> str:
        return self._mcp.pre

    @property
    def post_label(self) -> str:
        return self._mcp.post

    def start(self) -> None:
        # Startup is owned by ghidriff_runner._start_mcp_background.
        pass

    def stop(self) -> None:
        self._mcp.stop()

    def ready(self) -> bool:
        return bool(self._mcp.pre and self._mcp.post)

    def _program(self, which: Which) -> str:
        return self._mcp.pre if which == "pre" else self._mcp.post

    def mcp_config(self) -> dict:
        import os as _os
        import sys as _sys

        if not _BRIDGE_SCRIPT.exists():
            raise BackendError(
                f"MCP bridge not found at {_BRIDGE_SCRIPT}. "
                "Clone vendor/ghidra-mcp and ensure bridge_mcp_ghidra.py is present."
            )
        # Use the venv's python so the `mcp` package is importable by the bridge.
        venv_python = str(Path(_os.path.dirname(_sys.executable)) / "python")
        return {
            "mcpServers": {
                "ghidra": {
                    "command": venv_python,
                    "args": [str(_BRIDGE_SCRIPT), "--transport", "stdio"],
                    "env": {"GHIDRA_MCP_URL": f"http://127.0.0.1:{self._mcp.port}"},
                }
            }
        }

    def allowed_tools(self) -> list[str]:
        return ["mcp__ghidra"]

    def tool_docs(self) -> str:
        return f"""\
You have live access to a Ghidra MCP server running locally (port {self._mcp.port}) with two builds loaded:
- Pre-patch (vulnerable): `{self._mcp.pre}`
- Post-patch (fixed): `{self._mcp.post}`

The server was auto-connected when the bridge started — you can immediately use Ghidra tools without calling connect_instance.

## Key tools

- `decompile_function(address=FUNC_NAME, program=PROGRAM_NAME)` — decompile pseudo-C from either binary.  Use `program="{self._mcp.pre}"` for the vulnerable version, `program="{self._mcp.post}"` for the fixed version.
- `search_functions(name_pattern=SUBSTRING, program=PROGRAM_NAME)` — find functions by name pattern.
- `get_function_callers(name=FUNC_NAME, program=PROGRAM_NAME)` — what calls this function.
- `get_function_callees(name=FUNC_NAME, program=PROGRAM_NAME)` — what this function calls.
- `list_open_programs()` — confirm which programs are loaded.

## Investigation strategy

1. Start by decompiling the #1 heuristic candidate in BOTH binaries (pre and post) to see the change.
2. Check callers to determine if this is the outermost changed function or a callee updated as a side effect.
3. If the top candidate doesn't fit the CVE, try the next candidates.
4. Use search_functions to find related functions by name pattern if needed."""

    def closing_instruction(self) -> str:
        return ("Investigate the top candidates using the Ghidra tools. Start with "
                "decompile_function on candidate #1 in both binaries, then follow the evidence.")

    def decompile(self, name: str, which: Which) -> str:
        result = self._mcp.decompile_function(name, self._program(which))
        # decompile_function returns "[decompile error: ...]" on failure.
        if result.startswith("[decompile error"):
            return ""
        return result

    def callers(self, name: str, which: Which) -> list[str]:
        return self._mcp.get_callers(name, self._program(which))


# ══ IDA ═══════════════════════════════════════════════════════════════════


class _IdaMcpClient:
    """Minimal MCP-over-HTTP (streamable) JSON-RPC client for one IDA instance."""

    def __init__(self, port: int, timeout: int = 120):
        self.port = port
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.timeout = timeout
        self._session: str | None = None
        self._next_id = 0
        self._initialized = False

    def _rpc(self, method: str, params: dict | None = None, notify: bool = False):
        payload: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if not notify:
            self._next_id += 1
            payload["id"] = self._next_id

        req = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **({"Mcp-Session-Id": self._session} if self._session else {}),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            body = resp.read().decode("utf-8", "replace")

        if notify or not body.strip():
            return None
        data = _parse_jsonrpc_body(body)
        if data is None:
            raise BackendError(f"unparseable MCP response from port {self.port}: {body[:200]}")
        if "error" in data:
            raise BackendError(f"MCP error from port {self.port}: {data['error']}")
        return data.get("result")

    def initialize(self) -> None:
        if self._initialized:
            return
        self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "cve-pipeline", "version": "1"},
        })
        self._rpc("notifications/initialized", {}, notify=True)
        self._initialized = True

    def call(self, tool: str, arguments: dict):
        self.initialize()
        result = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        return _unwrap_tool_result(result)

    def alive(self) -> bool:
        try:
            self.initialize()
            self.call("server_health", {})
            return True
        except Exception:
            return False


def _parse_jsonrpc_body(body: str) -> dict | None:
    """Parse a JSON-RPC response that may arrive as JSON or as an SSE stream."""
    body = body.strip()
    if body.startswith("{"):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    # text/event-stream: take the last `data:` payload that parses.
    found = None
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            found = json.loads(line[5:].strip())
        except json.JSONDecodeError:
            continue
    return found


def _unwrap_tool_result(result):
    """Turn an MCP tools/call result into plain Python data.

    MCP wraps returns in `content: [{type: "text", text: ...}]`; ida-pro-mcp also
    provides `structuredContent`. Prefer the structured form, else parse the text
    as JSON, else hand back the raw text.
    """
    if not isinstance(result, dict):
        return result
    if "structuredContent" in result:
        sc = result["structuredContent"]
        # Tools returning a bare list get wrapped as {"result": [...]}.
        if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
            return sc["result"]
        return sc
    chunks = [c.get("text", "") for c in result.get("content", []) if isinstance(c, dict)]
    text = "\n".join(chunks).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


class IdaBackend(AnalysisBackend):
    """Drives two IDA Pro instances on a Windows VM through `ida-pro-mcp`.

    Flow: preflight the VM -> upload both binaries to a persistent work dir ->
    reuse or launch an IDA instance per binary -> discover the port each
    instance actually bound (the plugin auto-increments on collision) -> open an
    SSH tunnel per port.
    """

    name = "ida"

    def __init__(self, pre_binary: Path, post_binary: Path, cve_id: str,
                 shutdown: bool = True):
        self.pre_binary = Path(pre_binary)
        self.post_binary = Path(post_binary)
        self.cve_id = cve_id
        # When True, stop() closes IDA on the VM after saving; when False it
        # leaves the instances running so a later run can reuse the warm
        # databases. The .i64 is saved either way.
        self.shutdown = shutdown
        self._remote: dict[str, str] = {}      # which -> remote path
        self._ports: dict[str, int] = {}       # which -> port
        self._clients: dict[str, _IdaMcpClient] = {}
        self._launched: list[int] = []

    # ── VM plumbing ───────────────────────────────────────────────────────

    def _ssh_base(self) -> list[str]:
        return [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-i", str(IDA_VM_KEY), f"{IDA_VM_USER}@{IDA_VM_HOST}",
        ]

    def _agent(self, *args: str, timeout: int = 180):
        """Run pipeline/vm_agent.py on the VM, piping its source over stdin."""
        # ssh flattens argv into a single remote command string, so quote each
        # argument here — the IDA install path contains a space.
        remote_args = " ".join(
            f'"{a}"' for a in ["--ida-dir", IDA_INSTALL_DIR, *args]
        )
        cmd = self._ssh_base() + [f"python - {remote_args}"]
        try:
            proc = subprocess.run(
                cmd,
                input=_VM_AGENT.read_text(),
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"VM command timed out: {' '.join(args)}") from e
        if proc.returncode != 0 and not proc.stdout.strip():
            raise BackendError(
                f"VM command failed ({' '.join(args)}): {proc.stderr.strip()[:400]}"
            )
        try:
            data = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as e:
            raise BackendError(
                f"unexpected VM output for {' '.join(args)}: {proc.stdout[:300]}"
            ) from e
        if isinstance(data, dict) and data.get("error"):
            raise BackendError(f"VM error ({' '.join(args)}): {data['error']}")
        return data

    def _preflight(self) -> None:
        if not Path(IDA_VM_KEY).exists():
            raise BackendError(
                f"IDA VM key not found at {IDA_VM_KEY}. Set IDA_VM_KEY or place the key there."
            )
        try:
            info = self._agent("probe", timeout=60)
        except BackendError as e:
            raise BackendError(
                f"cannot reach the IDA VM at {IDA_VM_USER}@{IDA_VM_HOST}: {e}\n"
                "Check the VM is powered on and routed (see ROUTED_HOSTS in container.sh)."
            ) from e
        if not info.get("ok"):
            raise BackendError(
                f"IDA not found on the VM at {info.get('ida')}. Set IDA_INSTALL_DIR."
            )
        log.info("IDA VM ready: %s (python %s)", info.get("ida"), info.get("python"))

    def _upload(self) -> None:
        remote_dir = f"{IDA_WORK_DIR}\\{self.cve_id.replace('/', '-')}"
        self._agent("ensure_dir", remote_dir, timeout=60)
        for which, local in (("pre", self.pre_binary), ("post", self.post_binary)):
            remote = f"{remote_dir}\\{local.name}"
            self._remote[which] = remote
            if self._remote_matches(remote, local):
                log.info("IDA VM already has %s — skipping upload", local.name)
                continue
            print(f"  [ida] uploading {local.name} ({local.stat().st_size / 1e6:.1f} MB) ...",
                  flush=True)
            scp = [
                "scp", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-i", str(IDA_VM_KEY), str(local),
                f"{IDA_VM_USER}@{IDA_VM_HOST}:{remote.replace(chr(92), '/')}",
            ]
            proc = subprocess.run(scp, capture_output=True, text=True, timeout=1800)
            if proc.returncode != 0:
                raise BackendError(f"upload of {local.name} failed: {proc.stderr.strip()[:300]}")

    def _remote_matches(self, remote: str, local: Path) -> bool:
        """True if *remote* already holds a byte-identical copy of *local*."""
        cmd = self._ssh_base() + [
            "powershell", "-NoProfile", "-Command",
            f"$f='{remote}'; if (Test-Path $f) {{ (Get-FileHash $f -Algorithm SHA256).Hash }}",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return False
        remote_hash = proc.stdout.strip().lower()
        if len(remote_hash) != 64:
            return False
        h = hashlib.sha256()
        with open(local, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest() == remote_hash

    def _find_instance(self, remote_binary: str) -> dict | None:
        """A live IDA instance already serving *remote_binary*, if any."""
        target = remote_binary.lower()
        for inst in self._agent("instances", timeout=120):
            if not inst.get("alive"):
                continue
            # `binary` is only a basename, so match on idb_path — the .i64 that
            # IDA creates next to the binary it was opened on.
            idb = str(inst.get("idb_path") or "").lower()
            if idb in (target, f"{target}.i64"):
                return inst
        return None

    def _ensure_instance(self, which: Which) -> int:
        remote = self._remote[which]
        existing = self._find_instance(remote)
        if existing:
            port = int(existing["port"])
            print(f"  [ida] reusing instance for {which} on port {port} "
                  f"(pid {existing.get('pid')})", flush=True)
            return port

        print(f"  [ida] launching IDA on {Path(remote).name} ({which}) ...", flush=True)
        pid = int(self._agent("launch", remote, timeout=300)["pid"])
        self._launched.append(pid)

        # Auto-analysis of a kernel-sized binary is slow; the instance only
        # registers itself once the MCP server is bound.
        deadline = time.time() + IDA_MCP_STARTUP_TIMEOUT
        while time.time() < deadline:
            time.sleep(10)
            inst = self._find_instance(remote)
            if inst:
                port = int(inst["port"])
                print(f"  [ida] {which} ready on port {port}", flush=True)
                return port
        raise BackendError(
            f"IDA did not come up for {Path(remote).name} within "
            f"{IDA_MCP_STARTUP_TIMEOUT}s (pid {pid} on the VM)"
        )

    def _tunnel(self, action: str, ports: list[int] | None = None) -> None:
        cmd = [str(_TUNNEL_SCRIPT), action] + [str(p) for p in (ports or [])]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise BackendError(
                f"{_TUNNEL_SCRIPT.name} {action} failed: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )
        log.info("tunnel %s: %s", action, proc.stdout.strip())

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._preflight()
        self._upload()
        for which in ("pre", "post"):
            self._ports[which] = self._ensure_instance(which)

        self._tunnel("start", sorted(set(self._ports.values())))
        for which, port in self._ports.items():
            self._clients[which] = _IdaMcpClient(port)

        for which, client in self._clients.items():
            if not client.alive():
                raise BackendError(
                    f"IDA MCP server for '{which}' on port {client.port} is not "
                    "responding through the tunnel"
                )

    def stop(self) -> None:
        # Always persist the database to its .i64, then — unless shutdown was
        # disabled — close IDA on the VM. The tunnels are torn down last, since
        # both steps go through them.
        self._save_databases()
        if self.shutdown:
            self._close_instances()
        try:
            self._tunnel("stop", sorted(set(self._ports.values())))
        except Exception as e:
            log.warning("failed to stop IDA tunnel: %s", e)

    def _save_databases(self) -> None:
        """Write each open database to its .i64 (best-effort, per instance)."""
        for which, client in self._clients.items():
            try:
                client.call("idb_save", {})
                print(f"  [ida] saved {which} database", flush=True)
            except Exception as e:
                log.warning("failed to save IDA %s database: %s", which, e)

    def _close_instances(self) -> None:
        """Save-and-exit each IDA instance via qexit.

        qexit(0) packs the database and removes the .id* working files, then the
        process terminates — so the MCP request never gets a response. The
        dropped connection is the expected success signal, not an error.
        """
        for which, client in self._clients.items():
            try:
                client.call("py_eval", {"code": "import ida_pro; ida_pro.qexit(0)"})
            except Exception:
                pass  # connection drops when IDA exits — expected
            print(f"  [ida] closed {which} instance", flush=True)

    def ready(self) -> bool:
        return len(self._clients) == 2 and all(c.alive() for c in self._clients.values())

    # ── identity ──────────────────────────────────────────────────────────

    @property
    def pre_label(self) -> str:
        return self.pre_binary.name

    @property
    def post_label(self) -> str:
        return self.post_binary.name

    # ── what the LLM sees ─────────────────────────────────────────────────

    def mcp_config(self) -> dict:
        return {
            "mcpServers": {
                f"ida_{which}": {
                    "type": "http",
                    "url": f"http://127.0.0.1:{self._ports[which]}/mcp",
                }
                for which in ("pre", "post")
            }
        }

    def allowed_tools(self) -> list[str]:
        return ["mcp__ida_pre", "mcp__ida_post"]

    def tool_docs(self) -> str:
        return f"""\
You have live access to TWO IDA Pro instances, one per build, exposed as two separate MCP servers:
- `ida_pre`  — the pre-patch (vulnerable) build: `{self.pre_label}`
- `ida_post` — the post-patch (fixed) build: `{self.post_label}`

IMPORTANT: unlike other setups, there is no `program=` argument.  You choose the build by choosing
the server: `mcp__ida_pre__decompile` reads the vulnerable binary, `mcp__ida_post__decompile` reads
the fixed one.  Every tool below exists on both servers.

## Key tools

- `decompile(addr=FUNC_NAME_OR_ADDRESS)` — Hex-Rays pseudo-C.  Accepts a function name or an address.
  Pass `include_addresses=false` to save tokens when you only need the logic.
- `lookup_funcs(queries=[FUNC_NAME, ...])` — resolve names/addresses to functions; use it to confirm
  a function exists in a build before decompiling.
- `func_query(queries=[{{"filter": "SUBSTRING*"}}])` — find functions by name glob/regex (this is the
  equivalent of a name search; `name_regex` is also supported).
- `xrefs_to(addrs=[FUNC_NAME])` — what references/calls this function.
- `callees(addrs=[FUNC_NAME])` — what this function calls.
- `server_health()` — confirm the instance is up and which database it has loaded.

## Investigation strategy

1. Start by decompiling the #1 heuristic candidate on BOTH servers (`ida_pre` and `ida_post`) and
   compare the pseudo-C to see the change.
2. Use `xrefs_to` to determine if this is the outermost changed function or a callee updated as a
   side effect.
3. If the top candidate doesn't fit the CVE, try the next candidates.
4. Use `func_query` to find related functions by name pattern if needed.

Note: names come from PDB symbols where available.  If a name resolves on one server but not the
other, the function may have been added or inlined by the patch — that itself is evidence."""

    def closing_instruction(self) -> str:
        return ("Investigate the top candidates using the IDA tools. Start with `decompile` on "
                "candidate #1 against both `ida_pre` and `ida_post`, then follow the evidence.")

    # ── direct analysis calls ─────────────────────────────────────────────

    def decompile(self, name: str, which: Which) -> str:
        try:
            res = self._clients[which].call("decompile", {"addr": name})
        except Exception as e:
            log.warning("IDA decompile(%s, %s) failed: %s", name, which, e)
            return ""
        # `decompile` returns a DecompileResult (or a list of them for batches).
        if isinstance(res, list):
            res = res[0] if res else {}
        if isinstance(res, dict):
            return res.get("code") or ""
        return str(res or "")

    def callers(self, name: str, which: Which) -> list[str]:
        try:
            res = self._clients[which].call("xrefs_to", {"addrs": [name], "limit": 50})
        except Exception as e:
            log.warning("IDA xrefs_to(%s, %s) failed: %s", name, which, e)
            return []
        out: list[str] = []
        for entry in res if isinstance(res, list) else [res]:
            if not isinstance(entry, dict):
                continue
            for xref in entry.get("xrefs") or []:
                if not isinstance(xref, dict):
                    if xref:
                        out.append(str(xref))
                    continue
                # Data references (vtables, relocations) are not callers.
                if xref.get("type") == "data":
                    continue
                # `fn` is the function containing the reference — the caller.
                # It arrives as a Function object; fall back to the raw address
                # when the site is outside any function (thunks, stubs).
                fn = xref.get("fn")
                if isinstance(fn, dict):
                    label = fn.get("name") or fn.get("addr")
                else:
                    label = fn or xref.get("addr")
                if label:
                    out.append(str(label))
        # De-duplicate while preserving order.
        return list(dict.fromkeys(out))


# ══ factory ═══════════════════════════════════════════════════════════════


def make_backend(
    name: str,
    *,
    ghidra_server=None,
    pre_binary: Path | None = None,
    post_binary: Path | None = None,
    cve_id: str = "",
    ida_shutdown: bool = True,
) -> AnalysisBackend:
    """Build the backend selected by `--backend`.

    Ghidra's server is started elsewhere (concurrently with ghidriff) and is
    passed in; IDA's is owned by the backend and comes up on `start()`.
    """
    if name == "ghidra":
        if ghidra_server is None:
            raise BackendError("the ghidra backend requires a running GhidraMCPServer")
        return GhidraBackend(ghidra_server)
    if name == "ida":
        if pre_binary is None or post_binary is None:
            raise BackendError("the ida backend requires both binary paths")
        return IdaBackend(pre_binary, post_binary, cve_id, shutdown=ida_shutdown)
    raise BackendError(f"unknown backend {name!r}; expected one of {', '.join(BACKENDS)}")
