# Ghidra MCP — Options, Problems & Solutions

Goal: give the Claude patch-identifier agent live tools to decompile functions on demand
and query cross-references, instead of reasoning only from the pre-packaged ghidriff diff.

---

## Context

The current `patch_identifier.py` calls `claude -p` as a one-shot subprocess.
Claude receives a single prompt containing the CVE description and one function diff,
and returns a JSON verdict. It cannot look up additional functions, follow call chains,
or check who calls what.

Giving Claude real tools would let it:
- Decompile any function by name (not just the candidates ghidriff flagged)
- Walk the call graph: "who calls this function? what does it call?"
- Find all callers of a suspect allocation/free pair
- Compare the same function across both binaries
- Search functions by name pattern

---

## Headless-capable MCP Servers (shortlist)

### 1. `bethington/ghidra-mcp` ★ Most tools, most mature, best dual-binary support

- **URL**: https://github.com/bethington/ghidra-mcp
- **Stars**: ~2,400 | **Last commit**: June 8, 2026 (v5.13.1, very active)
- **Transport**: stdio (default), Streamable HTTP, SSE
- **Backend**: Java 21 standalone JAR (`GhidraMCPHeadlessServer.jar`) + Python MCP bridge.
  Does **not** use pyghidra — runs its own Ghidra engine in a separate JVM process.
- **Headless**: Yes — dedicated `GhidraMCPHeadlessServer` path, Docker Compose included,
  env vars: `GHIDRA_MCP_PORT`, `GHIDRA_MCP_BIND_ADDRESS`, `JAVA_OPTS`
- **Tool count**: 249 total (195 in headless mode)
- **Key tools**: `decompile_function` (45s timeout), `get_function_callers`,
  `get_function_callees`, `get_function_call_graph`, `get_full_call_graph`,
  `get_function_xrefs`, `search_functions_enhanced`, `find_similar_functions_fuzzy`
- **Install**: requires Maven 3.9 + Java 21 build step; Python bridge is separate
  ```bash
  python -m tools.setup build --ghidra-path /opt/ghidra
  python -m tools.setup deploy --ghidra-path /opt/ghidra
  ```
- **Ghidra version**: 12.1 hard minimum

#### Multi-binary support (source-verified)

All loaded binaries are stored in a `ConcurrentHashMap<String, Program> openPrograms`
inside `HeadlessProgramProvider`. Every tool endpoint accepts an optional `program`
parameter — when omitted it falls back to `currentProgram`.

**Loading both binaries:**
- Startup CLI (`--file`) only accepts one binary. Start the server pointing at the
  pre-patch binary, then call `/load_program` at runtime to load the post-patch binary.
- `/switch_program` changes the global default; per-call `program=` overrides it.

**Querying per binary:**
```
# decompile same function in both builds without switching context
GET /decompile_function?address=PiSwDeviceFree&program=ntoskrnl.exe.6926
GET /decompile_function?address=PiSwDeviceFree&program=ntoskrnl.exe.7058
```

**Cross-binary comparison tools (unique to bethington):**
- `/find_similar_functions_fuzzy` — `source_program` + `target_program` params,
  threshold + limit; finds functions in the post-patch binary that match a function
  from the pre-patch binary by fuzzy structural similarity
- `/bulk_fuzzy_match` — batch version of the above across all functions
- `/diff_functions` (in `BinaryComparisonService`) — takes `progA`, `progB`, and two
  function identifiers; returns a structured diff between their decompilations

This makes `bethington/ghidra-mcp` the only option that supports genuine cross-binary
analysis in a single server session — exactly what diff-based patch analysis needs.

**Problems:**
- Two-process architecture: Java JAR server + Python bridge must both run.
  Adds a second Ghidra JVM alongside the one ghidriff/pyghidra uses — no conflict
  (separate processes) but more memory and a Maven build step in the Dockerfile.
- Script execution (`run_script_inline`) disabled by default; needs env var to enable.
- Binding outside localhost requires an auth token.

---

### 2. `mrphrazer/ghidra-headless-mcp` ★ Best pyghidra fit

- **URL**: https://github.com/mrphrazer/ghidra-headless-mcp
- **Stars**: ~90 | **Last commit**: May 20, 2026
- **Transport**: stdio (default) or TCP (`--transport tcp --port 8765`)
- **Backend**: Pure Python, uses pyghidra directly in-process — same JVM bridge
  the rest of the pipeline already uses
- **Headless**: Yes — headless is the only mode. `--fake-backend` flag for CI without Ghidra.
- **Tool count**: 212 tools across 34 feature groups
- **Key tools**: `decomp.function` (30s timeout), `decomp.ast`, `function.callers`,
  `function.callees`, `reference.to`, `reference.from`, `callgraph_paths`,
  `function.by_name`, `symbol.by_name`
- **Install**: `pip install .` with `GHIDRA_INSTALL_DIR` set — no Maven, no Java build
- **Ghidra version**: pyghidra >=3.0.2 (compatible 11.x–12.x)
- **Companion project**: `mrphrazer/agentic-malware-analysis` — full Docker +
  Claude Code pipeline, directly analogous to our use case

**Problems:**
- Project is only ~3 months old (March 2026), ~90 stars, self-described "vibe coded."
  Code quality needs review before production use; pin to a specific commit.
- Shares the pyghidra JVM with ghidriff — must run in a **separate OS process**
  (not the same Python interpreter) to avoid jpype JVM contention.
- Does not cover debugger, Version Tracking, FID, BSim, or emulator workflows.

---

### 3. `jtang613/GhidrAssistMCP`

- **URL**: https://github.com/jtang613/GhidrAssistMCP
- **Stars**: ~637 | **Last commit**: May 29, 2026
- **Transport**: SSE + Streamable HTTP only (port 8080) — **no stdio**
- **Backend**: Native Java Ghidra extension (Jetty). Headless via `analyzeHeadless`
  with `-preScript GAMCPStartServerScript.java "port=8080" "wait=true"`
- **Headless**: Partial — GUI plugin is the primary design; headless path had lifecycle
  bugs fixed as recently as May 29, 2026
- **Tool count**: ~45–53 tools
- **Key tools**: `get_code` (decompile embedded with disasm), `xrefs` (direction: to/from/both,
  depth up to 5), `get_call_graph`, `search_functions_by_name`
- **Ghidra version**: 11.4+ required, tested on 12.0

**Problems:**
- No stdio transport — `claude -p` MCP support requires HTTP; must use Anthropic SDK loop
  or an MCP proxy to connect.
- Decompilation is not a first-class dedicated tool — embedded in `get_code` alongside
  disassembly and P-code, less ergonomic for targeted calls.
- analyzeHeadless re-runs full analysis on each invocation unless project is cached.
- No Docker support documented.
- Fewest tools of the three headless options.

---

### 4. `clearbluejar/pyghidra-mcp`

- **URL**: https://github.com/clearbluejar/pyghidra-mcp  |  **PyPI**: `uvx pyghidra-mcp`
- **Transport**: stdio or streamable-http
- **Backend**: pyghidra; treats a Ghidra **project** (not a single binary) as the unit
- **Extras**: Semantic vector search via ChromaDB embeddings (~20 core tools)
- **Problems**: Beta/active churn; semantic indexing is async; fewest raw tools

---

### 5. GUI-based servers — ruled out

Require a live Ghidra GUI session (X11). Not usable in a headless container.
- `LaurieWired/GhidraMCP` — most popular/starred, HTTP bridge, ~20 tools
- `13bm/GhidraMCP` — 70 tools, Go TCP bridge
- `starsong-consulting/GhydraMCP` — multi-instance REST+MCP, 60+ tools

---

## Comparison Table

| | bethington/ghidra-mcp | mrphrazer/ghidra-headless-mcp | jtang613/GhidrAssistMCP |
|---|---|---|---|
| **Transport** | stdio / HTTP / SSE | stdio / TCP | SSE + HTTP only |
| **Backend** | Java JAR + Python bridge | pyghidra (Python-native) | Java extension (Jetty) |
| **Uses pyghidra** | No (separate JVM) | Yes | No |
| **Headless** | Yes, dedicated path | Yes, only mode | Partial |
| **Tool count** | 249 (195 headless) | 212 | ~45–53 |
| **decompile** | `decompile_function` 45s | `decomp.function` 30s | embedded in `get_code` |
| **callers/callees** | dedicated tools | `function.callers/callees` | `get_call_graph` |
| **xrefs** | `get_function_xrefs` | `reference.to/from` | `xrefs` (direction param) |
| **search by name** | `search_functions_enhanced` + fuzzy | `function.by_name` | `search_functions_by_name` |
| **Install** | Maven build + deploy | `pip install .` | Gradle or GUI install |
| **Ghidra req.** | 12.1 (hard min) | pyghidra >=3.0.2 (11.x–12.x) | 11.4+ |
| **Stars / maturity** | 2,400 / very mature | 90 / 3 months old | 637 / moderate |
| **Docker support** | Yes (Docker Compose) | Yes (designed for it) | No |
| **JVM conflict risk** | None (separate process) | Yes (same pyghidra) | None (separate process) |

---

## Integration Approaches

### A — Start MCP server concurrently with ghidriff (preferred)

ghidriff takes 20-40 min. The MCP server can load the post-patch binary in
parallel so it is ready by the time `identify_patch()` runs.

```
run_cve.py
  │
  ├─ [thread 1] Start ghidriff on (pre, post) binaries   → 20-40 min
  ├─ [thread 2] Start MCP server on post binary           → ~5-10 min warm-up
  │
  └─ both done → identify_patch() with full tool access
```

Concern: jpype (pyghidra) uses a single JVM per process. ghidriff and the MCP
server must run in **separate OS processes** to avoid JVM contention.

### B — Switch agent from `claude -p` to Anthropic SDK tool loop

Replace `subprocess.run(["claude", "-p", ...])` with a Python loop using
`anthropic.Anthropic().messages.create(tools=[...])`. Tools are defined as Python
functions that proxy to the MCP server (or directly to pyghidra). Claude issues
`tool_use` blocks; the loop executes them and feeds `tool_result` back.

This approach works with any MCP server transport (stdio or HTTP) and does not
depend on `claude` CLI MCP support.

### C — Pre-export function DB during ghidriff (no live MCP)

Ghidra is already running during ghidriff. At the end of the ghidriff step, run
a small pyghidra/GhidraScript to dump all function decompilations + full xref
tables to a SQLite/JSON file. Agent tools then do fast local lookups (~ms) with
no Ghidra process needed during identify.

Tools become pure Python:
```python
def decompile_function(name: str) -> str:   # reads from SQLite
def get_callers(name: str) -> list[str]:
def get_callees(name: str) -> list[str]:
def search_functions(pattern: str) -> list[str]:
```

**Tradeoff**: larger up-front export (ntoskrnl has ~10k functions), bigger disk
footprint, but zero latency and no process coordination needed.

---

## Recommended Implementation Order

1. **Try approach A + `mrphrazer/ghidra-headless-mcp`** (easiest install, same ecosystem):
   - `pip install` inside the venv — no Maven, no Java build
   - Spawn MCP server as a background OS subprocess (not a thread) before ghidriff starts,
     pointing at the post-patch binary; kill it after `identify_patch()` finishes
   - Use Anthropic SDK tool loop in `patch_identifier.py` (TCP transport, port 8765)

2. **If JVM conflict materialises between ghidriff and the MCP server** →
   switch to `bethington/ghidra-mcp` (separate JVM, no conflict):
   - Add Maven build step to Dockerfile
   - Start Java JAR + Python bridge as background processes before ghidriff
   - Same Anthropic SDK tool loop, just different endpoint

3. **If both live MCP approaches are too fragile** → fall back to approach C (pre-export DB):
   - Add a `export_function_db()` call at the end of `run_ghidriff()` while Ghidra is warm
   - Implement 4 tool functions backed by SQLite (zero latency, no process coordination)
   - Use Anthropic SDK tool loop in `patch_identifier.py`

---

## Key Files to Modify

| File | Change needed |
|---|---|
| `pipeline/ghidriff_runner.py` | Start MCP server before ghidriff; pass server URL back |
| `pipeline/patch_identifier.py` | Replace `_call_claude_cli` with tool-loop agent |
| `pipeline/config.py` | Add `MCP_SERVER_PORT`, `MCP_SERVER_HOST` config |
| `.devcontainer/Dockerfile` | Install `ghidra-headless-mcp` and its dependencies |
