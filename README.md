# kernel-cve-pipeline

Automated pipeline that monitors Microsoft's Security Response Center (MSRC) for Windows kernel CVEs, downloads pre/post-patch binaries, runs binary diffing via [ghidriff](https://github.com/clearbluejar/ghidriff), identifies the patched function, and generates a technical security blog post using Claude.

## Pipeline stages

```
MSRC API (CVRF v2.0)
  │  CVE metadata — title, description, KB numbers, CVSS
  ▼
kernel_filter.py
  │  maps CVE to target binary (ntoskrnl.exe, win32k.sys, …)
  ▼
winbindex.py
  │  resolves pre-patch and post-patch PE files via winbindex + Microsoft Symbol Server
  ▼
ghidriff_runner.py
  │  runs Ghidra binary diff → ghidriff project (with PDB symbols) + markdown report
  ▼
patch_identifier.py
  │  heuristic scoring → Claude agent with Ghidra MCP decompilation → identifies
  │  the patched function, gathers pre/post decompiled code + structured analysis
  ▼
blog_generator.py
     generates a technical security blog post via Claude using decompiled code,
     structured vulnerability/fix/attack-vector fields, and the binary diff
```

## Prerequisites

- Docker + Docker Compose, **or** Python 3.12+ with Ghidra 12.1+ / Java 21
- An [Anthropic API key](https://console.anthropic.com/)

## Quick start (Docker)

```bash
# 1. Create .env
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 2. Run once
docker compose --profile once run --rm run-once

# 3. Daemon mode (polls every 24 hours)
docker compose up -d pipeline
```

## Single-CVE runner (development)

`run_cve.py` runs the full pipeline for one CVE and is the primary tool for development and investigation:

```bash
python3 run_cve.py CVE-2024-30088
python3 run_cve.py CVE-2024-30088 --skip-blog           # stop after patch identification
python3 run_cve.py CVE-2024-30088 --force                # ignore all cached stages
python3 run_cve.py CVE-2024-30088 --from-stage identify  # re-run identify + blog with cached diff
python3 run_cve.py CVE-2024-30088 --from-stage blog      # re-run blog only
python3 run_cve.py CVE-2024-30088 --update-id 2024-Jun   # skip MSRC search
python3 run_cve.py CVE-2024-30088 --disable-web          # restrict agent to backend tools only (no internet)
python3 run_cve.py CVE-2024-30088 --backend ida          # use IDA Pro on the Windows VM instead of Ghidra
python3 run_cve.py https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088
```

### Analysis backends

The identify stage drives a disassembler over MCP. `--backend` selects which one; ghidriff still
produces the binary diff either way.

| | `--backend ghidra` (default) | `--backend ida` |
|---|---|---|
| Server | headless GhidraMCP (Java), started locally | `ida-pro-mcp` inside IDA Pro 9.3 on a Windows VM |
| Decompiler | Ghidra | Hex-Rays |
| Programs | one server holds both builds (`program=` argument) | one instance per build, exposed as two MCP servers (`ida_pre` / `ida_post`) |
| Symbols | from the ghidriff project (PDB-analysed) | from IDA's own PDB download |

Everything backend-specific lives in `pipeline/analysis_backend.py` — the rest of the pipeline never
names Ghidra or IDA.

**IDA backend prerequisites.** The pipeline SSHes to the VM, uploads both binaries to `C:\ida_work\<CVE>`,
launches an IDA instance per binary, discovers the port each one bound (the plugin auto-increments from
13337), and opens an SSH tunnel per port via `scripts/start_ida_tunnel.sh`. So you need:

- IDA Pro 9.3 on the VM with [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) installed
- SSH access with the key at `IDA_VM_KEY`, and the VM routed into the container (`ROUTED_HOSTS` in `container.sh`)

By default each run **saves every database and closes IDA** on the VM when the identify stage finishes.
Pass `--no-ida-shutdown` to leave the instances running so a later run can reuse the warm databases
(the `.i64` is saved either way); uploads are skipped when the VM already holds a byte-identical copy.
To drive IDA by hand:

```bash
./scripts/start_ida_tunnel.sh start 13337 13338   # forward the MCP servers into the container
./scripts/start_ida_tunnel.sh status 13337 13338
./scripts/start_ida_tunnel.sh stop 13337 13338
```

Each stage result is cached in `data/traces/<CVE-ID>.json` so the pipeline can resume from any completed stage after a crash or forced re-run.

Output is written to `./data/`:

| Path | Contents |
|------|----------|
| `data/binaries/<CVE-ID>/` | Downloaded PE files (pre + post patch) |
| `data/diffs/` | ghidriff markdown reports, JSON diffs, and Ghidra projects (`.gzf`) |
| `data/symbols/` | Downloaded PDB symbol files |
| `data/blogs/` | Generated blog posts |
| `data/traces/<CVE-ID>.json` | Per-CVE stage cache (crash recovery) |
| `data/cache/agent_evals/` | Cached Claude/MCP agent evaluations per function |
| `data/db/pipeline.db` | SQLite state (processed CVEs, daemon mode) |

## Running outside Docker (development)

```bash
pip install -r requirements.txt

export ANTHROPIC_API_KEY=sk-ant-...
export GHIDRA_INSTALL_DIR=/opt/ghidra
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export DATA_DIR=/workspace/data

python -m pipeline.main --once
```

## Test harness

`test_pipeline.py` runs the pipeline stage-by-stage against a known CVE (CVE-2024-30088) with cached intermediate results. Expensive stages (ghidriff, ~20-40 min) are only run once; results survive crashes via `data/run_trace.json`.

```bash
python3 test_pipeline.py --stage msrc       # fetch + parse MSRC CVRF
python3 test_pipeline.py --stage winbindex  # download binaries
python3 test_pipeline.py --stage ghidriff   # run binary diff
python3 test_pipeline.py --stage identify   # identify patched function
python3 test_pipeline.py --stage all        # run all stages in order

python3 test_pipeline.py --stage ghidriff --force  # ignore cache, re-run
```

Each stage prints pass/fail with observed vs. expected values. The trace file (`data/run_trace.json`) lets you resume from any completed stage after a crash.

## Configuration

All settings are environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | *(required)* | Anthropic API key |
| `DATA_DIR` | `/data` | Root directory for all pipeline output |
| `TARGET_WINDOWS_BUILD` | `19041` | Windows build filter (`19041` = Win10 22H2, `22621` = Win11 22H2) |
| `POLL_INTERVAL_HOURS` | `24` | Daemon polling interval |
| `GHIDRA_INSTALL_DIR` | `/opt/ghidra` | Ghidra installation path |
| `IDA_VM_HOST` | `192.168.10.128` | Windows VM running IDA Pro (`--backend ida`) |
| `IDA_VM_USER` | `auto` | SSH user on the IDA VM |
| `IDA_VM_KEY` | `./auto_vm_key.pub` | SSH private key for the IDA VM |
| `IDA_WORK_DIR` | `C:\ida_work` | Persistent upload/database dir on the VM |
| `IDA_INSTALL_DIR` | `C:\Program Files\IDA Professional 9.3` | IDA install path on the VM |
| `IDA_MCP_STARTUP_TIMEOUT` | `900` | Seconds to wait for IDA auto-analysis |
| `LOG_LEVEL` | `INFO` | Logging level |

## Architecture notes

**Binary resolution** uses [winbindex](https://winbindex.m417z.com/) to map KB numbers to PE file versions, then downloads from the Microsoft Symbol Server using the PE timestamp+virtualSize as the lookup key.

**Patch identification** works in three phases:
1. Heuristic scoring ranks all changed functions by CVE keyword overlap, change size, and security patterns — no LLM calls.
2. A Claude agent evaluates the top candidates one at a time (300s timeout per call) using a [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) server for on-demand decompilation. The server opens the pre-analyzed ghidriff Ghidra project (which includes PDB symbols) so every function decompiles to named, readable pseudo-C. The agent stops at the first function with ≥75% confidence and records a structured verdict (`vulnerability_description`, `fix_description`, `attack_vector`). After the primary patch is found, remaining high-scoring candidates are evaluated for co-patches.
3. After the verdict, `_gather_mcp_context` decompiles the primary function and all co-patches (pre + post binary) while the MCP server is still running, building a rich context block for the blog stage.

By default the MCP identify agent has full internet access, which lets it consult external resources and existing writeups. Pass `--disable-web` to restrict it to the selected backend's tools only (`--allowedTools mcp__ghidra`, or `mcp__ida_pre,mcp__ida_post` under `--backend ida`), ensuring the analysis is derived solely from the binary diff and decompilation.

Agent evaluation results are cached per-function in `data/cache/agent_evals/` so re-runs don't re-evaluate already-seen functions.

**Blog generation** receives the full decompiled pseudo-C (pre-patch and post-patch) for the primary function and every co-patch, alongside the structured analysis fields from the identify stage and the raw ghidriff diff. This produces deep, code-grounded writeups that quote variable names and control-flow patterns directly from the decompilation.

## PatchBook — public blog

Finished blog posts can be published to [PatchBook](https://github.com/tzvironen/patchbook), a public Jekyll site hosted on GitHub Pages. PatchBook is a git submodule in `patchbook/`.

```bash
# publish all posts from data/blogs/ to patchbook/_posts/
python publish_to_patchbook.py

# publish a single CVE
python publish_to_patchbook.py CVE-2024-30088

# publish and commit in the submodule
python publish_to_patchbook.py --commit
```

The script strips the pipeline-generated header, extracts title/CVSS/excerpt metadata, adds Jekyll YAML frontmatter, and writes versioned filenames (`YYYY-MM-DD-cve-XXXX-slug.md`). Pushing the submodule triggers a GitHub Actions workflow that builds and deploys the site.

To preview PatchBook locally:

```bash
cd patchbook
bundle install
bundle exec jekyll serve
# → http://localhost:4000/patchbook
```

## Web UI

`web/app.py` is an internal control panel (port 3011) for running the pipeline and reviewing results. Start it with:

```bash
./scripts/start_web.sh
```

## Project layout

```
pipeline/
  msrc.py             — MSRC CVRF v2.0 API client
  winbindex.py        — binary version resolution + download
  kernel_filter.py    — CVE-to-binary classifier
  ghidriff_runner.py  — Ghidra diff runner (produces PDB-resolved project)
  ghidra_mcp.py       — GhidraMCP server lifecycle + HTTP client
  analysis_backend.py — Ghidra/IDA translator layer behind --backend
  vm_agent.py         — helper run on the Windows VM to drive IDA (piped over SSH)
  patch_identifier.py — heuristic ranker + Claude/MCP agent evaluator
  blog_generator.py   — Claude blog post generator
  database.py         — SQLite state tracking
  config.py           — environment-based configuration
  main.py             — orchestrator + CLI entry point
web/app.py            — internal pipeline control panel (Flask, port 3011)
run_cve.py            — single-CVE runner (development entry point)
test_pipeline.py      — stage-by-stage test harness
publish_to_patchbook.py — publish blog posts to PatchBook submodule
scripts/
  start_ida_tunnel.sh — SSH port-forward for the IDA MCP server(s)
  start_web.sh        — start the web UI
  start_patchbook.sh  — serve the PatchBook site locally
patchbook/            — PatchBook Jekyll site (git submodule, public)
vendor/ghidra-mcp/    — GhidraMCP server (submodule)
fixtures/             — cached MSRC API responses
data/                 — runtime output (gitignored)
```
