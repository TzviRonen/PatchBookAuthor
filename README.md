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
python3 run_cve.py CVE-2024-30088 --skip-blog        # stop after patch identification
python3 run_cve.py CVE-2024-30088 --force             # ignore all cached stages
python3 run_cve.py CVE-2024-30088 --from-stage blog   # re-run from a specific stage
python3 run_cve.py CVE-2024-30088 --update-id 2024-Jun  # skip MSRC search
python3 run_cve.py https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088
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
| `LOG_LEVEL` | `INFO` | Logging level |

## Architecture notes

**Binary resolution** uses [winbindex](https://winbindex.m417z.com/) to map KB numbers to PE file versions, then downloads from the Microsoft Symbol Server using the PE timestamp+virtualSize as the lookup key.

**Patch identification** works in three phases:
1. Heuristic scoring ranks all changed functions by CVE keyword overlap, change size, and security patterns — no LLM calls.
2. A Claude agent evaluates the top candidates one at a time (300s timeout per call) using a [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) server for on-demand decompilation. The server opens the pre-analyzed ghidriff Ghidra project (which includes PDB symbols) so every function decompiles to named, readable pseudo-C. The agent stops at the first function with ≥75% confidence and records a structured verdict (`vulnerability_description`, `fix_description`, `attack_vector`). After the primary patch is found, remaining high-scoring candidates are evaluated for co-patches.
3. After the verdict, `_gather_mcp_context` decompiles the primary function and all co-patches (pre + post binary) while the MCP server is still running, building a rich context block for the blog stage.

Agent evaluation results are cached per-function in `data/cache/agent_evals/` so re-runs don't re-evaluate already-seen functions.

**Blog generation** receives the full decompiled pseudo-C (pre-patch and post-patch) for the primary function and every co-patch, alongside the structured analysis fields from the identify stage and the raw ghidriff diff. This produces deep, code-grounded writeups that quote variable names and control-flow patterns directly from the decompilation.

## Project layout

```
pipeline/
  msrc.py             — MSRC CVRF v2.0 API client
  winbindex.py        — binary version resolution + download
  kernel_filter.py    — CVE-to-binary classifier
  ghidriff_runner.py  — Ghidra diff runner (produces PDB-resolved project)
  ghidra_mcp.py       — GhidraMCP server lifecycle + HTTP client
  patch_identifier.py — heuristic ranker + Claude/MCP agent evaluator
  blog_generator.py   — Claude blog post generator
  database.py         — SQLite state tracking
  config.py           — environment-based configuration
  main.py             — orchestrator + CLI entry point
run_cve.py            — single-CVE runner (development entry point)
test_pipeline.py      — stage-by-stage test harness
vendor/ghidra-mcp/    — GhidraMCP server (submodule)
fixtures/             — cached MSRC API responses
data/                 — runtime output (gitignored)
```
