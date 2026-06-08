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
  │  runs Ghidra binary diff → markdown report with per-function diffs
  ▼
patch_identifier.py
  │  heuristic scoring → Claude agent loop → identifies the patched function
  ▼
blog_generator.py
     generates a kernel-developer blog post via Claude (claude-opus-4-8)
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

Output is written to `./data/`:

| Path | Contents |
|------|----------|
| `data/binaries/<CVE-ID>/` | Downloaded PE files |
| `data/diffs/` | ghidriff markdown reports |
| `data/blogs/` | Generated blog posts |
| `data/db/pipeline.db` | SQLite state (processed CVEs) |

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

**Patch identification** works in two phases:
1. Heuristic scoring ranks all changed functions by CVE keyword overlap, change size, and security patterns — no LLM calls.
2. A Claude agent evaluates the top candidates one at a time, stopping at the first function with ≥75% confidence. It uses tool calls to fetch caller context on demand.

**Blog generation** sends only the identified function's diff (not the full noisy report) to Claude, producing a focused technical writeup.

## Project layout

```
pipeline/
  msrc.py             — MSRC CVRF v2.0 API client
  winbindex.py        — binary version resolution + download
  kernel_filter.py    — CVE-to-binary classifier
  ghidriff_runner.py  — Ghidra diff runner
  patch_identifier.py — heuristic ranker + Claude agent evaluator
  blog_generator.py   — Claude blog post generator
  database.py         — SQLite state tracking
  config.py           — environment-based configuration
  main.py             — orchestrator + CLI entry point
test_pipeline.py      — stage-by-stage test harness
fixtures/             — cached MSRC API responses
data/                 — runtime output (gitignored)
```
