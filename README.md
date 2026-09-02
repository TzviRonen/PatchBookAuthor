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
  │  heuristic scoring → Claude agent with IDA/Ghidra MCP decompilation → identifies
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
python3 run_cve.py CVE-2024-30088 --backend ghidra       # use local Ghidra instead of the default IDA VM
python3 run_cve.py https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088
```

The default backend is **IDA** (see below). If the IDA VM is unavailable the run fails with an
error rather than silently falling back — pass `--backend ghidra` to analyse locally.

### Run and publish in one step

`run_and_publish.sh` runs the pipeline for a CVE and then publishes the resulting report to PatchBook.
**It provisions nothing on the host**: if Ghidra, a JDK and the Python packages are not present, it
runs the analysis inside the image built from `Dockerfile`, which already has them.

```bash
./run_and_publish.sh CVE-2026-26179 --from-stage identify        # run + publish
./run_and_publish.sh CVE-2024-30088 --backend ghidra --publish-commit  # also commit in patchbook/
./run_and_publish.sh CVE-2024-30088 --skip-publish               # pipeline only
```

It picks where to run by itself:

| | when | how |
|---|---|---|
| **native** | `ghidriff` and `java` are both available | `run_cve.py` directly |
| **docker** | otherwise | `docker compose --profile cve run --rm cve …` |

The `cve` compose service mounts the working tree over `/app`, so `run_cve.py` — which the image does
not `COPY` — and any local edit are used without a rebuild. `DATA_DIR=/data` is bound to `./data`, so
the blog written inside the container is published from the host afterwards;
`publish_to_patchbook.py` is standard-library only and needs none of the pipeline's dependencies.

Wrapper-only flags, consumed here and not forwarded: `--docker` / `--native` force a mode,
`--no-build` skips the image build, `--publish-commit` commits in the submodule, `--skip-publish`
runs the pipeline only. Everything else goes to `run_cve.py` verbatim. The CVE id is picked out of
the arguments (bare id or MSRC URL) for the publish step.

Running in Docker needs `.env` (compose declares `env_file: .env`) — copy `.env.example` and fill in
`ANTHROPIC_API_KEY`. If neither path is available the script says which tools are missing and how to
install them, rather than failing inside the pipeline with `No such file or directory: 'ghidriff'`.

### The development container

`container.sh` builds `.devcontainer/Dockerfile`, which now carries JDK 21 and everything in
`requirements.txt`, so `run_cve.py` runs natively inside it and `run_and_publish.sh` takes the
native path. Ghidra itself is **not** baked in — it is bind-mounted at `/opt/ghidra`, and
`GHIDRA_INSTALL_DIR` points there.

The image builds with the **repo root** as its context, not `.devcontainer/`, so the Dockerfile can
`COPY requirements.txt`. `.dockerignore` keeps that context at a few MB rather than the ~2.2 GB the
tree weighs — without it every build would ship `data/` and `patchbook/` to the daemon.

### Analysis backends

The identify stage drives a disassembler over MCP. `--backend` selects which one; ghidriff still
produces the binary diff either way.

| | `--backend ida` (default) | `--backend ghidra` |
|---|---|---|
| Server | `ida-pro-mcp` inside IDA Pro 9.3 on a Windows VM | headless GhidraMCP (Java), started locally |
| Decompiler | Hex-Rays | Ghidra |
| Programs | one instance per build, exposed as two MCP servers (`ida_pre` / `ida_post`) | one server holds both builds (`program=` argument) |
| Symbols | from IDA's own PDB download | from the ghidriff project (PDB-analysed) |

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
2. A Claude agent evaluates the top candidates one at a time (300s timeout per call) using the selected backend's MCP server for on-demand decompilation (Hex-Rays under the default IDA backend, or a GhidraMCP server opening the pre-analyzed ghidriff project under `--backend ghidra`). Either way every function decompiles to named, readable pseudo-C from PDB symbols. The agent stops at the first function with ≥75% confidence and records a structured verdict (`vulnerability_description`, `fix_description`, `attack_vector`). After the primary patch is found, remaining high-scoring candidates are evaluated for co-patches.
3. After the verdict, `_gather_mcp_context` decompiles the primary function and all co-patches (pre + post binary) while the MCP server is still running, building a rich context block for the blog stage.

By default the MCP identify agent has internet access (`WebSearch`/`WebFetch`), which lets it consult external resources. Pass `--disable-web` to restrict it to the selected backend's tools only (`mcp__ida_pre,mcp__ida_post`, or `mcp__ghidra` under `--backend ghidra`), so the analysis derives solely from the binary diff and decompilation. In **both** modes the agent is denied local filesystem/shell tools (`Read`, `Grep`, `Bash`, …) so it cannot read the repo's own prior posts or cached verdicts and launder them back in as fresh analysis — its only inputs are MCP decompilation, the inline diff, and (unless `--disable-web`) web search. The same denial applies to the blog agent.

Agent evaluation results are cached per-function in `data/cache/agent_evals/` so re-runs don't re-evaluate already-seen functions.

**Blog generation** receives the full decompiled pseudo-C (pre-patch and post-patch) for the primary function and every co-patch, alongside the structured analysis fields from the identify stage and the raw ghidriff diff. This produces deep, code-grounded writeups that quote variable names and control-flow patterns directly from the decompilation. Every post follows a fixed skeleton (`TL;DR`, `Background`, `Root Cause`, `The Patch`, `Exploitability`) with a title of the form `CVE-YYYY-NNNNN: <bug class in component>`, and a deterministic metadata box (affected binary + version transition, CVE, CVSS, class, patch KB) is inserted directly under the title. The model also emits a machine-readable `<!--meta-->` block carrying the title and excerpt so publishing does not have to scrape them.

## PatchBook — public blog

Finished blog posts can be published to [PatchBook](https://github.com/TzviRonen/PatchBook), a public Jekyll site hosted on GitHub Pages. PatchBook is a git submodule in `patchbook/`.

```bash
# publish all reports from data/blogs/ to patchbook/_reports/
python publish_to_patchbook.py

# publish a single CVE
python publish_to_patchbook.py CVE-2024-30088

# publish and commit in the submodule
python publish_to_patchbook.py --commit
```

The script strips the pipeline-generated header and the `<!--meta-->` block, reads the title/excerpt from that block (falling back to scraping the body for older posts), extracts the CVSS, adds Jekyll YAML frontmatter, and writes dated filenames (`YYYY-MM-DD-cve-XXXX-slug.md`). When a CVE has several generations in `data/blogs/`, the **newest** one is published, so regenerating a post and re-publishing supersedes the previous version. Pushing the submodule triggers a GitHub Actions workflow that builds and deploys the site.

It also carries a post's `editors:` frontmatter forward (`_existing_block`). Those are credits readers add to themselves in the pull request that corrects a post, so re-publishing a CVE must not wipe them.

### Reader feedback

PatchBook takes two kinds of feedback on these AI-generated posts, deliberately kept apart:

- **Votes** (`valid` / `AI-slop`) go to a Cloudflare Worker + D1 database, not this repo. They appear instantly, require a GitHub login, and are capped at one per account per post.
- **Corrections** go through GitHub pull requests and appear only once merged.

See `patchbook/ARCHITECTURE.md` for why, and `patchbook/DEVELOPMENT.md` for how to run it.

To preview PatchBook locally, with the vote backend:

```bash
cd patchbook
./scripts/start_dev.sh          # site on :3004, vote API on :3003
```

Site only, using the production renderer:

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
