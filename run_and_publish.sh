#!/usr/bin/env bash
# Run the CVE pipeline for one CVE and publish the resulting report to PatchBook.
#
# The pipeline needs Ghidra, a JDK and ~20 Python packages. Rather than require
# all of that on the host, this script runs the analysis wherever it can:
#
#   native  — ghidriff and java are both on PATH; run run_cve.py directly
#   docker  — otherwise, run it inside the image from ./Dockerfile, which has
#             Ghidra, JDK 21 and requirements.txt already installed
#
# The publish step always runs on the host: publish_to_patchbook.py is
# standard-library only, and DATA_DIR=/data is bound to ./data, so a blog
# written inside the container is readable outside it.
#
# Usage:
#   ./run_and_publish.sh [options] <CVE-ID | MSRC-URL>
#
# Wrapper-only flags (consumed here, not forwarded to run_cve.py):
#   --docker           force the container path even if the host could run it
#   --native           force the host path; fail if its tools are missing
#   --no-build         skip the image build step (faster; assumes it is current)
#   --no-deps          do not pip install requirements.txt when it is missing
#   --publish-commit   also `git commit` the new report in the patchbook submodule
#   --skip-publish     run the pipeline only; do not publish
#
# Everything else is forwarded verbatim to run_cve.py, e.g.:
#   ./run_and_publish.sh CVE-2026-26179 --from-stage identify
#   ./run_and_publish.sh CVE-2024-30088 --backend ghidra --publish-commit
set -euo pipefail

cd "$(dirname "$0")"
PY=${PYTHON:-python3}

publish_commit=0
skip_publish=0
no_build=0
deps_install=1                    # install requirements.txt when it is missing
mode=${PIPELINE_MODE:-auto}       # auto | native | docker
run_args=()

for arg in "$@"; do
  case "$arg" in
    --publish-commit) publish_commit=1 ;;
    --skip-publish)   skip_publish=1 ;;
    --docker)         mode=docker ;;
    --native)         mode=native ;;
    --no-build)       no_build=1 ;;
    --no-deps)        deps_install=0 ;;
    *)                run_args+=("$arg") ;;
  esac
done

if [ ${#run_args[@]} -eq 0 ]; then
  echo "usage: $0 [options] <CVE-ID | MSRC-URL>" >&2
  exit 2
fi

# The CVE id may be given bare or inside an MSRC URL; pull it out for the
# publish step (run_cve.py accepts either form itself).
cve_id=$(printf '%s\n' "${run_args[@]}" | grep -oiE 'CVE-[0-9]{4}-[0-9]+' | head -n1 || true)
if [ -z "$cve_id" ]; then
  echo "[!] Could not find a CVE id (CVE-YYYY-NNNNN) in the arguments." >&2
  exit 2
fi
cve_id=$(printf '%s' "$cve_id" | tr '[:lower:]' '[:upper:]')

# ── pick an execution mode ────────────────────────────────────────────────────

# Mirror the lookup in pipeline/ghidriff_runner.py: the binary usually sits
# beside the interpreter in a virtualenv before it is ever on PATH.
have_ghidriff() {
  local venv_bin
  venv_bin="$(dirname "$("$PY" -c 'import sys; print(sys.executable)')")/ghidriff"
  [ -x "$venv_bin" ] || command -v ghidriff >/dev/null 2>&1
}

# Java cannot be pip-installed, so it decides on its own whether the host is a
# candidate at all: Ghidra is pure Java and will not start without it.
have_java() { command -v java >/dev/null 2>&1; }

# ghidriff standing in for the whole of requirements.txt is deliberate — it is
# the console script the pipeline actually execs, and the failure that sends
# people here. If it is absent the rest almost certainly is too, and installing
# the file fixes all of it in one go.
install_python_deps() {
  echo "==> Installing pipeline dependencies into $("$PY" -c 'import sys; print(sys.prefix)')"
  if ! "$PY" -m pip install -r requirements.txt; then
    echo "[!] pip install failed." >&2
    # Ubuntu 24.04 marks its system Python externally managed (PEP 668), so a
    # bare `pip install` there refuses before it starts.
    "$PY" -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)' 2>/dev/null || \
      echo "    $PY is not a virtualenv — activate one, or add --break-system-packages." >&2
    return 1
  fi
  have_ghidriff
}

have_native() {
  have_java || return 1
  have_ghidriff && return 0
  [ "$deps_install" -eq 1 ] || return 1
  install_python_deps
}

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then docker-compose "$@"
  else return 127
  fi
}

have_docker() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && compose version >/dev/null 2>&1
}

if [ "$mode" = auto ]; then
  if have_native; then mode=native; else mode=docker; fi
fi

if [ "$mode" = native ] && ! have_native; then
  echo "[!] --native was requested but the host cannot run the pipeline:" >&2
  have_java     || echo "      java is not installed      (apt-get install openjdk-21-jdk-headless)" >&2
  have_ghidriff || echo "      requirements.txt is not installed  (drop --no-deps to install it)" >&2
  echo "    Drop --native to run it in Docker instead." >&2
  exit 1
fi

if [ "$mode" = docker ] && ! have_docker; then
  echo "[!] The host is missing the pipeline's tools, and Docker is not usable either." >&2
  command -v docker >/dev/null 2>&1 || echo "      docker is not installed or not on PATH" >&2
  echo "    Either install Docker, or provision the host:" >&2
  echo "      apt-get install -y openjdk-21-jdk-headless && pip install -r requirements.txt" >&2
  exit 1
fi

# ── run the pipeline ──────────────────────────────────────────────────────────

echo "==> Pipeline: $cve_id  (mode: $mode)"

if [ "$mode" = native ]; then
  "$PY" run_cve.py "${run_args[@]}"
else
  # compose declares `env_file: .env`, which is a hard error when absent.
  if [ ! -f .env ]; then
    echo "[!] .env is missing — compose needs it for ANTHROPIC_API_KEY." >&2
    echo "    cp .env.example .env   and fill in your key." >&2
    exit 1
  fi

  if [ "$no_build" -eq 0 ]; then
    echo "==> Building the pipeline image (cached layers make this quick)"
    compose --profile cve build cve
  fi

  # Without a TTY (CI, nohup) compose run fails unless output is detached.
  tty_flag=()
  [ -t 1 ] || tty_flag=(-T)

  compose --profile cve run --rm "${tty_flag[@]}" cve "${run_args[@]}"
fi

# ── publish ───────────────────────────────────────────────────────────────────

if [ "$skip_publish" -eq 1 ]; then
  echo "==> Skipping publish (--skip-publish)."
  exit 0
fi

echo "==> Publishing $cve_id to PatchBook"
publish_args=("$cve_id")
[ "$publish_commit" -eq 1 ] && publish_args+=("--commit")
"$PY" publish_to_patchbook.py "${publish_args[@]}"
