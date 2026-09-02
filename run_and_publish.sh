#!/usr/bin/env bash
# Run the CVE pipeline for one CVE and publish the resulting blog post to PatchBook.
#
# This is a thin wrapper around the two development entry points:
#   1. run_cve.py            — full analysis pipeline (identify + blog)
#   2. publish_to_patchbook.py — copy the newest blog post into patchbook/_reports/
#
# Usage:
#   ./run_and_publish.sh [run_cve.py options] <CVE-ID | MSRC-URL>
#
# Wrapper-only flags (consumed here, not forwarded to run_cve.py):
#   --publish-commit   also `git commit` the new post inside the patchbook submodule
#   --skip-publish     run the pipeline only; do not publish
#
# Everything else is passed straight through to run_cve.py, e.g.:
#   ./run_and_publish.sh CVE-2026-26179 --from-stage identify --backend ida
#   ./run_and_publish.sh CVE-2024-30088 --backend ghidra --publish-commit
set -euo pipefail

cd "$(dirname "$0")"
PY=${PYTHON:-python3}

publish_commit=0
skip_publish=0
run_args=()

# Split our own flags out of the argument list; forward the rest verbatim.
for arg in "$@"; do
  case "$arg" in
    --publish-commit) publish_commit=1 ;;
    --skip-publish)   skip_publish=1 ;;
    *)                run_args+=("$arg") ;;
  esac
done

if [ ${#run_args[@]} -eq 0 ]; then
  echo "usage: $0 [run_cve.py options] <CVE-ID | MSRC-URL>" >&2
  exit 2
fi

# The CVE id may be given bare or embedded in an MSRC URL; pull it out for the
# publish step (run_cve.py accepts either form itself).
cve_id=$(printf '%s\n' "${run_args[@]}" | grep -oiE 'CVE-[0-9]{4}-[0-9]+' | head -n1 || true)
if [ -z "$cve_id" ]; then
  echo "[!] Could not find a CVE id (CVE-YYYY-NNNNN) in the arguments." >&2
  exit 2
fi
cve_id=$(printf '%s' "$cve_id" | tr '[:lower:]' '[:upper:]')

echo "==> Pipeline: $cve_id"
"$PY" run_cve.py "${run_args[@]}"

if [ "$skip_publish" -eq 1 ]; then
  echo "==> Skipping publish (--skip-publish)."
  exit 0
fi

echo "==> Publishing $cve_id to PatchBook"
publish_args=("$cve_id")
[ "$publish_commit" -eq 1 ] && publish_args+=("--commit")
"$PY" publish_to_patchbook.py "${publish_args[@]}"
