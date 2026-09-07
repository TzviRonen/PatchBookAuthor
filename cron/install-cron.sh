#!/usr/bin/env bash
# Install, remove or inspect the crontab entry that drives cron/run-slot.sh.
#
# Usage:
#   cron/install-cron.sh --test         every 5 min, PATCHBOOK_CRON_TEST=1 (gates 2+3 off)
#   cron/install-cron.sh --production   hourly at :20, all gates on
#   cron/install-cron.sh --uninstall    remove our entry, leave the rest alone
#   cron/install-cron.sh --show         print the current crontab
#
# The entry is bracketed by marker comments, so installing one mode replaces the
# other and never touches unrelated crontab lines.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
RUNNER="$REPO/cron/run-slot.sh"
BEGIN='# BEGIN patchbook-cve-slot'
END='# END patchbook-cve-slot'

usage() { sed -n '2,12p' "$0" >&2; exit 2; }

# Print the current crontab with our block removed. An empty crontab makes
# `crontab -l` exit 1, which is not an error here.
without_block() {
  crontab -l 2>/dev/null | awk -v b="$BEGIN" -v e="$END" '
    $0 == b { skip=1 } !skip { print } $0 == e { skip=0 }
  ' || true
}

install_block() {  # $1 = schedule, $2 = env prefix (may be empty), $3 = label
  local rest
  rest=$(without_block)
  {
    [ -n "$rest" ] && printf '%s\n' "$rest"
    printf '%s (%s) — installed %s\n' "$BEGIN" "$3" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s %s%s\n' "$1" "${2:+$2 }" "$RUNNER"
    printf '%s\n' "$END"
  } | crontab -
  echo "==> Installed the $3 schedule:" >&2
  crontab -l | sed -n "/$BEGIN/,/$END/p" >&2
}

command -v crontab >/dev/null || { echo "[!] crontab not found." >&2; exit 1; }
[ -x "$RUNNER" ] || { echo "[!] $RUNNER is missing or not executable." >&2; exit 1; }

case "${1:-}" in
  --test)
    install_block '*/5 * * * *' 'PATCHBOOK_CRON_TEST=1' 'test'
    echo "==> Firing one run now (foreground) so you can watch it:" >&2
    PATCHBOOK_CRON_TEST=1 "$RUNNER"
    ;;
  --production)
    # The minute is arbitrary — the gate reads five_hour.resets_at live, so the
    # job self-selects the right hour wherever this lands. Note cron runs in
    # host local time while resets_at is UTC; that is exactly why no wall-clock
    # constant appears anywhere in run-slot.sh.
    install_block '20 * * * *' '' 'production'
    ;;
  --uninstall)
    without_block | crontab -
    echo "==> Removed the patchbook-cve-slot entry." >&2
    ;;
  --show)
    crontab -l 2>/dev/null || echo "(no crontab for $USER)" >&2
    ;;
  *) usage ;;
esac
