#!/usr/bin/env bash
# Bring a fresh container up to the point where the hourly CVE slot runs.
#
# Idempotent: every step checks first, so re-running it is safe and cheap. The
# piece that actually needs re-running after a container restart is the cron
# daemon — this image has no init supervising it, so `cron` does not come back
# on its own, while the crontab itself survives.
#
# Usage:
#   cron/bootstrap.sh              # install what is missing, start cron, install the schedule
#   cron/bootstrap.sh --check      # report readiness, change nothing
#   cron/bootstrap.sh --no-schedule # set the host up but leave the crontab alone
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

ok()   { echo "  [ok]   $*"; }
# pgrep alone is not enough: with no init to reap it, a killed cron lingers as a
# zombie that pgrep still matches, which would report a dead daemon as running.
cron_pid() {
  local p st
  for p in $(pgrep -x cron 2>/dev/null); do
    st=$(ps -o stat= -p "$p" 2>/dev/null || true)
    case "$st" in Z*|"") continue ;; *) echo "$p"; return 0 ;; esac
  done
  return 1
}
act()  { echo "  [do]   $*"; }
bad()  { echo "  [!]    $*" >&2; }

check_only=0
schedule=1
for arg in "$@"; do
  case "$arg" in
    --check)       check_only=1 ;;
    --no-schedule) schedule=0 ;;
    *) echo "usage: $0 [--check] [--no-schedule]" >&2; exit 2 ;;
  esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  sudo -n true 2>/dev/null && SUDO="sudo -n" || true
fi

fail=0

# ── 1. packages ───────────────────────────────────────────────────────────────
# jq parses the quota response; cron ships both the daemon and crontab(1).
echo "== packages =="
missing=()
command -v jq      >/dev/null || missing+=(jq)
command -v crontab >/dev/null || missing+=(cron)
if [ ${#missing[@]} -eq 0 ]; then
  ok "jq, cron present"
elif [ "$check_only" = 1 ]; then
  bad "missing: ${missing[*]}"; fail=1
elif [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
  bad "missing ${missing[*]} and no root/passwordless sudo — install them by hand"; fail=1
else
  act "apt-get install ${missing[*]}"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y "${missing[@]}"
fi

# Tools we cannot install here: the analysis backend and the CLI itself.
echo "== pipeline tools =="
for bin in claude java git curl python3; do
  command -v "$bin" >/dev/null && ok "$bin" || { bad "$bin missing"; fail=1; }
done
if "${PYTHON:-python3}" -c 'import sys,os;sys.exit(0 if os.path.exists(os.path.dirname(sys.executable)+"/ghidriff") else 1)' 2>/dev/null \
   || command -v ghidriff >/dev/null; then
  ok "ghidriff"
else
  bad "ghidriff missing — pip install -r requirements.txt (the native path needs it)"; fail=1
fi

# ── 2. credentials ────────────────────────────────────────────────────────────
echo "== auth =="
[ -r "${CLAUDE_CREDENTIALS:-$HOME/.claude/.credentials.json}" ] \
  && ok "claude credentials readable" \
  || { bad "no claude credentials — run 'claude' and /login"; fail=1; }
# ssh-keygen -F, not grep: known_hosts entries are usually hashed, so the
# hostname does not appear in the file as plain text.
if ssh-keygen -F github.com >/dev/null 2>&1; then
  ok "github.com in known_hosts"
else
  bad "github.com not in known_hosts — the unattended push will hang on the host-key prompt"
  bad "  fix: ssh-keyscan github.com >> ~/.ssh/known_hosts"
fi

# ── 3. cron daemon ────────────────────────────────────────────────────────────
# No systemd in this image, so `service`/`systemctl` are not options; the daemon
# is started directly and daemonises itself.
echo "== cron daemon =="
if pid=$(cron_pid); then
  ok "cron running (pid $pid)"
elif [ "$check_only" = 1 ]; then
  bad "cron not running"; fail=1
elif [ -x /usr/sbin/cron ]; then
  act "starting /usr/sbin/cron"
  $SUDO /usr/sbin/cron
  sleep 1
  if pid=$(cron_pid); then ok "cron running (pid $pid)"
  else bad "cron failed to start"; fail=1; fi
else
  bad "/usr/sbin/cron not found"; fail=1
fi

# ── 4. schedule ───────────────────────────────────────────────────────────────
echo "== schedule =="
if ! command -v crontab >/dev/null; then
  bad "crontab unavailable; cannot install the schedule"; fail=1
elif crontab -l 2>/dev/null | grep -q 'patchbook-cve-slot'; then
  ok "$(crontab -l | grep -A1 'BEGIN patchbook-cve-slot' | tail -n1)"
elif [ "$check_only" = 1 ] || [ "$schedule" = 0 ]; then
  bad "no patchbook-cve-slot entry (cron/install-cron.sh --production)"; [ "$check_only" = 1 ] && fail=1
else
  act "installing the production schedule"
  "$REPO/cron/install-cron.sh" --production
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "Not ready — see the [!] lines above." >&2
  exit 1
fi
echo "Ready. Next slot fires on the hour at :20; it runs only if the 5-hour quota"
echo "window is within an hour of resetting. See cron/README.md."
