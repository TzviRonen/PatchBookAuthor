#!/usr/bin/env bash
# One scheduled "slot": spend leftover Claude subscription quota on the next
# unfinished CVE in cron/cves.txt and publish the report to PatchBook.
#
# Meant to be invoked hourly from cron. Most firings do nothing: the job runs a
# CVE only when all of these hold (see cron/README.md):
#
#   1. >= MIN_REMAINING_PCT of the 5-hour quota is left
#   2. the 5-hour window resets within RESET_WITHIN_MIN minutes  (use it or lose it)
#   3. this window has not been claimed by an earlier firing
#   4. a CVE is still pending, and no other slot is running
#
# Anything else — including a quota lookup that fails or returns a shape we do
# not recognise — logs a reason and exits 0. Never "run anyway" on bad data.
#
# Usage:
#   cron/run-slot.sh                     # normal gated run
#   PATCHBOOK_CRON_TEST=1 cron/run-slot.sh   # skip gates 2 and 3 only
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
STATE="$REPO/cron/state"
mkdir -p "$STATE"
touch "$STATE/done.txt" "$STATE/failed.txt" "$STATE/attempts.txt"

# ── logging ───────────────────────────────────────────────────────────────────
# Unlike the interactive scripts in this repo, this one runs unattended, so
# every line carries a UTC timestamp.
# Both streams: stderr for a hand-run, and a persistent file because under cron
# stderr goes to mail — and with no MTA installed, mail means /dev/null. Without
# this, the gate decisions and the run/fail verdict leave no trace on disk; only
# run_and_publish.sh's own output lands in the per-slot log.
_say() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" | tee -a "$STATE/cron.log" >&2; }
log()  { _say "==> $*"; }
warn() { _say "[!] $*"; }
skip() { log "skip: $*"; exit 0; }

# ── gate 4a: only one slot at a time ──────────────────────────────────────────
# Re-exec under flock, which holds the lock for the lifetime of the child; the
# guard variable stops that from recursing. `-E 0` makes a lost race a quiet
# success, which is the right answer for an hourly job that will try again.
if [ -z "${PATCHBOOK_CRON_LOCKED:-}" ]; then
  command -v flock >/dev/null || { warn "flock not found; refusing to run unlocked"; exit 0; }
  exec env PATCHBOOK_CRON_LOCKED=1 flock -n -E 0 "$STATE/run.lock" "$0" "$@"
fi

# ── config ────────────────────────────────────────────────────────────────────
# shellcheck source=/dev/null
[ -f "$REPO/cron/config.env" ] && . "$REPO/cron/config.env"
: "${MIN_REMAINING_PCT:=20}"
: "${RESET_WITHIN_MIN:=60}"
: "${BACKEND:=ghidra}"
: "${PUSH:=1}"
: "${MAX_ATTEMPTS:=3}"
export PATH

TEST=${PATCHBOOK_CRON_TEST:-0}
[ "$TEST" = 1 ] && log "test mode: gates 2 (window timing) and 3 (window claim) are skipped"

for bin in jq git python3; do
  command -v "$bin" >/dev/null || { warn "$bin not on PATH ($PATH)"; exit 0; }
done

# ── gates 1-2: quota headroom and window timing ───────────────────────────────
usage_json=$("$REPO/claude-usage.sh" --json 2>/dev/null) || \
  skip "claude-usage.sh failed (exit $?) — treating as unknown quota"
[ -n "$usage_json" ] || skip "claude-usage.sh returned no output"

util=$(jq -r '.five_hour.utilization // empty' <<<"$usage_json")
resets_at=$(jq -r '.five_hour.resets_at // empty' <<<"$usage_json")
if [ -z "$util" ] || [ -z "$resets_at" ]; then
  skip "no usable .five_hour in the usage response (endpoint shape changed?)"
fi

max_util=$((100 - MIN_REMAINING_PCT))
# utilization is a float; compare in jq rather than bash.
if [ "$(jq -n --argjson u "$util" --argjson m "$max_util" '$u <= $m')" != true ]; then
  skip "quota: utilization ${util}% > ${max_util}% (want >= ${MIN_REMAINING_PCT}% left)"
fi

reset_epoch=$(date -u -d "$resets_at" +%s 2>/dev/null) || \
  skip "cannot parse resets_at '$resets_at'"
# state/last-window holds reset_epoch, matched with a tolerance rather than
# compared as a string: the endpoint's reported reset drifts by a second or two
# between calls within the *same* window (…T01:40:00.506922 one call,
# …T01:39:59.776985 the next), so both an exact match and minute-truncation miss
# it. Windows are ~5 h apart, so anything within WINDOW_MATCH_SEC is the same one.
: "${WINDOW_MATCH_SEC:=1800}"
mins_left=$(( (reset_epoch - $(date -u +%s)) / 60 ))
log "quota: ${util}% used, window resets in ${mins_left} min ($resets_at)"

if [ "$TEST" != 1 ]; then
  if [ "$mins_left" -gt "$RESET_WITHIN_MIN" ]; then
    skip "window resets in ${mins_left} min, > ${RESET_WITHIN_MIN}; too early to burn leftovers"
  fi
  # gate 3: one run per window.
  if [ -f "$STATE/last-window" ]; then
    last=$(cat "$STATE/last-window")
    # Ignore anything that is not a bare epoch (an empty or hand-edited file):
    # a stray value must not be able to wedge the job into skipping forever.
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    if [ "$last" -gt 0 ] && [ "$(( reset_epoch > last ? reset_epoch - last : last - reset_epoch ))" \
         -le "$WINDOW_MATCH_SEC" ]; then
      skip "already done this window (claimed reset $(date -u -d "@$last" '+%FT%TZ'))"
    fi
  fi
fi

# ── gate 4b: pick a CVE ───────────────────────────────────────────────────────
attempts_of() {  # $1 = cve -> failure count so far (0 if never recorded)
  awk -v c="$1" '$1 == c { n = $2 } END { print n + 0 }' "$STATE/attempts.txt"
}

CVE=""
while read -r line; do
  line=${line%%#*}
  line=$(printf '%s' "$line" | tr -d '[:space:]')
  [ -n "$line" ] || continue
  cve=$(printf '%s' "$line" | tr '[:lower:]' '[:upper:]')
  grep -qxF "$cve" "$STATE/done.txt" && continue
  n=$(attempts_of "$cve")
  if [ "$n" -ge "$MAX_ATTEMPTS" ]; then
    log "$cve: skipped, $n failed attempts >= MAX_ATTEMPTS=$MAX_ATTEMPTS"
    continue
  fi
  CVE=$cve
  break
done < "$REPO/cron/cves.txt"

[ -n "$CVE" ] || skip "no eligible CVE left in cron/cves.txt"

# ── claim the window, then run ────────────────────────────────────────────────
# Written *before* the run: a slot that starts at :20 may outlive the reset, and
# the claim is what stops the next hourly firing from double-starting it.
printf '%s\n' "$reset_epoch" > "$STATE/last-window"

ts=$(date -u '+%Y%m%dT%H%M%SZ')
logfile="$STATE/slot-$ts.log"
log "running $CVE (backend=$BACKEND, push=$PUSH) -> $logfile"

rc=0
# pipefail makes the pipeline fail when the runner does; PIPESTATUS recovers
# its own exit code from behind the tee.
"$REPO/run_and_publish.sh" --backend "$BACKEND" --publish-commit "$CVE" 2>&1 \
  | tee -a "$logfile" || rc=${PIPESTATUS[0]}

if [ "$rc" -ne 0 ]; then
  # A failed attempt still consumed the window, so last-window stays claimed.
  n=$(( $(attempts_of "$CVE") + 1 ))
  grep -v "^$CVE " "$STATE/attempts.txt" > "$STATE/attempts.tmp" || true
  printf '%s %d\n' "$CVE" "$n" >> "$STATE/attempts.tmp"
  mv "$STATE/attempts.tmp" "$STATE/attempts.txt"
  printf '%s %s exit=%d log=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$CVE" "$rc" "$logfile" \
    >> "$STATE/failed.txt"
  warn "$CVE failed (exit $rc, attempt $n/$MAX_ATTEMPTS); see $logfile"
  exit 0
fi

# ── push ──────────────────────────────────────────────────────────────────────
# publish_to_patchbook.py --commit only commits inside the submodule; taking the
# report live, and recording the moved pointer in the outer repo, happens here.
if [ "$PUSH" = 1 ]; then
  log "pushing patchbook submodule to origin/main"
  if git -C "$REPO/patchbook" push origin HEAD:main >>"$logfile" 2>&1; then
    if ! git -C "$REPO" diff --quiet -- patchbook; then
      git -C "$REPO" add patchbook
      git -C "$REPO" commit -m "Bump patchbook: $CVE report" >>"$logfile" 2>&1
      branch=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)
      git -C "$REPO" push origin "HEAD:$branch" >>"$logfile" 2>&1 \
        || warn "outer repo push failed; submodule pointer committed locally only"
    else
      log "outer repo: submodule pointer unchanged, nothing to commit"
    fi
  else
    # The report is committed in the submodule either way — recoverable by hand.
    warn "patchbook push failed; report is committed locally but not live. See $logfile"
  fi
else
  log "PUSH=0: report committed locally, not pushed"
fi

printf '%s\n' "$CVE" >> "$STATE/done.txt"
log "$CVE done"
