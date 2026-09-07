# `cron/` — scheduled CVE analysis + publish

An hourly cron job that spends *leftover* Claude subscription quota on the next
CVE in a work list and publishes the resulting report to the live PatchBook
site, unattended.

The pipeline's expensive stages (`identify`, `blog`) run through the `claude -p`
CLI on a subscription, not an API key. That quota refills on a rolling 5-hour
window and anything unspent at reset is lost — so the job deliberately waits
until the window is nearly over and only then burns what is left.

## The trigger rule

`cron/run-slot.sh` fires an analysis only when **all** of these hold:

1. **Quota headroom** — `five_hour.utilization <= 100 - MIN_REMAINING_PCT`
   (default: at least 20% left).
2. **Window nearly over** — `five_hour.resets_at` is within `RESET_WITHIN_MIN`
   minutes (default 60).
3. **Window not yet claimed** — the current reset time is more than
   `WINDOW_MATCH_SEC` (30 min) away from the one recorded in
   `state/last-window`. It is matched with a tolerance, not compared exactly:
   the endpoint's reported reset drifts by a second or two between calls inside
   the same window, so an exact match would never dedupe. Real windows are ~5 h
   apart, so the tolerance cannot merge two of them.
4. **Work available** — a CVE in `cves.txt` is not in `state/done.txt` and is
   under `MAX_ATTEMPTS` in `state/attempts.txt`, and no other slot holds
   `state/run.lock`.

Anything else logs a `skip:` line and exits 0. The window boundary is read live
from `./claude-usage.sh` every run — there is no hard-coded reset time, so the
job stays correct as the rolling window drifts (and regardless of the host's
local timezone, which is what cron schedules in).

The usage endpoint rate-limits (HTTP 429) if you poll it in a tight loop — not
a concern for an hourly job, but expect it while testing gates by hand.

If the quota lookup fails, returns nothing, or has no usable `.five_hour`, the
slot is **skipped**, never run anyway: the endpoint is undocumented and may
change shape without notice.

A run started with under an hour left will often outlast the reset and borrow
from the next window. That is intended — the lock plus the `last-window` claim
keep it from overlapping itself.

## Files

| Path | Role |
|---|---|
| `cves.txt` | Work list, one CVE id per line, `#` comments allowed. **Never mutated by the job.** |
| `config.env` | Knobs (see below). Every one can be overridden from the environment. |
| `run-slot.sh` | The wrapper cron invokes; all gate logic lives here. |
| `install-cron.sh` | `--test` / `--production` / `--uninstall` / `--show` crontab management. |
| `state/` | Runtime bookkeeping, gitignored (see below). |

### `state/`

- `done.txt` — completed CVEs. Delete a line to requeue that CVE.
- `failed.txt` — one line per failure: timestamp, CVE, exit code, log path.
- `attempts.txt` — `<CVE> <n>` failure counts, checked against `MAX_ATTEMPTS`.
- `last-window` — the reset time (unix epoch) of the window this job last
  claimed. A non-numeric value is ignored rather than allowed to wedge gate 3.
- `run.lock` — flock target.
- `cron.log` — every firing's decision line (gate skips, run start, verdict).
  The wrapper's own output only reaches stderr otherwise, which under cron means
  mail, which means nowhere on a box with no MTA.
- `slot-<ts>.log` — full pipeline output of each run that actually fired.

### Knobs (`config.env`)

`MIN_REMAINING_PCT` (20), `RESET_WITHIN_MIN` (60), `BACKEND` (`ghidra`),
`PUSH` (1), `MAX_ATTEMPTS` (3), `WINDOW_MATCH_SEC` (1800), and an explicit `PATH` — cron's own is minimal
and the job needs `claude`, `java`, `python3`, `git`, `jq` and `curl`.

`BACKEND=ghidra` rather than the pipeline's `ida` default because the IDA
backend needs the IDA VM (`pipeline/config.py`) reachable; switch it back when
that VM is up.

## What a firing does

`./run_and_publish.sh --backend "$BACKEND" --publish-commit "$CVE"`, tee'd to
`state/slot-<ts>.log`. That script already picks native vs docker mode, drops a
preset `ANTHROPIC_API_KEY` so the CLI uses OAuth, and chains
`publish_to_patchbook.py`. It is idempotent: `run_cve.py` caches every stage in
`data/traces/<CVE>.json`, so re-running a finished CVE replays in seconds.

On success, and when `PUSH=1`, the slot pushes the patchbook submodule to
`origin/main`, then commits and pushes the moved submodule pointer in the outer
repo. On failure it bumps `attempts.txt`, appends to `failed.txt`, and leaves
the CVE pending — but keeps the window claimed, since a failed attempt still
consumed it.

## Bringing up a fresh container

```bash
cron/bootstrap.sh           # install what is missing, start cron, install the schedule
cron/bootstrap.sh --check   # report readiness, change nothing
```

Idempotent, so re-running it is safe. It installs `jq` and `cron` if absent
(needs root or passwordless sudo), verifies the tools it cannot install
(`claude`, `java`, `ghidriff`, `git`, `curl`), checks the claude credentials and
`github.com` in `known_hosts`, starts the cron daemon, and installs the
production crontab.

**Run it after every container restart.** This image has no init supervising
`cron`, so the daemon does not come back on its own — the crontab does, which
means a restart leaves a schedule that nothing executes. (`--check` catches
exactly that state; it distinguishes a live daemon from the zombie a killed
`cron` leaves behind, since nothing reaps it here.)

## Rollout

```bash
cron/install-cron.sh --test        # */5, PATCHBOOK_CRON_TEST=1, plus one run now
cron/install-cron.sh --uninstall   # once you have seen a report reach the site
cron/install-cron.sh --production  # 20 * * * *
```

Test mode skips **only** gates 2 and 3 (timing and the window claim). The quota
floor, the lock and the done-list still apply, so a test firing is a real run
that really publishes — point `cves.txt` at an already-cached CVE first.

### Prerequisites

- An analysis backend: `pip install -r requirements.txt` for the native path
  (needs `java`), or a filled-in `.env` for the docker path.
- Non-interactive push: cron has no ssh-agent, so verify
  `git -C patchbook push --dry-run origin HEAD:main` works with a
  passphrase-less key and `github.com` in `known_hosts`.
- `claude -p` must authenticate with no TTY and no `ANTHROPIC_API_KEY` set.

## Troubleshooting

```bash
./claude-usage.sh --json | jq .five_hour   # what the gates see
PATCHBOOK_CRON_TEST=1 cron/run-slot.sh     # run one slot by hand
MIN_REMAINING_PCT=99 cron/run-slot.sh      # force the quota gate to decline
RESET_WITHIN_MIN=1   cron/run-slot.sh      # force the timing gate to decline
tail -f cron/state/slot-*.log
journalctl -u cron --since '1 hour ago'
```
