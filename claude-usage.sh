#!/usr/bin/env bash
# Show remaining Claude Code subscription usage.
#
# Queries Anthropic's undocumented OAuth usage endpoint -- the same one the CLI
# uses to render /usage. Undocumented means the path, headers, and response
# shape can change without notice; don't build anything durable on this.
#
# Usage:
#   ./claude-usage.sh          # human-readable summary
#   ./claude-usage.sh --json   # raw JSON response

set -euo pipefail

CREDS="${CLAUDE_CREDENTIALS:-$HOME/.claude/.credentials.json}"

for bin in jq curl; do
  command -v "$bin" >/dev/null || { echo "error: $bin not found in PATH" >&2; exit 1; }
done

[[ -r "$CREDS" ]] || { echo "error: cannot read $CREDS (run 'claude' and /login first)" >&2; exit 1; }

token=$(jq -r '.claudeAiOauth.accessToken // empty' "$CREDS")
[[ -n "$token" ]] || { echo "error: no claudeAiOauth.accessToken in $CREDS" >&2; exit 1; }

# Bearer + the oauth beta flag are both required; this endpoint rejects API keys.
response=$(curl -sS --fail-with-body https://api.anthropic.com/api/oauth/usage \
  -H "Authorization: Bearer $token" \
  -H "anthropic-beta: oauth-2025-04-20")

if [[ "${1:-}" == "--json" ]]; then
  jq . <<<"$response"
  exit 0
fi

# .limits[].percent is utilization (consumed), so remaining is 100 - percent.
jq -r '
  def pretty: {session: "Session (5h)", weekly_all: "Weekly (all)",
               weekly_opus: "Weekly (Opus)", weekly_sonnet: "Weekly (Sonnet)"}[.] // .;
  def pad($w): .[0:$w] + (" " * ($w - length) // "");
  "Claude usage remaining\n",
  (.limits[] | "  \(.kind | pretty | pad(18))\(100 - .percent)%  (resets \(.resets_at // "n/a"))")
' <<<"$response"
