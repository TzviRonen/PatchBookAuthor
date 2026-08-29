#!/usr/bin/env bash
# Forward the IDA Pro MCP server(s) (loopback-only on the Windows VM) to this container.
#
# Usage:
#   ./scripts/start_ida_tunnel.sh [start|stop|status] [PORT ...]
#
# With no ports, defaults to $IDA_MCP_PORT (13337). The IDA plugin auto-increments
# its port when one is taken, so a pre/post pair typically lands on 13337 + 13338:
#   ./scripts/start_ida_tunnel.sh start 13337 13338
set -euo pipefail

# Repo root is one level up from this script (scripts/).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VM_HOST=${IDA_VM_HOST:-192.168.10.128}
VM_USER=${IDA_VM_USER:-auto}
VM_KEY=${IDA_VM_KEY:-"$REPO_ROOT/auto_vm_key.pub"}
DEFAULT_PORT=${IDA_MCP_PORT:-13337}

action=${1:-start}
shift || true
ports=("$@")
[ ${#ports[@]} -eq 0 ] && ports=("$DEFAULT_PORT")

pidfile_for() { echo "/tmp/ida_mcp_tunnel_$1.pid"; }

# A forwarded port is only really up if the ssh process is alive *and* the local
# end accepts connections. `kill -0` alone is not enough: when this script exits,
# its backgrounded ssh is reparented, and if the container's PID 1 does not reap
# children the ssh lingers as a zombie that `kill -0` still reports as alive.
port_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && exec 3>&- && return 0
  return 1
}

proc_alive() {
  local pid=$1 state
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
  state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || echo "")
  [ "$state" != "Z" ]
}

is_running() {
  local pf pid
  pf=$(pidfile_for "$1")
  [ -f "$pf" ] || return 1
  pid=$(cat "$pf")
  proc_alive "$pid" && port_open "$1"
}

start_one() {
  local port=$1 pf
  pf=$(pidfile_for "$port")
  if is_running "$port"; then
    echo "port $port: already running (pid $(cat "$pf"))"
    return 0
  fi
  # Stale pidfile (zombie ssh, or a forward that died): clean up first.
  [ -f "$pf" ] && { kill "$(cat "$pf")" 2>/dev/null || true; rm -f "$pf"; }
  # Detach the child's stdin/stdout/stderr from any inherited fds. `ssh -N` runs
  # forever, so if it kept the script's stdout/stderr open, a caller reading this
  # script's output via a pipe (e.g. Python subprocess.run capture_output) would
  # block until EOF — which never comes — instead of returning when we exit.
  ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -o BatchMode=yes \
      -i "$VM_KEY" -N -L "${port}:127.0.0.1:${port}" "${VM_USER}@${VM_HOST}" \
      </dev/null >/dev/null 2>&1 &
  echo $! > "$pf"
  sleep 2
  if is_running "$port"; then
    echo "port $port: up (127.0.0.1:${port} -> ${VM_HOST}:${port}, pid $(cat "$pf"))"
  else
    rm -f "$pf"
    echo "port $port: FAILED to establish tunnel" >&2
    return 1
  fi
}

stop_one() {
  local port=$1 pf pid
  pf=$(pidfile_for "$port")
  if [ -f "$pf" ]; then
    pid=$(cat "$pf")
    # Kill unconditionally when a pid is recorded — is_running() is false for a
    # zombie or a half-dead forward, but the process may still need reaping.
    kill "$pid" 2>/dev/null || true
    rm -f "$pf"
    echo "port $port: stopped"
  else
    echo "port $port: not running"
  fi
}

rc=0
for port in "${ports[@]}"; do
  case "$action" in
    start)  start_one "$port" || rc=1 ;;
    stop)   stop_one "$port" ;;
    status) is_running "$port" && echo "port $port: running (pid $(cat "$(pidfile_for "$port")"))" \
                              || echo "port $port: not running" ;;
    *)      echo "usage: $0 [start|stop|status] [PORT ...]" >&2; exit 2 ;;
  esac
done
exit $rc
