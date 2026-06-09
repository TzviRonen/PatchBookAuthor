#!/usr/bin/env bash
# Interactive management for this project's AI container (Claude Code + Codex).
# Usage: ./container.sh [start|stop|shell|status|rebuild|logs]

set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="$(basename "$WORKSPACE")"
PROJECT_SLUG="$(printf '%s' "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/-\{2,\}/-/g; s/^-//; s/-$//')"
PROJECT_SLUG="${PROJECT_SLUG:-workspace}"
PROJECT_HASH="$(printf '%s' "$WORKSPACE" | sha256sum | cut -c1-12)"
IMAGE_NAME="ai-container-${PROJECT_SLUG}-${PROJECT_HASH}"
CONTAINER_NAME="$IMAGE_NAME"

# ── helpers ────────────────────────────────────────────────────────────────

find_free_ports() {
    local count=$1 found=()
    for p in $(seq 3000 3030); do
        if ! ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${p}$"; then
            found+=("$p")
            [[ ${#found[@]} -ge $count ]] && break
        fi
    done
    echo "${found[@]}"
}

container_state() {
    local status
    if status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null) && [[ -n "$status" ]]; then
        echo "$status"
    else
        echo "missing"
    fi
}

build_image() {
    echo "[*] Building image '$IMAGE_NAME'..."
    docker build -t "$IMAGE_NAME" "$WORKSPACE/.devcontainer"
}

ensure_running() {
    if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
        build_image
    fi
    local state
    state=$(container_state)
    case "$state" in
        running) ;;
        exited|created|paused)
            echo "[*] Starting container..."
            docker start "$CONTAINER_NAME" > /dev/null
            ;;
        missing)
            read -ra FREE_PORTS < <(find_free_ports 3)
            PORT_FLAGS=()
            for p in "${FREE_PORTS[@]}"; do PORT_FLAGS+=(-p "${p}:${p}"); done
            echo "[*] Creating container${FREE_PORTS:+ (ports: ${FREE_PORTS[*]})}..."
            docker run -d \
                --name "$CONTAINER_NAME" \
                --cap-add=SYS_PTRACE \
                --security-opt seccomp=unconfined \
                "${PORT_FLAGS[@]}" \
                -v "$WORKSPACE:/workspace" \
                -v "$HOME/.claude:/home/sandbox/.claude" \
                -v "$HOME/.claude.json:/home/sandbox/.claude.json" \
                -v "$HOME/.codex:/home/sandbox/.codex" \
                -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
                -e "OPENAI_API_KEY=${OPENAI_API_KEY:-}" \
                -w /workspace \
                "$IMAGE_NAME" \
                sleep infinity > /dev/null
            ;;
        *)
            echo "[!] Unexpected state '$state'. Removing and recreating..."
            docker rm -f "$CONTAINER_NAME" > /dev/null
            ensure_running
            ;;
    esac
}

print_status() {
    local state
    state=$(container_state)
    local image_exists="no"
    docker image inspect "$IMAGE_NAME" &>/dev/null && image_exists="yes"
    echo "  Image:     $IMAGE_NAME  (exists: $image_exists)"
    echo "  Container: $CONTAINER_NAME  (state: $state)"
}

# ── commands ───────────────────────────────────────────────────────────────

cmd_start()  { ensure_running; echo "[*] Container is running."; }

cmd_stop() {
    local state
    state=$(container_state)
    case "$state" in
        missing) echo "[*] Container does not exist." ;;
        exited)  echo "[*] Container is already stopped." ;;
        *)
            echo "[*] Stopping container..."
            docker stop "$CONTAINER_NAME" > /dev/null
            echo "[*] Stopped."
            ;;
    esac
}

cmd_shell()  { ensure_running; echo "[*] Opening terminal..."; docker exec -it "$CONTAINER_NAME" bash; }
cmd_status() { echo; print_status; echo; }

cmd_rebuild() {
    echo "[*] Removing container and image..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    docker rmi -f "$IMAGE_NAME"   2>/dev/null || true
    build_image
    echo "[*] Done. Run './container.sh start' or './container.sh shell' to use it."
}

cmd_logs() { docker logs --tail=50 -f "$CONTAINER_NAME"; }

# ── interactive menu ────────────────────────────────────────────────────────

interactive_menu() {
    while true; do
        echo
        echo "  AI Sandbox — Container Manager"
        echo "  ================================"
        print_status
        echo
        echo "  1) Open terminal (shell)"
        echo "  2) Start container"
        echo "  3) Stop container"
        echo "  4) Rebuild image"
        echo "  5) Show logs"
        echo "  q) Quit"
        echo
        read -rp "  Choice: " choice
        case "$choice" in
            1) cmd_shell ;;
            2) cmd_start ;;
            3) cmd_stop ;;
            4) cmd_rebuild ;;
            5) cmd_logs ;;
            q|Q) echo "Bye."; exit 0 ;;
            *) echo "  Unknown option." ;;
        esac
    done
}

# ── entry point ─────────────────────────────────────────────────────────────

case "${1:-}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    shell)   cmd_shell ;;
    status)  cmd_status ;;
    rebuild) cmd_rebuild ;;
    logs)    cmd_logs ;;
    "")      interactive_menu ;;
    *)
        echo "Usage: $0 [start|stop|shell|status|rebuild|logs]"
        echo "       $0          (interactive menu)"
        exit 1
        ;;
esac
