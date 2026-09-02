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
SSH_KEY="$HOME/.ssh/ai_container_id_ed25519"
GHIDRA_DIR="$HOME/Desktop/ghidra_12.1.2_PUBLIC"
# Host-side IPs that must stay reachable from inside the container (routed via the host).
ROUTED_HOSTS=(192.168.10.128)

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
    # Context is the repo root, not .devcontainer/, so the Dockerfile can COPY
    # requirements.txt and install the pipeline's dependencies. .dockerignore
    # keeps that context to a few MB instead of the ~2.2 GB the tree weighs.
    docker build -t "$IMAGE_NAME" -f "$WORKSPACE/.devcontainer/Dockerfile" "$WORKSPACE"
}

# Point the container at the host for any IP that lives on a network the docker
# bridge does not reach on its own (e.g. a VM host-only network).
ensure_routes() {
    [[ ${#ROUTED_HOSTS[@]} -eq 0 ]] && return 0
    local gw
    gw=$(docker exec "$CONTAINER_NAME" sh -c "ip route show default | awk '{print \$3; exit}'" 2>/dev/null || true)
    if [[ -z "$gw" ]]; then
        echo "[!] Could not determine container gateway — skipping host routes."
        return 0
    fi
    for ip in "${ROUTED_HOSTS[@]}"; do
        if docker exec "$CONTAINER_NAME" ip route replace "$ip/32" via "$gw" 2>/dev/null; then
            echo "[*] Routed $ip via host ($gw)."
        else
            echo "[!] Failed to add route to $ip (needs NET_ADMIN; try './container.sh rebuild' then start)."
        fi
    done
}

ensure_running() {
    if [[ ! -f "$SSH_KEY" ]]; then
        echo "[!] SSH key not found: $SSH_KEY"
        echo "    Git operations inside the container require this key."
        echo "    Generate it, register the public key with GitHub, then retry."
        exit 1
    fi
    if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
        build_image
    fi
    local state
    state=$(container_state)
    case "$state" in
        running) ;;
        exited|created|paused)
            echo "[*] Starting container..."
            if ! docker start "$CONTAINER_NAME" > /dev/null 2>&1; then
                echo "[!] Start failed (port conflict). Removing and recreating..."
                docker rm -f "$CONTAINER_NAME" > /dev/null
                ensure_running
            fi
            ;;
        missing)
            read -ra FREE_PORTS < <(find_free_ports 3)
            PORT_FLAGS=()
            for p in "${FREE_PORTS[@]}"; do PORT_FLAGS+=(-p "${p}:${p}"); done
            EXTRA_MOUNTS=()
            if [[ -d "$GHIDRA_DIR" ]]; then
                EXTRA_MOUNTS+=(-v "$GHIDRA_DIR:/opt/ghidra:ro")
            else
                echo "[!] Ghidra not found at $GHIDRA_DIR — skipping /opt/ghidra mount."
            fi
            echo "[*] Creating container..."
            docker run -d \
                --name "$CONTAINER_NAME" \
                --cap-add=SYS_PTRACE \
                --cap-add=NET_ADMIN \
                --add-host=host.docker.internal:host-gateway \
                --security-opt seccomp=unconfined \
                "${PORT_FLAGS[@]}" \
                -v "$WORKSPACE:/workspace" \
                -v "$HOME/.claude:/home/sandbox/.claude" \
                -v "$HOME/.claude.json:/home/sandbox/.claude.json" \
                -v "$HOME/.codex:/home/sandbox/.codex" \
                -v "$SSH_KEY:/home/sandbox/.ssh/id_ed25519:ro" \
                "${EXTRA_MOUNTS[@]}" \
                -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
                -e "OPENAI_API_KEY=${OPENAI_API_KEY:-}" \
                -e "CONTAINER_PORTS=${FREE_PORTS[*]}" \
                -w /workspace \
                "$IMAGE_NAME" \
                sleep infinity > /dev/null
            ;;
        *)
            echo "[!] Unexpected state '$state'. Removing and recreating..."
            docker rm -f "$CONTAINER_NAME" > /dev/null
            ensure_running
            return
            ;;
    esac
    ensure_routes
}

print_ports() {
    local ports
    ports=$(docker port "$CONTAINER_NAME" 2>/dev/null | awk -F'[/:]' '{print $1}' | sort -nu | tr '\n' ' ')
    [[ -n "$ports" ]] && echo "[*] Forwarded ports: $ports"
}

cmd_ports() {
    if [[ -f /.dockerenv ]]; then
        if [[ -n "${CONTAINER_PORTS:-}" ]]; then
            echo "[*] Forwarded ports: $CONTAINER_PORTS"
        else
            echo "[!] Port info unavailable (container predates this feature)."
        fi
    else
        local state ports
        state=$(container_state)
        if [[ "$state" != "running" ]]; then
            echo "[!] Container is not running (state: $state)."
            return
        fi
        ports=$(docker port "$CONTAINER_NAME" 2>/dev/null | awk -F'[/:]' '{print $1}' | sort -nu | tr '\n' ' ')
        if [[ -n "$ports" ]]; then
            echo "[*] Forwarded ports: $ports"
        else
            echo "[*] No ports forwarded."
        fi
    fi
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

cmd_start()  { ensure_running; print_ports; echo "[*] Container is running."; }

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

cmd_shell()  { ensure_running; print_ports; echo "[*] Opening terminal..."; docker exec -it "$CONTAINER_NAME" bash; }
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
        echo "  6) Show forwarded ports"
        echo "  q) Quit"
        echo
        read -rp "  Choice: " choice
        case "$choice" in
            1) cmd_shell ;;
            2) cmd_start ;;
            3) cmd_stop ;;
            4) cmd_rebuild ;;
            5) cmd_logs ;;
            6) cmd_ports ;;
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
    ports)   cmd_ports ;;
    "")      interactive_menu ;;
    *)
        echo "Usage: $0 [start|stop|shell|status|rebuild|logs|ports]"
        echo "       $0          (interactive menu)"
        exit 1
        ;;
esac
