#!/usr/bin/env bash
# Opens a bash terminal inside this project's AI container (Claude Code + Codex).
# Builds the image if needed, starts the container if stopped.

set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="$(basename "$WORKSPACE")"
PROJECT_SLUG="$(printf '%s' "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/-\{2,\}/-/g; s/^-//; s/-$//')"
PROJECT_SLUG="${PROJECT_SLUG:-workspace}"
PROJECT_HASH="$(printf '%s' "$WORKSPACE" | sha256sum | cut -c1-12)"
IMAGE_NAME="ai-container-${PROJECT_SLUG}-${PROJECT_HASH}"
CONTAINER_NAME="$IMAGE_NAME"

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

build_image() {
    echo "[*] Building image '$IMAGE_NAME'..."
    docker build -t "$IMAGE_NAME" "$WORKSPACE/.devcontainer"
}

if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    build_image
fi

get_state() {
    local status
    if status=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null) && [[ -n "$status" ]]; then
        echo "$status"
    else
        echo "missing"
    fi
}
STATE=$(get_state)

case "$STATE" in
    running)
        echo "[*] Attaching to running container '$CONTAINER_NAME'..."
        ;;
    exited|created|paused)
        echo "[*] Starting stopped container '$CONTAINER_NAME'..."
        docker start "$CONTAINER_NAME"
        ;;
    missing)
        read -ra FREE_PORTS < <(find_free_ports 3)
        PORT_FLAGS=()
        for p in "${FREE_PORTS[@]}"; do PORT_FLAGS+=(-p "${p}:${p}"); done
        echo "[*] Creating container '$CONTAINER_NAME'${FREE_PORTS:+ (ports: ${FREE_PORTS[*]})}..."
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
            sleep infinity
        ;;
    *)
        echo "[!] Unexpected container state: $STATE. Removing and recreating..."
        docker rm -f "$CONTAINER_NAME"
        exec "$0" "$@"
        ;;
esac

echo "[*] Opening terminal in '$CONTAINER_NAME'..."
docker exec -it "$CONTAINER_NAME" bash
