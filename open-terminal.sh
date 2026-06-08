#!/usr/bin/env bash
# Opens a bash terminal inside the claude-sandbox container.
# Builds the image if needed, starts the container if stopped.

set -euo pipefail

IMAGE_NAME="claude-sandbox"
CONTAINER_NAME="claude-sandbox"
WORKSPACE="$(cd "$(dirname "$0")" && pwd)"

build_image() {
    echo "[*] Building image '$IMAGE_NAME'..."
    docker build \
        -t "$IMAGE_NAME" \
        "$WORKSPACE/.devcontainer"
}

# Build image if it doesn't exist
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    build_image
fi

# Handle container state
STATE=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "missing")

case "$STATE" in
    running)
        echo "[*] Attaching to running container '$CONTAINER_NAME'..."
        ;;
    exited|created|paused)
        echo "[*] Starting stopped container '$CONTAINER_NAME'..."
        docker start "$CONTAINER_NAME"
        ;;
    missing)
        echo "[*] Creating and starting container '$CONTAINER_NAME'..."
        docker run -d \
            --name "$CONTAINER_NAME" \
            --cap-add=SYS_PTRACE \
            --security-opt seccomp=unconfined \
            -v "$WORKSPACE:/workspace" \
            -v "$HOME/.claude:/root/.claude" \
            -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
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
