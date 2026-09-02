# The one image for this repo.
#
# It serves two callers with different needs, so it carries the union of both:
#
#   ./container.sh          an interactive dev container (Claude Code, Codex,
#                           a toolchain, the repo mounted at /workspace)
#   docker compose          the pipeline itself, headless
#
# They are not separable in practice: the pipeline shells out to `claude -p`
# (pipeline/patch_identifier.py, pipeline/blog_generator.py) and to `ghidriff`,
# so the "headless" image needs the Node CLI, and the dev container needs the
# JDK and every Python dependency. Two Dockerfiles meant each was missing half
# of what it needed.
#
# Ghidra is deliberately NOT baked in — it is bind-mounted at
# $GHIDRA_INSTALL_DIR, which keeps this image about a gigabyte smaller and lets
# a Ghidra upgrade happen without a rebuild.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget git openssh-client \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ make cmake build-essential \
    sudo bash vim nano less \
    unzip cabextract \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Ghidra is pure Java, and jpype1/pyghidra compile against the JDK during the
# pip install below, so the JDK has to be in place first.
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Node.js 22 — required by Claude Code and Codex, and by the pipeline, which
# invokes `claude -p` as a subprocess for the identify and blog stages.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code @openai/codex

RUN curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh \
    && mv /root/.local/bin/rtk /usr/local/bin/rtk

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install ipython requests

# The pipeline's own dependencies: ghidriff, the Anthropic SDK, the MCP client,
# pyghidra/jpype1 and the rest. Copied separately so the layer caches on
# everything but a requirements.txt change.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# codex: bypass internal approvals/sandbox inside the container
RUN CODEX_REAL="$(readlink -f "$(command -v codex)")" \
    && printf '#!/bin/bash\nexec node "%s" --dangerously-bypass-approvals-and-sandbox "$@"\n' "$CODEX_REAL" \
    > /usr/local/bin/codex && chmod +x /usr/local/bin/codex

# Non-root user (UID 1000) — Claude Code refuses --dangerously-skip-permissions as root
RUN usermod -l sandbox -d /home/sandbox -m -s /bin/bash ubuntu \
    && groupmod -n sandbox ubuntu \
    && echo 'sandbox ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN mkdir -p /home/sandbox/.local/bin \
    && ln -s "$(which claude)" /home/sandbox/.local/bin/claude \
    && chown -R sandbox:sandbox /home/sandbox/.local

RUN echo 'alias claude="claude --dangerously-skip-permissions"' >> /home/sandbox/.bashrc \
    && echo 'export PS1="\[\033[1;31m\][sandbox]\[\033[0m\] \w \$ "' >> /home/sandbox/.bashrc

RUN mkdir -p /home/sandbox/.ssh \
    && touch /home/sandbox/.ssh/known_hosts \
    && (ssh-keyscan -H github.com >> /home/sandbox/.ssh/known_hosts 2>/dev/null || true) \
    && printf 'Host github.com\n    StrictHostKeyChecking accept-new\n    IdentityFile ~/.ssh/id_ed25519\n' \
       > /home/sandbox/.ssh/config \
    && chmod 700 /home/sandbox/.ssh \
    && chmod 600 /home/sandbox/.ssh/config \
    && chmod 644 /home/sandbox/.ssh/known_hosts \
    && chown -R sandbox:sandbox /home/sandbox/.ssh

USER sandbox
WORKDIR /workspace

# No ENTRYPOINT: container.sh runs a shell, and the compose services below set
# their own. The repo is mounted rather than COPYed, so an edit takes effect
# without a rebuild.
