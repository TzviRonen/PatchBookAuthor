FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget git openssh-client \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ make cmake build-essential \
    sudo bash vim nano less \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Ghidra is pure Java and will not start without a JDK. Ghidra itself is not in
# this image — container.sh bind-mounts it read-only at /opt/ghidra.
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Node.js 22 (required by Claude Code and Codex)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code @openai/codex

RUN curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh \
    && mv /root/.local/bin/rtk /usr/local/bin/rtk

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install ipython requests

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
