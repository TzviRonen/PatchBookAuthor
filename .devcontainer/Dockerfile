FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget git \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ make cmake build-essential \
    sudo bash vim nano less \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 (required by Claude Code and Codex)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code @openai/codex

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install ipython requests

# cai: claude with all permissions skipped (safe inside this sandbox)
RUN printf '#!/bin/bash\nexec claude --dangerously-skip-permissions "$@"\n' \
    > /usr/local/bin/cai && chmod +x /usr/local/bin/cai

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

USER sandbox
WORKDIR /workspace
