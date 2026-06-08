FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Base system packages
RUN apt-get update && apt-get install -y \
    curl wget git \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ make cmake build-essential \
    sudo bash vim nano less \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 (required by Claude Code)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Python venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install ipython requests

# `cai` wrapper: runs claude with all permissions skipped (safe inside this sandbox)
RUN printf '#!/bin/bash\nexec claude --dangerously-skip-permissions "$@"\n' \
    > /usr/local/bin/cai \
    && chmod +x /usr/local/bin/cai

# Non-root user matching typical host UID 1000 so bind-mount ownership aligns
# Claude Code refuses --dangerously-skip-permissions when running as root
# Ubuntu 24.04 base already has UID 1000 ('ubuntu'); rename it to sandbox
RUN usermod -l sandbox -d /home/sandbox -m -s /bin/bash ubuntu \
    && groupmod -n sandbox ubuntu \
    && echo 'sandbox ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Claude looks for itself at ~/.local/bin/claude when running as non-root
RUN mkdir -p /home/sandbox/.local/bin \
    && ln -s "$(which claude)" /home/sandbox/.local/bin/claude \
    && chown -R sandbox:sandbox /home/sandbox/.local

# Shell config for sandbox user
RUN echo 'alias claude="claude --dangerously-skip-permissions"' >> /home/sandbox/.bashrc \
    && echo 'export PS1="\[\033[1;31m\][sandbox]\[\033[0m\] \w \$ "' >> /home/sandbox/.bashrc

USER sandbox
WORKDIR /workspace
