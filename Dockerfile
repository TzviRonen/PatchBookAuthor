FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    openjdk-21-jdk-headless \
    wget \
    curl \
    unzip \
    cabextract \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra — fetch latest release URL from GitHub API, fall back to known good version
RUN GHIDRA_URL=$( \
        curl -sf "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name'].endswith('.zip') and 'PUBLIC' in a['name']))" \
        2>/dev/null \
    ) && \
    if [ -z "$GHIDRA_URL" ]; then \
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241127.zip"; \
    fi && \
    echo "Downloading Ghidra from: $GHIDRA_URL" && \
    wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /tmp/ghidra_extracted && \
    mv /tmp/ghidra_extracted/ghidra_* /opt/ghidra && \
    rm -rf /tmp/ghidra.zip /tmp/ghidra_extracted

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pipeline/ /app/pipeline/
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

VOLUME ["/data"]
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
