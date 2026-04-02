FROM python:3.11-slim AS base

LABEL maintainer="CyberArmor <security@cyberarmor.ai>"
LABEL description="CyberArmor Endpoint Agent (containerized mode)"

# Security: run as non-root
RUN groupadd -r cyberarmor && useradd -r -g cyberarmor -m cyberarmor

# System deps for cryptography, watchdog, psutil
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cyberarmor

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY . .

# Config and data volumes
RUN mkdir -p /etc/cyberarmor /var/log/cyberarmor /var/lib/cyberarmor/quarantine \
    && chown -R cyberarmor:cyberarmor /etc/cyberarmor /var/log/cyberarmor /var/lib/cyberarmor

VOLUME ["/etc/cyberarmor", "/var/log/cyberarmor", "/var/lib/cyberarmor"]

# Environment
ENV CYBERARMOR_CONFIG=/etc/cyberarmor/agent.json
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

USER cyberarmor

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8020/health').raise_for_status()" || exit 1

EXPOSE 8020

ENTRYPOINT ["python", "agent.py"]
CMD ["--config", "/etc/cyberarmor/agent.json"]
