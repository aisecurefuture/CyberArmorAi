FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir mitmproxy fastapi uvicorn httpx cryptography pydantic

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY services/proxy/ /app/

EXPOSE 8080 8443 8081
CMD ["mitmdump", "--mode", "regular", "--set", "block_global=false", "--set", "connection_strategy=lazy", "--set", "ssl_insecure=true", "--set", "ignore_hosts=(^|\\.)apple\\.com(:\\d+)?$|(^|\\.)icloud\\.com(:\\d+)?$|(^|\\.)mzstatic\\.com(:\\d+)?$|(^|\\.)zoom\\.us(:\\d+)?$", "-s", "transparent_proxy.py", "--listen-port", "8080"]
