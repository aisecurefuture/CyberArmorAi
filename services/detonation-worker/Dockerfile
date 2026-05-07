# Microsoft's official Playwright image. Pinned by tag so dependency
# updates flow through deliberately, not on every rebuild. The image
# already contains Chromium, Firefox, WebKit, and the OS libs they need.
#
# IMPORTANT: this container fetches and renders attacker-controlled URLs.
# It MUST be deployed in a network namespace with NO route to internal
# services or cloud metadata endpoints. The compose stack puts it on a
# dedicated `detonation` network for that reason.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Web framework only — Playwright + browsers come from the base image.
RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic

COPY services/detonation-worker/main.py ./main.py

# Run as non-root. The base image ships a `pwuser` we can use.
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8015
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8015"]
