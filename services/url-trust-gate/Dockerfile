ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    httpx \
    cryptography

# Playwright is optional at runtime — the gate degrades cleanly when it's
# missing. Install it here so deep-mode is available out of the box.
# To trim the image, remove this RUN and skip browser install; deep-mode
# requests will fall through with playwright_not_installed.
RUN pip install --no-cache-dir playwright==1.49.0 && \
    playwright install --with-deps chromium

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

COPY services/url-trust-gate/main.py          ./main.py
COPY services/url-trust-gate/canonicalize.py  ./canonicalize.py
COPY services/url-trust-gate/reputation.py    ./reputation.py
COPY services/url-trust-gate/crawler.py       ./crawler.py
COPY services/url-trust-gate/detonation.py    ./detonation.py
COPY services/url-trust-gate/extractors.py    ./extractors.py
COPY services/url-trust-gate/evidence.py      ./evidence.py
COPY services/url-trust-gate/feeds.py         ./feeds.py
COPY services/url-trust-gate/metrics.py       ./metrics.py
COPY services/url-trust-gate/tenant_lists.py  ./tenant_lists.py
COPY scripts/security/run_uvicorn_tls.py      ./run_uvicorn_tls.py

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

# IMPORTANT: this service initiates outbound requests to attacker-controlled
# URLs. In production it MUST run in a dedicated network namespace with NO
# route to internal services or metadata endpoints. The Python-level SSRF
# checks in crawler.py are belt-and-braces; the network namespace is the
# real boundary.
EXPOSE 8014
CMD ["python", "run_uvicorn_tls.py", "main:app", "8014"]
