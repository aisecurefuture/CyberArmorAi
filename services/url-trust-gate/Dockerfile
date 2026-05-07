ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    httpx \
    cryptography

# Playwright is OPTIONAL at runtime. The gate's detonation.py degrades
# cleanly when it's missing (deep-mode requests fall through with
# playwright_not_installed and the policy engine still gets the heuristic
# scores from the safe crawl).
#
# Default build skips Playwright so the image stays small and portable.
# To enable deep-mode rendering set:
#     docker build --build-arg INSTALL_PLAYWRIGHT=1 ...
# (or `INSTALL_PLAYWRIGHT=1` in your compose env / CI).
#
# We deliberately do NOT pass `--with-deps` to `playwright install`.
# `--with-deps` shells out to apt with an Ubuntu-fallback package list
# that doesn't translate to Debian (it asks for `ttf-unifont` /
# `ttf-ubuntu-font-family` which only exist on Ubuntu). For production
# deep-mode workers, install the OS libs in a separate RUN with the
# correct Debian package names, OR run detonation in a dedicated
# Playwright-published image. Per the architecture doc, detonation
# SHOULD run in an isolated egress container anyway.
ARG INSTALL_PLAYWRIGHT=0
RUN if [ "$INSTALL_PLAYWRIGHT" = "1" ]; then \
        pip install --no-cache-dir playwright==1.49.0 && \
        playwright install chromium; \
    fi

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
