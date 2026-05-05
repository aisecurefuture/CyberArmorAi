ARG PQC_BASE_IMAGE=cyberarmor-python312-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic cryptography

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY agents/proxy-agent/main.py /app/main.py
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8010
CMD ["python", "run_uvicorn_tls.py", "main:app", "8010"]
