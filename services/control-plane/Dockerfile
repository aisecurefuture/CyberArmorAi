ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary redis pyjwt httpx cryptography boto3

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

# Copy every Python module in services/control-plane/ so new helpers
# (repo_collector.py, future provider clients, etc.) ship without
# needing to hand-touch this file. The .dockerignore in the repo root
# keeps __pycache__ and tests out of the image.
COPY services/control-plane/*.py ./
COPY scripts/security/run_uvicorn_tls.py ./run_uvicorn_tls.py

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
CMD ["python", "run_uvicorn_tls.py", "main:app", "8000"]
