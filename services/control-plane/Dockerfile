ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary redis pyjwt httpx cryptography

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

COPY services/control-plane/main.py ./main.py
COPY services/control-plane/db.py ./db.py
COPY services/control-plane/models.py ./models.py
COPY scripts/security/run_uvicorn_tls.py ./run_uvicorn_tls.py

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
CMD ["python", "run_uvicorn_tls.py", "main:app", "8000"]
