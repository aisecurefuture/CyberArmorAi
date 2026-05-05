ARG PQC_BASE_IMAGE=cyberarmor-python312-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic msal boto3 cryptography

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY services/identity/ /app/

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8004
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]
