ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic httpx cryptography

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY services/integration-control /app

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8012
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8012"]
