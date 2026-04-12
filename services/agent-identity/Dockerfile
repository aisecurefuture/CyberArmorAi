FROM python:3.11-slim
WORKDIR /app
COPY services/agent-identity/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
COPY services/agent-identity/ /app/
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser
EXPOSE 8008
CMD ["python", "run_uvicorn_tls.py", "main:app", "8008"]
