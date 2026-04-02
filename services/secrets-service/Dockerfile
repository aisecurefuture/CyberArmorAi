FROM python:3.11-slim
WORKDIR /app
COPY services/secrets-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
COPY services/secrets-service/ /app/
COPY scripts/security/run_uvicorn_tls.py /app/run_uvicorn_tls.py
EXPOSE 8013
CMD ["python", "run_uvicorn_tls.py", "main:app", "8013"]
