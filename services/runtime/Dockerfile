FROM python:3.11-slim
WORKDIR /app
COPY services/runtime/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
COPY services/runtime/main.py ./
COPY scripts/security/run_uvicorn_tls.py ./run_uvicorn_tls.py
EXPOSE 8000
CMD ["python", "run_uvicorn_tls.py", "main:app", "8000"]
