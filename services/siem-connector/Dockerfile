FROM python:3.11-slim
LABEL maintainer="CyberArmor <security@cyberarmor.ai>"
RUN groupadd -r cyberarmor && useradd -r -g cyberarmor -m cyberarmor
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] httpx pydantic cryptography
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
COPY services/siem-connector/ /app/
USER cyberarmor
EXPOSE 8005
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
