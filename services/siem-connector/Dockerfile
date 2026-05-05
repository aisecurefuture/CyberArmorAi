ARG PQC_BASE_IMAGE=cyberarmor-python311-pqc:local
FROM ${PQC_BASE_IMAGE}
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
