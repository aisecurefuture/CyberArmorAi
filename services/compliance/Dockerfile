FROM python:3.11-slim
LABEL maintainer="CyberArmor <security@cyberarmor.ai>"
RUN groupadd -r cyberarmor && useradd -r -g cyberarmor -m cyberarmor
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic sqlalchemy psycopg2-binary cryptography
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
COPY services/compliance/ /app/
USER cyberarmor
EXPOSE 8006
CMD ["uvicorn", "main_persisted:app", "--host", "0.0.0.0", "--port", "8006"]
