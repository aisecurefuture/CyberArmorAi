FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn pydantic SQLAlchemy psycopg2-binary pyotp qrcode cryptography httpx

# Shared crypto helpers (TOTP, key transport, etc.) live in libs/cyberarmor-core.
COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH:-}"

COPY services/dashboard-auth/main.py /app/main.py
COPY services/dashboard-auth/db.py /app/db.py
COPY services/dashboard-auth/models.py /app/models.py

RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8088
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]
