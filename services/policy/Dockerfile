FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    sqlalchemy \
    psycopg2-binary \
    cryptography

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY services/policy/main.py           ./main.py
COPY services/policy/db.py             ./db.py
COPY services/policy/models.py         ./models.py
COPY services/policy/policy_engine.py  ./policy_engine.py
COPY services/policy/opa_client.py     ./opa_client.py
COPY services/policy/rego_compiler.py  ./rego_compiler.py
COPY services/policy/rego/             ./rego/
COPY scripts/security/run_uvicorn_tls.py ./run_uvicorn_tls.py

EXPOSE 8001
CMD ["python", "run_uvicorn_tls.py", "main:app", "8001"]
