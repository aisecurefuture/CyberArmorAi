FROM python:3.11-slim

WORKDIR /app

# System deps for tokenizers / torch CPU
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Web framework (from PyPI)
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic cryptography

# CPU-only torch – must use PyTorch's own index to get the +cpu wheel
RUN pip install --no-cache-dir "torch==2.6.0+cpu" \
    --index-url https://download.pytorch.org/whl/cpu

# HuggingFace model libraries
RUN pip install --no-cache-dir \
    transformers \
    tokenizers \
    accelerate \
    sentencepiece

COPY libs/cyberarmor-core /app/libs/cyberarmor-core
ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"

COPY services/detection/ml_models.py ./ml_models.py
COPY services/detection/main.py ./main.py

# Model cache directory (mount a volume in production for persistence)
RUN mkdir -p /tmp/cyberarmor_models
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app /tmp/cyberarmor_models
ENV TRANSFORMERS_CACHE=/tmp/cyberarmor_models
ENV HF_HOME=/tmp/cyberarmor_models
# Set TRANSFORMERS_OFFLINE=1 after initial download to block any outbound HF traffic
ENV TRANSFORMERS_OFFLINE=0

USER appuser

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
