#!/usr/bin/env bash
set -euo pipefail

MODELS_DIR="${TRANSFORMERS_CACHE:-${HF_HOME:-/tmp/cyberarmor_models}}"

mkdir -p "${MODELS_DIR}"
chown -R appuser:appuser "${MODELS_DIR}"

exec su -s /bin/sh appuser -c 'exec uvicorn main:app --host 0.0.0.0 --port 8002'
