#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CYBERARMOR_ENABLE_NATIVE_PQC="${CYBERARMOR_ENABLE_NATIVE_PQC:-1}"

if [[ "${CYBERARMOR_ENABLE_NATIVE_PQC}" != "1" && "${CYBERARMOR_ENABLE_NATIVE_PQC}" != "true" ]]; then
  echo "[build_pqc_base_images] native PQC disabled; skipping base image builds"
  exit 0
fi

cd "${ROOT_DIR}"

docker build \
  -f docker/pqc-base/Dockerfile \
  --build-arg PYTHON_IMAGE=python:3.11-slim \
  -t cyberarmor-python311-pqc:local \
  .

docker build \
  -f docker/pqc-base/Dockerfile \
  --build-arg PYTHON_IMAGE=python:3.12-slim \
  -t cyberarmor-python312-pqc:local \
  .
