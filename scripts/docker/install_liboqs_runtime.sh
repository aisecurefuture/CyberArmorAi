#!/usr/bin/env bash
set -euo pipefail

CYBERARMOR_ENABLE_NATIVE_PQC="${CYBERARMOR_ENABLE_NATIVE_PQC:-1}"
LIBOQS_VERSION="${LIBOQS_VERSION:-0.12.0}"
# Keep the Python binding aligned with the native liboqs version unless the
# caller explicitly overrides it. A mismatch can build successfully but fail at
# import time with missing symbols.
LIBOQS_PYTHON_REF="${LIBOQS_PYTHON_REF:-${LIBOQS_VERSION}}"

if [[ "${CYBERARMOR_ENABLE_NATIVE_PQC}" != "1" && "${CYBERARMOR_ENABLE_NATIVE_PQC}" != "true" ]]; then
  echo "[install_liboqs_runtime] native PQC disabled; skipping liboqs install"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  cmake \
  git \
  libssl-dev \
  ninja-build \
  pkg-config \
  python3-dev

git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build \
  -GNinja \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build /tmp/liboqs/build
cmake --install /tmp/liboqs/build
rm -rf /tmp/liboqs

python -m pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PYTHON_REF}"

ldconfig

python - <<'PY'
import json
import oqs

report = {
    "oqs_python_import": True,
    "ml_kem_1024": "ML-KEM-1024" in oqs.get_enabled_kem_mechanisms(),
    "ml_dsa_87": "ML-DSA-87" in oqs.get_enabled_sig_mechanisms(),
}
print(json.dumps(report))
PY

apt-get purge -y --auto-remove \
  build-essential \
  cmake \
  git \
  libssl-dev \
  ninja-build \
  pkg-config \
  python3-dev
rm -rf /var/lib/apt/lists/*
