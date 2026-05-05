ARG PYTHON_IMAGE=python:3.11-slim

FROM ${PYTHON_IMAGE} AS oqs-builder

COPY scripts/docker/install_liboqs_runtime.sh /tmp/install_liboqs_runtime.sh
RUN bash /tmp/install_liboqs_runtime.sh && rm -f /tmp/install_liboqs_runtime.sh

FROM ${PYTHON_IMAGE}

COPY --from=oqs-builder /usr/local /usr/local

RUN ldconfig
