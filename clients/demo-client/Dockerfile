FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY demo_client.py /app/demo_client.py
RUN useradd --create-home --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app
USER appuser
CMD ["python", "/app/demo_client.py"]
