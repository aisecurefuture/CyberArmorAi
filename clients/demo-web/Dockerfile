FROM python:3.11-slim
WORKDIR /app
COPY clients/demo-web/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY clients/demo-web/main.py /app/main.py
EXPOSE 8020
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8020"]
