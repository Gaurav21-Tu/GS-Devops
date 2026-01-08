# Dockerfile
FROM python:3.11-slim

# Allow docker build args to tune user if desired
ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY image/ ./image/

EXPOSE 8888
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8888", "--proxy-headers"]