FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -u 1001 synora && \
    mkdir -p /data/backups && \
    chown -R synora:synora /app /data

USER synora

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

ENV PORT=8080 \
    SYNORA_DB=/data/synora.db \
    SYNORA_BACKUP_DIR=/data/backups \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME ["/data"]

CMD ["python", "-m", "uvicorn", "app:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--log-level", "warning", \
     "--access-log"]