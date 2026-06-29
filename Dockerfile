# syntax=docker/dockerfile:1

FROM python:3.12-slim

# Don't write .pyc files, flush stdout/stderr so logs show up live in `docker logs`
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source
COPY main.py .
COPY src/ ./src/

# cookies.json (and any optional log file) are written at runtime to /data,
# which is backed by a named volume so the Buff session survives restarts.
RUN mkdir -p /data

ENTRYPOINT ["python", "main.py"]
CMD ["--config", "/app/config.json", "--cookies", "/data/cookies.json"]
