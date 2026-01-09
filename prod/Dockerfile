# Production Dockerfile for CertAutomator
# Maintenance Update: 2026-01-09
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies & security patches
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y openssl curl && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/

# Create a non-root user and switch to it
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set entrypoint to run the Flask server
# Set entrypoint to run the Gunicorn WSGI server
# -w 1: Single worker to prevent duplicate schedulers
# --threads 4: Multi-threaded for concurrency
# -b 0.0.0.0:5050: Bind to port
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5050", "app.server:app"]
EXPOSE 5050
