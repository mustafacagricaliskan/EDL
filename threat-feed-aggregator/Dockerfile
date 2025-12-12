# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies for building packages
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install only runtime system libs (if needed, e.g., libssl)
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Ensure scripts are in PATH
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

# Copy application code
COPY . .

# Create necessary directories with correct permissions
RUN mkdir -p /app/data /app/config /app/certs && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose HTTPS port (Note: Non-root users cannot bind to ports < 1024 by default.
# We will run on 8443 inside the container and map 443 outside via Docker Compose)
EXPOSE 8443

# Run with Gunicorn
# -w 1: One worker (sufficient for IO-bound if using threads)
# --threads 4: Four threads per worker for concurrency
# -b 0.0.0.0:8443: Bind to port 8443
# --certfile & --keyfile: SSL configuration
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:8443", "--certfile=threat_feed_aggregator/certs/cert.pem", "--keyfile=threat_feed_aggregator/certs/key.pem", "--log-level", "debug", "--access-logfile", "-", "--error-logfile", "-", "threat_feed_aggregator.app:app"]