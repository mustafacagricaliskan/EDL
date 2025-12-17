# Use official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=8080

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# --- OpenShift Compatibility Fixes ---
# 1. Create directory structure to ensure permissions can be set
RUN mkdir -p /app/threat_feed_aggregator/data

# 2. Grant permissions to Group 0 (root group)
# OpenShift runs containers with a random UID but always part of GID 0.
# We need to ensure the group has write access to code and data directories.
RUN chgrp -R 0 /app && \
    chmod -R g=u /app

# Expose unprivileged port
EXPOSE 8080

# Entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# User 1001 is a convention, but OCP will likely override this UID.
# The important part is the group permission set above.
USER 1001

# Run the application
ENTRYPOINT ["/entrypoint.sh"]
