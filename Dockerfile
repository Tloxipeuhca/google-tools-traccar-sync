# =============================================================================
# GoogleFindMyTools – Traccar sync service
#
# Builds a self-contained image by cloning two repositories:
#   1. leonboe1/GoogleFindMyTools  — base project (NovaApi, ProtoDecoders, …)
#   2. Tloxipeuhca/google-tools-traccar-sync — Traccar sync module
#
# The Traccar/ folder and extended requirements.txt from the sync repo are
# overlaid on top of the base project.
#
# Usage (from the Traccar/ directory):
#   docker compose up -d
# =============================================================================

FROM python:3.11-slim

WORKDIR /app

# System packages required by some Python dependencies (frida, cryptography …)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# 1. Clone GoogleFindMyTools – provides NovaApi, ProtoDecoders, main.py, …
RUN git clone --depth 1 https://github.com/leonboe1/GoogleFindMyTools.git .

# 2. Clone the Traccar sync module and overlay it on the base project
RUN git clone --depth 1 https://github.com/Tloxipeuhca/google-tools-traccar-sync.git /tmp/traccar-sync \
    && cp -r /tmp/traccar-sync/Traccar /app/Traccar \
    && sort -u /app/requirements.txt /tmp/traccar-sync/requirements.txt -o /app/requirements.txt \
    && rm -rf /tmp/traccar-sync

# Install all Python dependencies (base + Traccar extras, e.g. flask)
RUN pip install --no-cache-dir -r requirements.txt

# Pre-create runtime directories; they will be overridden by bind-mounts at run time
RUN mkdir -p Data logs

EXPOSE 5001

# Keep Python output unbuffered so logs appear immediately in docker logs
ENV PYTHONUNBUFFERED=1

# TRACCAR_SERVER_URL and PORT are injected at runtime via environment variables
# (see docker-compose.yml or pass -e flags to docker run)
CMD python -m Traccar.service \
        --server-url "${TRACCAR_SERVER_URL}" \
        --port "${PORT:-5001}"
