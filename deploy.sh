#!/bin/bash
# deploy.sh — Re-download deployment files and rebuild the Docker image if needed.
# Run from the directory where Dockerfile, docker-compose.yml and .env live.

set -e

BASE_URL="https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/Traccar"

echo "==> Downloading latest deployment files..."
curl -sSfLO "${BASE_URL}/Dockerfile"
curl -sSfLO "${BASE_URL}/docker-compose.yml"
curl -sSfLO "${BASE_URL}/deploy.sh"
chmod +x deploy.sh

echo "==> Rebuilding image and restarting service..."
docker compose up --build -d

echo "==> Last 30 log lines:"
docker compose logs --tail=30
