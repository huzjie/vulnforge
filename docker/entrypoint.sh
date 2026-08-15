#!/bin/sh
# vulnforge API container entrypoint.
#
# Responsibilities:
#   1. Resolve the runtime config path and fall back to the bundled example
#      config when none is mounted (vulnforge also ships built-in defaults).
#   2. Execute the provided command (default: `vulnforge serve`).

set -eu

: "${VULNFORGE_CONFIG:=/app/config.yaml}"

# docker-compose creates a directory at the mount point when the source file
# does not exist. Treat that as "no config" and fall back to the example.
if [ -d "${VULNFORGE_CONFIG}" ]; then
  echo "[entrypoint] ${VULNFORGE_CONFIG} is a directory; falling back to /app/config.yaml"
  VULNFORGE_CONFIG="/app/config.yaml"
fi

if [ ! -f "${VULNFORGE_CONFIG}" ]; then
  if [ -f /app/config.example.yaml ]; then
    echo "[entrypoint] no config at ${VULNFORGE_CONFIG}; using config.example.yaml"
    cp /app/config.example.yaml "${VULNFORGE_CONFIG}"
  else
    echo "[entrypoint] WARNING: no config file present; vulnforge will run with built-in mock defaults"
  fi
fi

export VULNFORGE_CONFIG
echo "[entrypoint] executing: $*"
exec "$@"
