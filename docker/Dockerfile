# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only build essentials needed for compiling any optional wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and install the full dependency set.
COPY pyproject.toml README.md config.example.yaml ./
COPY vulnforge ./vulnforge
RUN pip install -e ".[full]"

# --- runtime stage ----------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VULNFORGE_CONFIG=/app/config.yaml

WORKDIR /app

RUN addgroup --system vulnforge \
    && adduser --system --ingroup vulnforge vulnforge

# Copy installed site-packages from the builder.
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Entrypoint wrapper (creates config fallback, waits for deps, etc.)
COPY docker/entrypoint.sh /usr/local/bin/vulnforge-entrypoint
RUN chmod +x /usr/local/bin/vulnforge-entrypoint

RUN mkdir -p /app/results /app/.vf_cache && chown -R vulnforge:vulnforge /app

USER vulnforge

EXPOSE 8000

ENTRYPOINT ["vulnforge-entrypoint"]
CMD ["vulnforge", "serve"]
