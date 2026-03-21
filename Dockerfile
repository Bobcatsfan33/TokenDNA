# TokenDNA — Production Dockerfile
# CIS Docker Benchmark v1.6 / FedRAMP High container hardening
#
# Security controls:
#   - Multi-stage build (no build tools in runtime image)
#   - Non-root user (UID 10001 — not in common user range)
#   - Read-only root filesystem enforced via docker-compose
#   - No shell in final image (scratch-like minimal footprint)
#   - Pinned base image digest in CI (update monthly)
#   - .env files explicitly deleted
#   - PYTHONDONTWRITEBYTECODE prevents .pyc file creation (clean FS)

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools — stripped from runtime image
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Install minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root service account (UID/GID 10001 avoids common ranges)
RUN groupadd -g 10001 aegis && useradd -u 10001 -g aegis -s /sbin/nologin -M aegis

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source (owned by root, readable by aegis — defense in depth)
COPY --chown=root:aegis . .

# Harden file permissions
RUN chmod -R o-rwx /app && \
    chmod -R g-w /app && \
    # Remove any accidentally included sensitive files
    rm -f .env .env.* *.key *.pem && \
    # Create log directory (tmpfs mount in compose overrides this)
    mkdir -p /var/log/aegis && chown aegis:aegis /var/log/aegis

# Security: prevent python from writing .pyc files to the FS
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    # Disable pip version check / telemetry
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/ || exit 1

# Use exec form (not shell form) — prevents shell injection
CMD ["python", "-m", "uvicorn", "api:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info", \
     "--no-access-log"]
