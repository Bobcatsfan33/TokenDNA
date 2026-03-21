# TokenDNA — Production Dockerfile
# Multi-stage: compile wheels in builder → copy to slim runtime image

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for wheels that need compilation (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

# Create non-root user
RUN groupadd -r tokendna && useradd -r -g tokendna -d /app -s /sbin/nologin tokendna

WORKDIR /app

# Install pre-built wheels (no compiler needed at runtime)
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels

# Copy application source
COPY --chown=tokendna:tokendna . .

# Optional: copy MaxMind database if using offline GeoIP
# COPY --chown=tokendna:tokendna GeoLite2-City.mmdb /data/GeoLite2-City.mmdb

USER tokendna

# Expose FastAPI port
EXPOSE 8000

# Health check — lightweight ping against the / endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Start with uvicorn; tune --workers for your CPU count
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
