# TokenDNA — production container image
#
# Multi-stage build → distroless runtime.
#
# Security posture:
#   * Build stage:  python:3.11-slim with toolchain to compile cryptography +
#                   psycopg + any other native-extension wheels.
#   * Runtime stage: gcr.io/distroless/python3-debian12:nonroot
#                   - no shell, no apt, no busybox, no curl, no wget
#                   - ships only the Python interpreter + libc + ca-certs
#                   - default UID 65532 (nonroot variant); we keep it
#                   - read-only root FS friendly
#   * Healthcheck:   urllib.request via the Python interpreter — no curl/wget
#                   binary required, since distroless has neither.
#   * .env, *.key, *.pem stripped before COPY into runtime stage.
#   * PYTHONDONTWRITEBYTECODE keeps the runtime FS clean / read-only-friendly.
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/bobcatsfan33/tokendna:dev .
#
# Run:
#   docker run --rm -p 8000:8000 \
#     -e ATTESTATION_CA_SECRET=demo-secret-32-bytes-aaaaaaa \
#     -e DEV_MODE=true \
#     ghcr.io/bobcatsfan33/tokendna:dev

# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Native build deps for cryptography, psycopg[binary], etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt


# ── Stage 2: app staging ─────────────────────────────────────────────────────
# Separate from runtime so we can strip secrets / build artefacts before
# they reach the distroless layer.
FROM python:3.11-slim AS appstage

WORKDIR /app
COPY . /app

# Defence in depth: strip anything that should never be inside an image.
RUN find /app -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && find /app \( -name '.env' -o -name '.env.*' -o -name '*.key' -o -name '*.pem' \) -delete \
 && rm -rf /app/.git /app/.github /app/.pytest_cache /app/.mypy_cache /app/tests \
 && find /app -name '*.pyc' -delete


# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

# Cosign-friendly OCI labels (parsed by GHCR, scanners, and the release
# workflow when computing the SBOM).
LABEL org.opencontainers.image.title="TokenDNA" \
      org.opencontainers.image.description="Runtime identity verification and behavioural trust engine for AI agents." \
      org.opencontainers.image.source="https://github.com/Bobcatsfan33/TokenDNA" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.vendor="TokenDNA"

# Bring in the resolved site-packages tree from the builder…
COPY --from=builder --chown=nonroot:nonroot /install /usr/local

# …and the cleaned application source from the appstage.
COPY --from=appstage --chown=nonroot:nonroot /app /app

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONPATH=/app:/usr/local/lib/python3.11/site-packages \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DB_PATH=/data/tokendna.db \
    AUDIT_LOG_PATH=/var/log/aegis/audit.jsonl

# Distroless ships a `nonroot` user (UID 65532); we just declare it.
USER nonroot:nonroot

EXPOSE 8000

# distroless has no shell + no curl/wget, so the healthcheck runs through
# the Python interpreter that's already in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"]

# Distroless `python3-debian12` images use the python interpreter as the
# entrypoint, so we hand it the module + args directly.
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["api:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info", \
     "--no-access-log"]
