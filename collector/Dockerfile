# TokenDNA Collector — production container image.
#
# Multi-stage → distroless runtime.  Same security posture as the
# platform image at the repo root (see ../Dockerfile).  Stdlib-only
# Python at runtime so the image stays under ~50 MB compressed.
#
# Build (single-arch dev):
#   docker build -t ghcr.io/bobcatsfan33/tokendna-collector:dev collector/
#
# Build (multi-arch release; .github/workflows/release-collector-docker.yml
# does this automatically on `v*` tag pushes):
#   docker buildx build --platform linux/amd64,linux/arm64 -t … collector/
#
# Run:
#   docker run --rm \
#     -e TOKENDNA_TENANT_ID=acme \
#     -e TOKENDNA_COLLECTOR_ID=collector-1 \
#     -e TOKENDNA_CLOUD_ENDPOINT=https://cloud.tokendna.example/ \
#     -e TOKENDNA_CLOUD_API_KEY=... \
#     -e OKTA_DOMAIN=acme.okta.com \
#     -e OKTA_API_TOKEN=... \
#     -p 9100:9100 \
#     ghcr.io/bobcatsfan33/tokendna-collector:latest

FROM python:3.11-slim AS builder
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml ./
COPY tokendna_collector ./tokendna_collector
RUN pip install --prefix=/install .


FROM python:3.11-slim AS appstage
WORKDIR /app
COPY tokendna_collector ./tokendna_collector
COPY pyproject.toml LICENSE NOTICE README.md ./
RUN find /app -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && find /app -name '*.pyc' -delete


FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="TokenDNA Collector" \
      org.opencontainers.image.description="Open-source edge collector for the TokenDNA AI runtime security platform." \
      org.opencontainers.image.source="https://github.com/Bobcatsfan33/TokenDNA" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="TokenDNA"

COPY --from=builder --chown=nonroot:nonroot /install /usr/local
COPY --from=appstage --chown=nonroot:nonroot /app /app

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/usr/local/lib/python3.11/site-packages \
    TOKENDNA_BUFFER_PATH=/data/buffer

USER nonroot:nonroot

EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys,json; r=urllib.request.urlopen('http://127.0.0.1:9100/health',timeout=3); sys.exit(0 if json.load(r).get('state') in ('healthy','degraded') else 1)"]

ENTRYPOINT ["python", "-m", "tokendna_collector"]
