"""Collector process entry point.

Usage (inside the container):
    python -m tokendna_collector

Reads ``CollectorConfig`` from the environment.  Required:

    TOKENDNA_TENANT_ID         tenant id provisioned in TokenDNA Cloud
    TOKENDNA_COLLECTOR_ID      stable per-instance id
    TOKENDNA_CLOUD_ENDPOINT    https://cloud.tokendna.example/
    TOKENDNA_CLOUD_API_KEY     API key from TokenDNA Cloud admin

Optional:

    TOKENDNA_HEALTH_ADDR       default 0.0.0.0:9100
    TOKENDNA_BUFFER_PATH       default /var/lib/tokendna-collector/buffer
    OKTA_DOMAIN, OKTA_API_TOKEN  enables the Okta adapter when both set

Future commits add a single TOML config file for richer adapter
selection; the env-var bootstrap above is enough for Sprint 1-2.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from .adapters.idp import OktaSystemLogAdapter
from .config import AdapterConfig, CollectorConfig
from .runner import CollectorRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tokendna_collector")


def load_config_from_env() -> tuple[CollectorConfig, list]:
    required = {
        "TOKENDNA_TENANT_ID":     os.getenv("TOKENDNA_TENANT_ID", "").strip(),
        "TOKENDNA_COLLECTOR_ID":  os.getenv("TOKENDNA_COLLECTOR_ID", "").strip(),
        "TOKENDNA_CLOUD_ENDPOINT": os.getenv("TOKENDNA_CLOUD_ENDPOINT", "").strip(),
        "TOKENDNA_CLOUD_API_KEY": os.getenv("TOKENDNA_CLOUD_API_KEY", "").strip(),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        logger.error("missing required env vars: %s", ", ".join(missing))
        sys.exit(2)

    cfg = CollectorConfig(
        tenant_id=required["TOKENDNA_TENANT_ID"],
        collector_id=required["TOKENDNA_COLLECTOR_ID"],
        cloud_endpoint=required["TOKENDNA_CLOUD_ENDPOINT"],
        cloud_api_key=required["TOKENDNA_CLOUD_API_KEY"],
        health_listen_addr=os.getenv("TOKENDNA_HEALTH_ADDR", "0.0.0.0:9100"),
        buffer_path=os.getenv("TOKENDNA_BUFFER_PATH", "/var/lib/tokendna-collector/buffer"),
    )

    adapters = []
    okta_domain = os.getenv("OKTA_DOMAIN", "").strip()
    okta_token = os.getenv("OKTA_API_TOKEN", "").strip()
    if okta_domain and okta_token:
        cfg.adapters.append(AdapterConfig(
            source_type="okta",
            name=f"okta:{okta_domain}",
            poll_interval_seconds=int(os.getenv("OKTA_POLL_INTERVAL_SECONDS", "30")),
            options={"domain": okta_domain, "api_token": okta_token},
        ))
        adapters.append(OktaSystemLogAdapter())

    if not adapters:
        logger.warning(
            "no adapters configured — set OKTA_DOMAIN+OKTA_API_TOKEN to enable Okta"
        )

    return cfg, adapters


def serve_health(runner: CollectorRunner, addr: str) -> Thread:
    """Spin up a tiny HTTP server for /health on a background thread."""
    host, _, port = addr.rpartition(":")
    bind = (host or "0.0.0.0", int(port) if port else 9100)

    loop = asyncio.get_event_loop()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/health":
                self.send_response(404)
                self.end_headers()
                return
            future = asyncio.run_coroutine_threadsafe(runner.health(), loop)
            try:
                health = future.result(timeout=5.0)
            except Exception as exc:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(exc)}).encode())
                return
            status = 200 if health["state"] != "unhealthy" else 503
            body = json.dumps(health, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args, **_kwargs) -> None:  # noqa: D401
            return

    httpd = ThreadingHTTPServer(bind, Handler)
    t = Thread(target=httpd.serve_forever, name="health-http", daemon=True)
    t.start()
    logger.info("health endpoint listening on http://%s:%s/health", bind[0], bind[1])
    return t


async def amain() -> int:
    cfg, adapters = load_config_from_env()
    runner = CollectorRunner(cfg, adapters)
    serve_health(runner, cfg.health_listen_addr)
    logger.info(
        "collector starting: tenant=%s id=%s adapters=%s",
        cfg.tenant_id, cfg.collector_id, [a.source_type for a in adapters],
    )
    try:
        await runner.start()
    except KeyboardInterrupt:  # pragma: no cover
        runner.stop()
    return 0


def main() -> None:
    sys.exit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
