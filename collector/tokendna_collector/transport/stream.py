"""Cloud transport — streaming client to TokenDNA Cloud.

Posts compressed batches of ``NormalizedEvent`` records to the cloud
ingestion endpoint over TLS.  The protocol is intentionally simple:

  POST {cloud_endpoint}/api/v1/ingest
  Content-Type: application/x-ndjson
  Content-Encoding: gzip          (or zstd / identity per Compressor)
  Authorization: Bearer <api_key>
  X-TokenDNA-Tenant: <tenant>
  X-TokenDNA-Collector: <collector_id>

  body: {compressed JSONL frame of N events}

  → 200 with {"accepted": N, "duplicates": M}
  → 4xx for permanent errors (auth, schema)
  → 5xx for retryable errors (the runner backs off + buffers)

mTLS client certificates are supported via ``client_cert`` /
``client_key`` arguments — when provided the connection performs mutual
auth.  When omitted the connection still uses TLS server-cert
verification, which is appropriate for early customers.

Implementation note: stdlib only.  ``urllib.request`` + ``ssl``.  No
async HTTP client (httpx) yet because the runner already isolates
network I/O in ``asyncio.to_thread``, and avoiding a runtime dep keeps
the collector image small.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import dataclasses
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from typing import Iterable

from ..schema import NormalizedEvent
from .compress import Compressor


def _serialize_event(event: NormalizedEvent) -> str:
    """Match the on-disk format used by LocalBuffer."""
    d = dataclasses.asdict(event)
    for k in ("timestamp", "received_at"):
        if isinstance(d.get(k), datetime):
            d[k] = d[k].isoformat()
    for k in ("event_category", "outcome"):
        v = d.get(k)
        if hasattr(v, "value"):
            d[k] = v.value
    return json.dumps(d, separators=(",", ":"), sort_keys=True)


class CloudTransportError(Exception):
    """Base class for cloud-transport failures."""


class PermanentTransportError(CloudTransportError):
    """4xx response — caller should not retry without intervention."""


class TransientTransportError(CloudTransportError):
    """5xx / network failure — caller should retry with backoff."""


class CloudStream:
    """Send events to the TokenDNA Cloud ingestion endpoint."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        tenant_id: str,
        collector_id: str,
        *,
        ca_cert_path: str | None = None,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
        compressor: Compressor | None = None,
        timeout_seconds: float = 30.0,
    ):
        if not endpoint.startswith("https://"):
            raise ValueError("cloud_endpoint must be HTTPS")
        self._url = endpoint.rstrip("/") + "/api/v1/ingest"
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._collector_id = collector_id
        self._compressor = compressor or Compressor.gzip()
        self._timeout = timeout_seconds
        self._ssl_ctx = self._build_ssl_context(
            ca_cert_path, client_cert_path, client_key_path
        )

    @staticmethod
    def _build_ssl_context(
        ca: str | None, cert: str | None, key: str | None
    ) -> ssl.SSLContext:
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert and key:
            ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    # ── Public API ──────────────────────────────────────────────────────
    def send_batch(self, events: Iterable[NormalizedEvent]) -> dict:
        """POST one compressed JSONL frame; returns the cloud's response.

        Raises ``PermanentTransportError`` on 4xx, ``TransientTransportError``
        on 5xx / network errors.  Caller is expected to retry transient
        failures with exponential backoff.
        """
        body = "\n".join(_serialize_event(e) for e in events).encode("utf-8")
        if not body:
            return {"accepted": 0, "duplicates": 0}
        compressed = self._compressor.encode(body)

        req = urllib.request.Request(
            self._url,
            data=compressed,
            method="POST",
            headers={
                "Content-Type": "application/x-ndjson",
                "Content-Encoding": self._compressor.name,
                "Authorization": f"Bearer {self._api_key}",
                "X-TokenDNA-Tenant": self._tenant_id,
                "X-TokenDNA-Collector": self._collector_id,
                "User-Agent": "tokendna-collector/0.0.1",
            },
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout, context=self._ssl_ctx
            ) as resp:
                payload = resp.read().decode("utf-8") or "{}"
                try:
                    return json.loads(payload)
                except json.JSONDecodeError:
                    return {"accepted": len(events) if hasattr(events, "__len__") else 0}
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")[:200]
            if 400 <= e.code < 500:
                raise PermanentTransportError(
                    f"HTTP {e.code} from cloud: {body_text}"
                ) from e
            raise TransientTransportError(
                f"HTTP {e.code} from cloud: {body_text}"
            ) from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise TransientTransportError(f"network: {e}") from e
