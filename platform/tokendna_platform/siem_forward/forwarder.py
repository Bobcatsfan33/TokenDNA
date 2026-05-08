"""SIEM forwarder implementations.

Each forwarder is a concrete subclass of ``SIEMForwarder`` with its
own ``_payload`` builder + auth header set.  Network I/O uses stdlib
``urllib.request`` so no SDK pull-in.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from ..findings import Finding


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Render a Finding into a JSON-safe dict."""
    out = dataclasses.asdict(finding)
    if isinstance(out.get("detected_at"), datetime):
        out["detected_at"] = out["detected_at"].isoformat()
    sev = out.get("severity")
    if hasattr(sev, "value"):
        out["severity"] = sev.value
    return out


class SIEMForwardError(Exception):
    """Raised when a SIEM rejects a finding payload."""


class SIEMForwarder(ABC):
    """Abstract forwarder; concrete forwarders POST per-vendor payloads."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def forward(self, finding: Finding) -> None:
        ...


class SplunkHECForwarder(SIEMForwarder):
    """Splunk HTTP Event Collector.

    Construct with the HEC URL and a token issued by the Splunk admin
    against an HEC-enabled token policy.  Finding goes into Splunk as
    a structured JSON event under index ``main`` (override per call).
    """

    def __init__(
        self,
        *,
        hec_url: str,
        hec_token: str,
        index: str | None = None,
        sourcetype: str = "tokendna:finding",
        timeout_seconds: float = 10.0,
        # Test seam: override the underlying HTTP function.
        http: Any | None = None,
    ):
        if not hec_url.startswith("https://"):
            raise ValueError("Splunk HEC URL must be HTTPS")
        self._url = hec_url.rstrip("/") + "/services/collector/event"
        self._token = hec_token
        self._index = index
        self._sourcetype = sourcetype
        self._timeout = timeout_seconds
        self._http = http

    @property
    def name(self) -> str:
        return "splunk_hec"

    def forward(self, finding: Finding) -> None:
        body = json.dumps({
            "event":      _serialize_finding(finding),
            "sourcetype": self._sourcetype,
            **({"index": self._index} if self._index else {}),
            "time":       finding.detected_at.timestamp(),
        }).encode("utf-8")
        self._post(body)

    def _post(self, body: bytes) -> None:
        if self._http is not None:
            self._http(self._url, body, {"Authorization": f"Splunk {self._token}"})
            return
        req = urllib.request.Request(
            self._url, data=body, method="POST",
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "tokendna-platform/0.0.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise SIEMForwardError(f"Splunk HEC HTTP {e.code}: {e.read()[:200]}") from e


class DatadogForwarder(SIEMForwarder):
    """Datadog Logs Intake API."""

    def __init__(
        self,
        *,
        api_key: str,
        site: str = "datadoghq.com",
        service: str = "tokendna-platform",
        timeout_seconds: float = 10.0,
        http: Any | None = None,
    ):
        self._url = f"https://http-intake.logs.{site}/api/v2/logs"
        self._api_key = api_key
        self._service = service
        self._timeout = timeout_seconds
        self._http = http

    @property
    def name(self) -> str:
        return "datadog"

    def forward(self, finding: Finding) -> None:
        body = json.dumps({
            "ddsource":  "tokendna",
            "ddtags":    f"tenant:{finding.tenant_id},engine:{finding.source_engine}",
            "service":   self._service,
            "hostname":  "tokendna-platform",
            "message":   finding.title,
            "tokendna":  _serialize_finding(finding),
        }).encode("utf-8")
        if self._http is not None:
            self._http(self._url, body, {"DD-API-KEY": self._api_key})
            return
        req = urllib.request.Request(
            self._url, data=body, method="POST",
            headers={
                "DD-API-KEY": self._api_key,
                "Content-Type": "application/json",
                "User-Agent": "tokendna-platform/0.0.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise SIEMForwardError(f"Datadog Logs HTTP {e.code}: {e.read()[:200]}") from e
