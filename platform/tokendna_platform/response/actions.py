"""Response action implementations."""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..findings import Finding


class ResponseActionError(Exception):
    """Raised when a response endpoint returns non-2xx."""


@dataclass
class ResponseOutcome:
    """Returned by every action so the router can record what happened."""
    action_name: str
    finding_id: str
    succeeded: bool
    detail: str = ""


class ResponseAction(ABC):
    """A response action — identified by name, dispatches one finding."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def execute(self, finding: Finding) -> ResponseOutcome: ...


# ── Built-in actions ─────────────────────────────────────────────────────
#
# Every shipping action follows the same shape: take a target endpoint
# + auth in __init__, accept a Finding in execute(), POST a vendor-
# specific payload, raise on failure (the router catches + records).

def _post_json(url: str, body: dict[str, Any], headers: dict[str, str], *,
               http: Any | None = None, timeout_seconds: float = 10.0) -> None:
    if http is not None:
        http(url, json.dumps(body).encode(), headers)
        return
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={**headers, "Content-Type": "application/json",
                 "User-Agent": "tokendna-platform/0.0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as r:
            r.read()
    except urllib.error.HTTPError as e:
        raise ResponseActionError(f"HTTP {e.code} from {url}: {e.read()[:200]}") from e


class OktaRevokeSession(ResponseAction):
    """POST to Okta /api/v1/users/{user}/sessions to revoke active sessions."""

    def __init__(self, *, domain: str, api_token: str, http: Any | None = None) -> None:
        self._domain = domain
        self._token = api_token
        self._http = http

    @property
    def name(self) -> str:
        return "okta_revoke_session"

    def execute(self, finding: Finding) -> ResponseOutcome:
        url = f"https://{self._domain}/api/v1/users/{finding.subject}/sessions"
        try:
            _post_json(url, body={}, headers={"Authorization": f"SSWS {self._token}"},
                       http=self._http)
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=True, detail=f"revoked sessions for {finding.subject}",
            )
        except ResponseActionError as exc:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail=str(exc),
            )


class AWSWAFBlockIP(ResponseAction):
    """Add a deny rule to a WAF web-ACL via a customer-controlled webhook.

    The customer hosts an endpoint (typically a small Lambda or
    Cloudflare Worker) that consumes the payload and updates their
    WAF.  This is intentional — TokenDNA does not need direct AWS
    credentials.
    """

    def __init__(self, *, webhook_url: str, signing_secret: str | None = None,
                 http: Any | None = None) -> None:
        self._url = webhook_url
        self._secret = signing_secret
        self._http = http

    @property
    def name(self) -> str:
        return "aws_waf_block_ip"

    def execute(self, finding: Finding) -> ResponseOutcome:
        ip = finding.metadata.get("source_ip") or finding.metadata.get("client_ip")
        if not ip:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail="no source_ip / client_ip in finding metadata",
            )
        body = {
            "action": "block_ip",
            "ip": ip,
            "reason": finding.title,
            "tenant_id": finding.tenant_id,
        }
        headers = {}
        if self._secret:
            headers["X-TokenDNA-Signature"] = f"hmac-sha256:{self._secret[:8]}…"
        try:
            _post_json(self._url, body=body, headers=headers, http=self._http)
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=True, detail=f"WAF block requested for {ip}",
            )
        except ResponseActionError as exc:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail=str(exc),
            )


class K8sIsolatePod(ResponseAction):
    """Webhook-driven pod isolation via a customer K8s admission controller."""

    def __init__(self, *, webhook_url: str, http: Any | None = None) -> None:
        self._url = webhook_url
        self._http = http

    @property
    def name(self) -> str:
        return "k8s_isolate_pod"

    def execute(self, finding: Finding) -> ResponseOutcome:
        body = {
            "action": "isolate_pod",
            "agent":  finding.subject,
            "tenant_id": finding.tenant_id,
            "reason": finding.title,
        }
        try:
            _post_json(self._url, body=body, headers={}, http=self._http)
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=True, detail=f"isolation request sent for {finding.subject}",
            )
        except ResponseActionError as exc:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail=str(exc),
            )


class PagerDutyEscalate(ResponseAction):
    """Trigger a PagerDuty incident via the v2 Events API."""

    def __init__(self, *, routing_key: str, http: Any | None = None) -> None:
        self._key = routing_key
        self._http = http

    @property
    def name(self) -> str:
        return "pagerduty_escalate"

    def execute(self, finding: Finding) -> ResponseOutcome:
        body = {
            "routing_key": self._key,
            "event_action": "trigger",
            "payload": {
                "summary": finding.title,
                "severity": finding.severity.value,
                "source": "tokendna",
                "custom_details": {
                    "finding_id": finding.finding_id,
                    "subject":    finding.subject,
                    "engine":     finding.source_engine,
                    "tenant_id":  finding.tenant_id,
                },
            },
        }
        try:
            _post_json("https://events.pagerduty.com/v2/enqueue",
                       body=body, headers={}, http=self._http)
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=True, detail="incident triggered",
            )
        except ResponseActionError as exc:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail=str(exc),
            )


class JiraTicket(ResponseAction):
    """Create a Jira issue under a configured project + issuetype."""

    def __init__(
        self, *, base_url: str, email: str, api_token: str,
        project_key: str, issue_type: str = "Task",
        http: Any | None = None,
    ):
        if not base_url.startswith("https://"):
            raise ValueError("Jira base_url must be HTTPS")
        self._url = base_url.rstrip("/") + "/rest/api/3/issue"
        self._email = email
        self._token = api_token
        self._project = project_key
        self._issue_type = issue_type
        self._http = http

    @property
    def name(self) -> str:
        return "jira_ticket"

    def execute(self, finding: Finding) -> ResponseOutcome:
        body = {
            "fields": {
                "project": {"key": self._project},
                "issuetype": {"name": self._issue_type},
                "summary": f"[TokenDNA] {finding.title}",
                "description": (
                    f"Severity: {finding.severity.value}\n"
                    f"Subject:  {finding.subject}\n"
                    f"Engine:   {finding.source_engine}\n"
                    f"Tenant:   {finding.tenant_id}\n"
                    f"\n{finding.description or '(no extra detail)'}"
                ),
            },
        }
        # Jira basic auth: base64(email:token).
        import base64
        token = base64.b64encode(f"{self._email}:{self._token}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        try:
            _post_json(self._url, body=body, headers=headers, http=self._http)
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=True, detail="Jira ticket created",
            )
        except ResponseActionError as exc:
            return ResponseOutcome(
                action_name=self.name, finding_id=finding.finding_id,
                succeeded=False, detail=str(exc),
            )
