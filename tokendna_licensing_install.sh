#!/usr/bin/env bash
# ==============================================================================
# TokenDNA — Stripe-backed signed-license gating (open-core entitlement spine)
#
# Run this FROM THE ROOT of your local TokenDNA clone:
#     bash tokendna_licensing_install.sh
#
# What it does:
#   1. Creates branch feat/stripe-license-gating
#   2. Adds modules/product/licensing.py        (Ed25519 license verification)
#   3. Rewrites modules/product/commercial_tiers.py (license caps effective tier)
#   4. Adds api_routers/license.py              (GET status / POST activate)
#   5. Rewrites api_routers/__init__.py         (registers the license router)
#   6. Adds scripts/generate_license_keys.py    (keypair generator + pubkey inject)
#   7. Adds tests/test_licensing.py             (unit tests)
#   8. Adds docs/LICENSING.md, appends license vars to .env.example
#   9. Generates YOUR signing keypair (private key -> ~/.tokendna/, NEVER committed)
#  10. Re-baselines the CI route-surface snapshot, runs tests, commits
#
# It does NOT push. Review the diff, then:
#     git push -u origin feat/stripe-license-gating
#
# SECURITY NOTES
#   * The private signing key is written to ~/.tokendna/license_signing_private.pem
#     (chmod 600). It must NEVER enter this repo or any public location.
#     Back it up somewhere safe (password manager / encrypted drive).
#   * Nothing personal (email, phone number) goes into code or keys. Your Stripe
#     account linkage lives entirely in the Stripe dashboard + the PRIVATE
#     license-server repo (see tokendna_license_server_install.sh).
#   * Default enforcement is "off" so existing behavior, tests, and the 10-min
#     demo are unchanged. Production deployments opt in with
#     TOKENDNA_LICENSE_ENFORCEMENT=enforce.
# ==============================================================================
set -euo pipefail

if [ ! -f "modules/product/commercial_tiers.py" ]; then
  echo "ERROR: run this from the TokenDNA repo root." >&2
  exit 1
fi

git checkout -b feat/stripe-license-gating

# ──────────────────────────────────────────────────────────────────────────────
# 1. modules/product/licensing.py
# ──────────────────────────────────────────────────────────────────────────────
cat > modules/product/licensing.py <<'PYEOF'
"""
TokenDNA — Signed license keys (the open-core entitlement boundary).

Why this exists
---------------
TokenDNA's repository is public. ``modules.product.commercial_tiers`` gates
the ``ent.*`` enterprise features (Blast Radius, enforcement plane, intent
correlation, MCP gateway, behavioral DNA) by the tenant's billing plan — but
in a self-hosted deployment the tenant database belongs to the operator, so a
DB row saying ``plan='enterprise'`` proves nothing. The real entitlement
boundary is a cryptographically signed license key:

* Licenses are issued by the (private) TokenDNA license service, driven by
  Stripe subscription events. Only the Ed25519 *public* key ships here.
* A license is a compact signed string::

      TDNA1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>

  signed over the bytes of ``"TDNA1." + <base64url payload>``.
* Verification is fully offline — no phone-home. (The license service exposes
  an optional ``/v1/licenses/validate`` revocation check for operators who
  want it.)

Payload fields
--------------
``lid`` license id · ``sub`` Stripe customer id · ``org`` display name ·
``tier`` community|pro|enterprise · ``features`` optional list of à-la-carte
``ent.*`` keys · ``iat`` issued-at (unix) · ``exp`` expiry (unix).

Enforcement modes — ``TOKENDNA_LICENSE_ENFORCEMENT``
----------------------------------------------------
``off``     (default) plan-based gating only; behavior identical to pre-license
            builds. Keeps dev, CI, and the 10-minute demo friction-free.
``warn``    log when the DB plan exceeds the license, but allow.
``enforce`` the license caps the effective commercial tier. Production mode.

This gate is a compliance boundary, not DRM: the repo is public, so the check
is patchable by a determined operator. Commercial use without a license is
governed by the BUSL-1.1 terms; the signed key is what makes honest
commercial use frictionless and auditable.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

LICENSE_PREFIX = "TDNA1"

# Ed25519 public key (hex). Injected by ``scripts/generate_license_keys.py
# --inject``. The corresponding private key is held offline by the vendor and
# never enters this repository.
LICENSE_PUBLIC_KEY_HEX = "__TOKENDNA_LICENSE_PUBKEY_HEX__"

_VALID_TIERS = {"community", "pro", "enterprise"}
_CACHE_TTL_SECONDS = 60.0


class LicenseError(Exception):
    """Raised when a license key is malformed, unsigned, or expired."""


@dataclass(frozen=True)
class License:
    license_id: str
    customer: str
    org: str
    tier: str
    issued_at: int
    expires_at: int
    features: tuple[str, ...] = field(default_factory=tuple)

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "customer": self.customer,
            "org": self.org,
            "tier": self.tier,
            "features": list(self.features),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


# ── base64url helpers ────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ── Verification ─────────────────────────────────────────────────────────────

def parse_and_verify(
    raw: str,
    *,
    public_key_hex: Optional[str] = None,
    now: Optional[float] = None,
) -> License:
    """Parse a raw license string, verify its signature, and check expiry.

    Raises ``LicenseError`` on any failure. Never raises anything else for
    malformed input.
    """
    pub_hex = public_key_hex if public_key_hex is not None else LICENSE_PUBLIC_KEY_HEX
    if not pub_hex or pub_hex.startswith("__"):
        raise LicenseError("license public key not configured in this build")

    raw = (raw or "").strip()
    parts = raw.split(".")
    if len(parts) != 3 or parts[0] != LICENSE_PREFIX:
        raise LicenseError("malformed license key (expected TDNA1.<payload>.<sig>)")

    payload_b64, sig_b64 = parts[1], parts[2]
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("license key is not valid base64url") from exc

    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        message = f"{LICENSE_PREFIX}.{payload_b64}".encode("ascii")
        try:
            public_key.verify(signature, message)
        except InvalidSignature as exc:
            raise LicenseError("license signature verification failed") from exc
    except LicenseError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LicenseError(f"license verification unavailable: {exc}") from exc

    try:
        payload = json.loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("license payload is not valid JSON") from exc

    tier = str(payload.get("tier", "")).lower()
    if tier not in _VALID_TIERS:
        raise LicenseError(f"license tier {tier!r} is not recognized")

    lic = License(
        license_id=str(payload.get("lid", "")),
        customer=str(payload.get("sub", "")),
        org=str(payload.get("org", "")),
        tier=tier,
        issued_at=int(payload.get("iat", 0)),
        expires_at=int(payload.get("exp", 0)),
        features=tuple(str(f) for f in payload.get("features", []) or ()),
    )
    if lic.is_expired(now):
        raise LicenseError("license has expired")
    return lic


# ── Loading + caching ────────────────────────────────────────────────────────

def _license_file_path() -> str:
    return os.getenv("TOKENDNA_LICENSE_FILE", "") or "./license.key"


def _load_raw_license() -> Optional[str]:
    raw = (os.getenv("TOKENDNA_LICENSE_KEY") or "").strip()
    if raw:
        return raw
    path = _license_file_path()
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read().strip()
            return content or None
    except OSError as exc:
        logger.warning("license file %s unreadable: %s", path, exc)
    return None


_lock = threading.Lock()
_state: dict[str, Any] = {"license": None, "error": None, "loaded_at": None, "present": False}


def reload() -> None:
    """Force a re-read of the license from env/file on next access."""
    with _lock:
        _state["loaded_at"] = None


def _is_stale_locked() -> bool:
    """True when the cached license must be re-read from env/file.

    ``loaded_at`` is ``None`` before the first load and after ``reload()``.
    ``time.monotonic()`` has an undefined reference point (it can start near
    zero at process launch), so ``0.0`` must NOT be treated as "long ago" —
    only an explicit ``None`` forces a refresh.
    """
    loaded_at = _state["loaded_at"]
    return loaded_at is None or (time.monotonic() - float(loaded_at)) > _CACHE_TTL_SECONDS


def _refresh_locked() -> None:
    raw = _load_raw_license()
    _state["present"] = raw is not None
    if raw is None:
        _state["license"], _state["error"] = None, None
    else:
        try:
            _state["license"], _state["error"] = parse_and_verify(raw), None
        except LicenseError as exc:
            _state["license"], _state["error"] = None, str(exc)
            logger.warning("license rejected: %s", exc)
    _state["loaded_at"] = time.monotonic()


def get_license() -> Optional[License]:
    """Return the currently valid license, or ``None``. Never raises."""
    with _lock:
        if _is_stale_locked():
            _refresh_locked()
        lic = _state["license"]
    if lic is not None and lic.is_expired():
        return None
    return lic


# ── Entitlement surface consumed by commercial_tiers ─────────────────────────

def enforcement_mode() -> str:
    """``off`` | ``warn`` | ``enforce`` — driven by env, default ``off``."""
    mode = (os.getenv("TOKENDNA_LICENSE_ENFORCEMENT") or "off").strip().lower()
    return mode if mode in {"off", "warn", "enforce"} else "off"


def licensed_tier() -> str:
    """Tier granted by the current license, or ``community`` when absent."""
    lic = get_license()
    return lic.tier if lic is not None else "community"


def feature_granted(feature_key: str) -> bool:
    """True when the license grants ``feature_key`` à la carte."""
    lic = get_license()
    return lic is not None and feature_key in lic.features


def status() -> dict[str, Any]:
    """Structured license status for the ``/api/license/status`` endpoint."""
    with _lock:
        if _is_stale_locked():
            _refresh_locked()
        lic, error, present = _state["license"], _state["error"], _state["present"]
    if lic is not None and lic.is_expired():
        lic, error = None, "license has expired"
    if lic is not None:
        state = "valid"
    elif not present:
        state = "missing"
    else:
        state = "invalid"
    out: dict[str, Any] = {
        "state": state,
        "enforcement": enforcement_mode(),
        "tier": lic.tier if lic else "community",
    }
    if lic is not None:
        out["license"] = lic.to_dict()
    if error:
        out["error"] = error
    return out


def activate(raw: str) -> License:
    """Verify ``raw`` and persist it to the license file. Raises LicenseError."""
    lic = parse_and_verify(raw)
    path = _license_file_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw.strip() + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    reload()
    logger.info("license %s activated (tier=%s, org=%s)", lic.license_id, lic.tier, lic.org)
    return lic
PYEOF

# ──────────────────────────────────────────────────────────────────────────────
# 2. modules/product/commercial_tiers.py  (full rewrite: license cap integrated)
# ──────────────────────────────────────────────────────────────────────────────
cat > modules/product/commercial_tiers.py <<'PYEOF'
"""
TokenDNA — Commercial tier entitlement system

Defines the three customer-facing tiers (community / pro / enterprise) and the
``ent.*`` feature gates that control access to the Phase 5 enterprise modules.

Why a separate module
---------------------
``modules.product.feature_gates`` enforces the OSS / paid plan boundaries that
existed before Phase 5. This module models the *commercial tier ladder* the
sales motion cares about (community → pro → enterprise) and emits structured
``403`` errors with the upgrade target and metadata so the UI can render an
actionable upsell rather than a generic "forbidden" page.

Licensing
---------
In a self-hosted open-core deployment the tenant database is under the
operator's control, so the DB ``plan`` alone cannot be the entitlement
boundary. When ``TOKENDNA_LICENSE_ENFORCEMENT`` is ``warn`` or ``enforce``,
the Stripe-issued signed license key (``modules.product.licensing``) caps the
effective commercial tier and can grant à-la-carte ``ent.*`` features.

Public surface
--------------
- ``CommercialTier``                Enum of tiers in ascending order.
- ``FeatureGate``                   Frozen dataclass describing one gate.
- ``COMMERCIAL_FEATURES``           Catalog of every ``ent.*`` gate.
- ``tier_for_plan(plan)``           Map ``Plan`` → ``CommercialTier``.
- ``is_entitled(plan, feature)``    Pure boolean check.
- ``forbidden_payload(...)``        Build the structured 403 detail dict.
- ``require_feature(feature)``      FastAPI dependency factory (returns the
                                    resolved ``TenantContext`` so routes can
                                    swap ``Depends(get_tenant)`` 1-for-1).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from fastapi import Depends, HTTPException, status

from modules.tenants.middleware import get_tenant
from modules.tenants.models import Plan, TenantContext

logger = logging.getLogger(__name__)


# ── Tiers ─────────────────────────────────────────────────────────────────────

class CommercialTier(str, Enum):
    """Customer-facing commercial tiers, ordered by entitlement strength."""
    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# Lower number = lower entitlement. Comparisons go through this map so the
# CommercialTier enum can stay a plain str-Enum (FastAPI/JSON friendly).
_TIER_RANK: dict[CommercialTier, int] = {
    CommercialTier.COMMUNITY: 10,
    CommercialTier.PRO: 20,
    CommercialTier.ENTERPRISE: 30,
}


def _rank(tier: CommercialTier) -> int:
    return _TIER_RANK[tier]


# Existing Plan values map onto commercial tiers. FREE and STARTER both fall
# into COMMUNITY — the commercial taxonomy is coarser than the billing plans.
_PLAN_TO_TIER: dict[Plan, CommercialTier] = {
    Plan.FREE: CommercialTier.COMMUNITY,
    Plan.STARTER: CommercialTier.COMMUNITY,
    Plan.PRO: CommercialTier.PRO,
    Plan.ENTERPRISE: CommercialTier.ENTERPRISE,
}


def tier_for_plan(plan: Plan | str) -> CommercialTier:
    """
    Resolve a billing ``Plan`` (or its raw string value) to a commercial tier.
    Unknown values fall back to COMMUNITY — the most restrictive tier — so
    misconfigured tenants never accidentally get paid features.
    """
    if isinstance(plan, Plan):
        return _PLAN_TO_TIER.get(plan, CommercialTier.COMMUNITY)
    try:
        return _PLAN_TO_TIER.get(Plan(str(plan).lower()), CommercialTier.COMMUNITY)
    except ValueError:
        return CommercialTier.COMMUNITY


# ── Feature gate catalog ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class FeatureGate:
    """One commercial entitlement gate."""
    key: str
    name: str
    min_tier: CommercialTier
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "min_tier": self.min_tier.value,
            "description": self.description,
        }


# Phase 5 commercial gates — every Phase 5 module is anchored here.
COMMERCIAL_FEATURES: dict[str, FeatureGate] = {
    gate.key: gate
    for gate in (
        FeatureGate(
            key="ent.mcp_gateway",
            name="MCP Security Gateway",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Enforce MCP server attestation, capability-aware routing, "
                "and intent-aware request inspection at the network edge."
            ),
        ),
        FeatureGate(
            key="ent.agent_discovery",
            name="Agent Discovery & Inventory",
            min_tier=CommercialTier.PRO,
            description=(
                "Continuously inventory agents, detect ghost/orphaned agents, "
                "and enforce lifecycle offboarding."
            ),
        ),
        FeatureGate(
            key="ent.enforcement_plane",
            name="Real-Time Enforcement Plane",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Real-time policy guard, agent freeze/unfreeze, and runtime "
                "enforcement of constitutional rules."
            ),
        ),
        FeatureGate(
            key="ent.behavioral_dna",
            name="Behavioral DNA Drift",
            min_tier=CommercialTier.PRO,
            description=(
                "Track per-agent behavioral DNA fingerprints and alert on "
                "permission/behavior drift relative to attested baselines."
            ),
        ),
        FeatureGate(
            key="ent.blast_radius",
            name="Blast Radius Simulator",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Simulate the downstream impact of an agent compromise across "
                "the trust graph."
            ),
        ),
        FeatureGate(
            key="ent.intent_correlation",
            name="Intent Correlation Engine",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Correlate UIS events against attack-playbook signatures to "
                "surface multi-step exploit intent."
            ),
        ),
        FeatureGate(
            key="ent.federation",
            name="Federated Agent Trust",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Cross-organization agent trust establishment, mutual "
                "handshake, and dual-attestation policy enforcement for "
                "agent actions that cross organizational boundaries."
            ),
        ),
    )
}


def get_feature(feature_key: str) -> FeatureGate:
    """
    Look up a gate. Raises ``KeyError`` for unknown keys — callers should
    catch and translate to the appropriate user-facing error.
    """
    try:
        return COMMERCIAL_FEATURES[feature_key]
    except KeyError as exc:
        raise KeyError(f"Unknown commercial feature gate: {feature_key!r}") from exc


def list_features(plan: Plan | str | None = None) -> list[dict[str, Any]]:
    """
    Return the full feature matrix. When ``plan`` is supplied, each row also
    includes an ``entitled`` boolean for that plan's tier.
    """
    rows: list[dict[str, Any]] = []
    tier = tier_for_plan(plan) if plan is not None else None
    for gate in COMMERCIAL_FEATURES.values():
        row = gate.to_dict()
        if tier is not None:
            row["tenant_tier"] = tier.value
            row["entitled"] = _rank(tier) >= _rank(gate.min_tier)
        rows.append(row)
    return rows


# ── Entitlement checks ────────────────────────────────────────────────────────

def is_entitled(plan: Plan | str, feature_key: str) -> bool:
    """
    Pure boolean check. Returns ``False`` for unknown features so a typo in a
    gate key cannot accidentally grant access.
    """
    gate = COMMERCIAL_FEATURES.get(feature_key)
    if gate is None:
        return False
    return _rank(tier_for_plan(plan)) >= _rank(gate.min_tier)


def forbidden_payload(
    *,
    tenant: TenantContext,
    feature_key: str,
    gate: FeatureGate,
    license_state: str | None = None,
) -> dict[str, Any]:
    """
    Build the structured ``detail`` body for a 403 response. The shape is
    stable — the dashboard renders an upsell modal off these fields.
    ``license_state`` is additive: present only when the deny was caused by
    the license cap rather than the billing plan.
    """
    payload: dict[str, Any] = {
        "error": "feature_not_entitled",
        "feature": feature_key,
        "feature_name": gate.name,
        "tenant_id": tenant.tenant_id,
        "tenant_tier": tier_for_plan(tenant.plan).value,
        "required_tier": gate.min_tier.value,
        "message": (
            f"Feature '{gate.name}' requires the {gate.min_tier.value} tier; "
            f"tenant '{tenant.tenant_id}' is on the "
            f"{tier_for_plan(tenant.plan).value} tier."
        ),
        "upgrade_url": "/billing/upgrade",
    }
    if license_state is not None:
        payload["license_state"] = license_state
        payload["message"] += (
            " A valid TokenDNA license key covering this tier is required "
            "(see /api/license/status)."
        )
    return payload


def _license_capped_rank(plan_rank: int, feature_key: str) -> tuple[int, str | None]:
    """
    Apply the signed-license cap to ``plan_rank``.

    Returns ``(effective_rank, license_state)`` where ``license_state`` is
    non-None only when enforcement actively lowered the rank. Any exception in
    the licensing layer fails open to plan-based gating — licensing must never
    take the API down.
    """
    try:
        from modules.product import licensing  # noqa: PLC0415

        mode = licensing.enforcement_mode()
        if mode == "off":
            return plan_rank, None
        # À-la-carte feature grant bypasses the tier ladder entirely.
        if licensing.feature_granted(feature_key):
            return _TIER_RANK[CommercialTier.ENTERPRISE], None
        try:
            lic_rank = _rank(CommercialTier(licensing.licensed_tier()))
        except ValueError:
            lic_rank = _rank(CommercialTier.COMMUNITY)
        if lic_rank >= plan_rank:
            return plan_rank, None
        if mode == "enforce":
            state = str(licensing.status().get("state", "missing"))
            return lic_rank, state
        logger.warning(
            "license warn: plan grants rank %s but license only covers rank %s "
            "(feature=%s); allowing because TOKENDNA_LICENSE_ENFORCEMENT=warn",
            plan_rank, lic_rank, feature_key,
        )
        return plan_rank, None
    except Exception:  # noqa: BLE001
        return plan_rank, None


# ── FastAPI dependency factory ────────────────────────────────────────────────

def require_feature(feature_key: str) -> Callable[..., TenantContext]:
    """
    FastAPI dependency factory.

    Usage — drop-in replacement for ``Depends(get_tenant)``::

        @app.post("/api/simulate/blast_radius")
        async def api_blast_radius(
            body: dict,
            tenant: TenantContext = Depends(require_feature("ent.blast_radius")),
        ):
            ...

    Or as a side-effect dependency on routes that already inject tenant via
    a different dependency (e.g. ``require_role``)::

        @app.post(
            "/api/intent/playbooks",
            dependencies=[Depends(require_feature("ent.intent_correlation"))],
        )
        async def api_intent_add_playbook(
            body: dict,
            tenant: TenantContext = Depends(require_role(Role.ANALYST)),
        ):
            ...

    Behaviour:
      - ``get_tenant`` runs first; auth failures continue to return 401.
      - The tenant's plan tier is capped by the signed license when
        ``TOKENDNA_LICENSE_ENFORCEMENT=enforce`` (see module docstring).
      - If the effective tier is below the gate's ``min_tier``, raises
        ``HTTPException(403)`` with the ``forbidden_payload`` detail.
      - On success returns the resolved ``TenantContext`` (so callers using
        the first form keep working unchanged).

    Unknown feature keys are caught at *dependency-construction* time so a
    typo in a route decorator fails on import rather than at request time.
    """
    gate = get_feature(feature_key)  # KeyError → fast fail at import.

    def _dependency(
        tenant: TenantContext = Depends(get_tenant),
    ) -> TenantContext:
        plan_rank = _rank(tier_for_plan(tenant.plan))
        effective_rank, license_state = _license_capped_rank(plan_rank, feature_key)
        if effective_rank < _rank(gate.min_tier):
            # Staged-rollout override: a tenant may be allowlisted onto a
            # feature without paying for the tier. Lookup is best-effort —
            # if staged_rollout is unavailable, fall through to the 403.
            try:
                from modules.product import staged_rollout  # noqa: PLC0415
                if staged_rollout.is_allowlisted(tenant.tenant_id, feature_key):
                    return tenant
            except Exception:  # noqa: BLE001
                pass
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=forbidden_payload(
                    tenant=tenant,
                    feature_key=feature_key,
                    gate=gate,
                    license_state=license_state,
                ),
            )
        return tenant

    # Friendly repr in OpenAPI / debug logs.
    _dependency.__name__ = f"require_feature[{feature_key}]"
    return _dependency
PYEOF

# ──────────────────────────────────────────────────────────────────────────────
# 3. api_routers/license.py
# ──────────────────────────────────────────────────────────────────────────────
cat > api_routers/license.py <<'PYEOF'
"""License status + activation endpoints.

GET  /api/license/status    — current license state (any authenticated tenant)
POST /api/license/activate  — verify + persist a license key (admin/owner)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from modules.product import licensing
from modules.tenants.middleware import get_tenant
from modules.tenants.models import TenantContext

router = APIRouter(tags=["license"])

# Prefer the platform RBAC dependency when available; fall back to plain
# tenant auth so this router never blocks app startup.
try:  # pragma: no cover - wiring, exercised via app import
    from modules.security.rbac import Role, require_role

    _admin_dependency = require_role(Role.ADMIN)
except Exception:  # noqa: BLE001  pragma: no cover
    _admin_dependency = get_tenant


class ActivateBody(BaseModel):
    license_key: str = Field(..., min_length=10, max_length=8192)


@router.get("/api/license/status")
async def api_license_status(
    tenant: TenantContext = Depends(get_tenant),
) -> dict:
    """Return the current license state, enforcement mode, and granted tier."""
    return licensing.status()


@router.post("/api/license/activate")
async def api_license_activate(
    body: ActivateBody,
    tenant: TenantContext = Depends(_admin_dependency),
) -> dict:
    """Verify a license key and persist it to the configured license file."""
    try:
        lic = licensing.activate(body.license_key)
    except licensing.LicenseError as exc:
        raise HTTPException(status_code=400, detail=f"invalid license: {exc}") from exc
    return {"status": "activated", "license": lic.to_dict()}
PYEOF

# ──────────────────────────────────────────────────────────────────────────────
# 4. api_routers/__init__.py  (full rewrite: + license router)
# ──────────────────────────────────────────────────────────────────────────────
cat > api_routers/__init__.py <<'PYEOF'
"""Route registry for the decomposed API surface (T-1).

api.py is FROZEN (the CI ratchet fails any PR that grows it). New endpoints are
born here, one router per product domain. Routers are appended to ALL_ROUTERS
as domains migrate out of api.py; the route-surface guard keeps the externally
visible surface unchanged. See api_routers/MIGRATION.md.
"""
from __future__ import annotations

import hashlib
import os
import pathlib

from fastapi import APIRouter, FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from api_routers.agents import router as agents_router
from api_routers.assets import router as assets_router
from api_routers.campaigns import router as campaigns_router
from api_routers.certs import router as certs_router
from api_routers.compliance import router as compliance_router
from api_routers.console import router as console_router
from api_routers.delegation import router as delegation_router
from api_routers.demo import router as demo_router
from api_routers.discovery import router as discovery_router
from api_routers.enforcement import router as enforcement_router
from api_routers.enterprise import router as enterprise_router
from api_routers.federation import router as federation_router
from api_routers.identity_surface import router as identity_surface_router
from api_routers.intel import router as intel_router
from api_routers.kill import router as kill_router
from api_routers.license import router as license_router
from api_routers.mcp import router as mcp_router
from api_routers.misc import router as misc_router
from api_routers.passport import router as passport_router
from api_routers.policy_bundles import router as policy_bundles_router
from api_routers.policy_export import router as policy_export_router
from api_routers.policy_guard import router as policy_guard_router
from api_routers.policy_suggestions import router as policy_suggestions_router
from api_routers.product import router as product_router
from api_routers.retrieval import router as retrieval_router
from api_routers.siem import router as siem_router
from api_routers.threat_sharing import router as threat_sharing_router
from api_routers.verifier import router as verifier_router
from api_routers.workflow import router as workflow_router

ALL_ROUTERS: tuple[APIRouter, ...] = (
    agents_router,
    assets_router,
    campaigns_router,
    certs_router,
    compliance_router,
    console_router,
    delegation_router,
    demo_router,
    discovery_router,
    enforcement_router,
    enterprise_router,
    federation_router,
    identity_surface_router,
    intel_router,
    kill_router,
    license_router,
    mcp_router,
    misc_router,
    passport_router,
    policy_bundles_router,
    policy_export_router,
    policy_guard_router,
    policy_suggestions_router,
    product_router,
    retrieval_router,
    siem_router,
    threat_sharing_router,
    verifier_router,
    workflow_router,
)


_STATIC_DIR = pathlib.Path(__file__).resolve().parent.parent / "dashboard" / "static"


class _CachingStatic(StaticFiles):
    """StaticFiles whose cache policy is env-driven.

    * Local dev (default): ``no-store`` so edits to local assets show up on a
      normal reload (paired with versioned ?v= URLs).
    * Production: set ``ASSET_CACHE_SECONDS`` (e.g. 86400) to serve
      ``public, max-age=<n>`` — safe because every asset URL is version-busted.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        secs = int(os.getenv("ASSET_CACHE_SECONDS", "0") or "0")
        if secs > 0:
            response.headers["Cache-Control"] = f"public, max-age={secs}"
        else:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response


# Paths the demo-password gate never blocks (health probes + the login page).
_DEMO_OPEN_PATHS = {"/healthz", "/readyz", "/", "/metrics", "/__demo_login"}
_DEMO_COOKIE = "tdna_demo"


def _demo_token(password: str) -> str:
    return hashlib.sha256(("tokendna-demo::" + password).encode()).hexdigest()


def _demo_login_page(error: bool = False) -> str:
    msg = '<p class="err">Incorrect password.</p>' if error else ""
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>TokenDNA — Demo Access</title><style>"
        "html,body{height:100%;margin:0;background:#070b12;color:#e2e8f0;"
        "font:15px/1.5 ui-sans-serif,system-ui,sans-serif;display:flex;align-items:center;justify-content:center}"
        ".box{background:#0f1622;border:1px solid #1e293b;border-radius:12px;padding:32px 28px;width:320px;text-align:center}"
        ".brand{font-weight:800;font-size:20px;margin-bottom:4px}.brand span{color:#3aa9ff}"
        ".sub{color:#94a3b8;font-size:13px;margin-bottom:20px}"
        "input{width:100%;box-sizing:border-box;background:#0b1220;border:1px solid #1e293b;color:#e2e8f0;"
        "padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:12px}"
        "button{width:100%;background:#3aa9ff;color:#00131f;border:0;padding:10px;border-radius:8px;"
        "font-weight:700;font-size:14px;cursor:pointer}.err{color:#ef4444;font-size:12px;margin:0 0 12px}"
        "</style></head><body><form class=box method=post action=/__demo_login>"
        "<div class=brand>Token<span>DNA</span></div>"
        "<div class=sub>Enter the demo password to continue.</div>"
        f"{msg}"
        "<input type=password name=password placeholder=Password autofocus>"
        "<button type=submit>Enter</button></form></body></html>"
    )


class DemoAuthMiddleware(BaseHTTPMiddleware):
    """Shared-password gate for a public demo. Active only when DEMO_PASSWORD is
    set; otherwise a pure pass-through (local dev stays open). Health probes and
    the login page are always reachable so Railway's healthcheck still passes."""

    def __init__(self, app, password: str):
        super().__init__(app)
        self._token = _demo_token(password)
        self._password = password

    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in _DEMO_OPEN_PATHS and path != "/__demo_login":
            return await call_next(request)
        if path == "/__demo_login":
            if request.method == "POST":
                form = await request.form()
                if form.get("password") == self._password:
                    resp = RedirectResponse(url="/dashboard", status_code=303)
                    resp.set_cookie(_DEMO_COOKIE, self._token, httponly=True, samesite="lax", max_age=86400 * 7)
                    return resp
                return HTMLResponse(_demo_login_page(error=True), status_code=401)
            return HTMLResponse(_demo_login_page())
        if request.cookies.get(_DEMO_COOKIE) == self._token:
            return await call_next(request)
        # Unauthenticated: API/asset calls get 401, navigations get the login page.
        accept = request.headers.get("accept", "")
        if path.startswith("/api/") or path.startswith("/static/") or "text/html" not in accept:
            return Response("authentication required", status_code=401)
        return HTMLResponse(_demo_login_page(), status_code=401)


def mount_all(app: FastAPI) -> None:
    """Mount every registered domain router onto the app (called from api.py).

    Also mounts the locally-vendored dashboard assets (React + the
    dependency-free trust-graph engine) at /static so the dashboard runs fully
    offline with zero third-party CDN requests. A StaticFiles ``Mount`` has no
    ``methods`` attribute, so the route-surface guard skips it.
    """
    for router in ALL_ROUTERS:
        app.include_router(router)
    if _STATIC_DIR.is_dir():
        app.mount("/static", _CachingStatic(directory=str(_STATIC_DIR)), name="static")
    # Optional public-demo password gate (no-op unless DEMO_PASSWORD is set, so
    # local dev stays open). Added last → outermost middleware → gates everything.
    demo_pw = (os.getenv("DEMO_PASSWORD") or "").strip()
    if demo_pw:
        app.add_middleware(DemoAuthMiddleware, password=demo_pw)
PYEOF

# ──────────────────────────────────────────────────────────────────────────────
# 5. scripts/generate_license_keys.py
# ──────────────────────────────────────────────────────────────────────────────
mkdir -p scripts
cat > scripts/generate_license_keys.py <<'PYEOF'
#!/usr/bin/env python3
"""Generate the Ed25519 keypair that signs TokenDNA licenses.

The PRIVATE key stays on the vendor's machine (default ~/.tokendna/) and must
never be committed to any repository. The PUBLIC key is embedded in
modules/product/licensing.py via --inject.

Usage:
    python scripts/generate_license_keys.py                       # generate
    python scripts/generate_license_keys.py --inject modules/product/licensing.py
    python scripts/generate_license_keys.py --show                # print pubkey
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_KEY_PATH = pathlib.Path.home() / ".tokendna" / "license_signing_private.pem"


def load_or_create(path: pathlib.Path, force: bool) -> Ed25519PrivateKey:
    if path.exists() and not force:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 private key")
        print(f"using existing private key: {path}")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600
    print(f"NEW private key written: {path}  (chmod 600 — BACK THIS UP, never commit)")
    return key


def pubkey_hex(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def inject(target: pathlib.Path, hexkey: str) -> None:
    text = target.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r'LICENSE_PUBLIC_KEY_HEX = "[^"]*"',
        f'LICENSE_PUBLIC_KEY_HEX = "{hexkey}"',
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit(f"LICENSE_PUBLIC_KEY_HEX assignment not found in {target}")
    target.write_text(new_text, encoding="utf-8")
    print(f"public key injected into {target}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", type=pathlib.Path, default=DEFAULT_KEY_PATH)
    ap.add_argument("--inject", type=pathlib.Path, default=None,
                    help="path to licensing.py to receive the public key")
    ap.add_argument("--show", action="store_true", help="print public key hex only")
    ap.add_argument("--force", action="store_true", help="overwrite an existing key")
    args = ap.parse_args()

    key = load_or_create(args.key, args.force)
    hexkey = pubkey_hex(key)
    print(f"public key (hex): {hexkey}")
    if args.inject:
        inject(args.inject, hexkey)
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
chmod +x scripts/generate_license_keys.py

# ──────────────────────────────────────────────────────────────────────────────
# 6. tests/test_licensing.py
# ──────────────────────────────────────────────────────────────────────────────
cat > tests/test_licensing.py <<'PYEOF'
"""Unit tests for the signed-license entitlement boundary."""
from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from modules.product import licensing


@pytest.fixture()
def signing_key(monkeypatch, tmp_path):
    """Ephemeral keypair; public half patched into the licensing module.
    Also isolates env/file state so tests never see a real license."""
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    monkeypatch.setattr(licensing, "LICENSE_PUBLIC_KEY_HEX", pub_hex)
    monkeypatch.delenv("TOKENDNA_LICENSE_KEY", raising=False)
    monkeypatch.delenv("TOKENDNA_LICENSE_ENFORCEMENT", raising=False)
    monkeypatch.setenv("TOKENDNA_LICENSE_FILE", str(tmp_path / "license.key"))
    licensing.reload()
    yield key
    licensing.reload()


def make_key(
    key: Ed25519PrivateKey,
    *,
    tier: str = "enterprise",
    exp_delta: int = 3600,
    features: tuple[str, ...] = (),
) -> str:
    now = int(time.time())
    payload = {
        "lid": "L-TEST-1",
        "sub": "cus_test123",
        "org": "TestCo",
        "tier": tier,
        "features": list(features),
        "iat": now,
        "exp": now + exp_delta,
    }
    payload_b64 = licensing._b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    sig = key.sign(f"{licensing.LICENSE_PREFIX}.{payload_b64}".encode("ascii"))
    return f"{licensing.LICENSE_PREFIX}.{payload_b64}.{licensing._b64url_encode(sig)}"


def test_valid_license_parses(signing_key):
    lic = licensing.parse_and_verify(make_key(signing_key, tier="pro"))
    assert lic.tier == "pro"
    assert lic.customer == "cus_test123"
    assert not lic.is_expired()


def test_tampered_payload_rejected(signing_key):
    raw = make_key(signing_key)
    prefix, payload_b64, sig_b64 = raw.split(".")
    forged = json.loads(licensing._b64url_decode(payload_b64))
    forged["tier"] = "enterprise"
    forged["exp"] = int(time.time()) + 10**9
    forged_b64 = licensing._b64url_encode(
        json.dumps(forged, separators=(",", ":")).encode()
    )
    with pytest.raises(licensing.LicenseError):
        licensing.parse_and_verify(f"{prefix}.{forged_b64}.{sig_b64}")


def test_expired_license_rejected(signing_key):
    with pytest.raises(licensing.LicenseError, match="expired"):
        licensing.parse_and_verify(make_key(signing_key, exp_delta=-10))


def test_wrong_key_rejected(signing_key):
    other = Ed25519PrivateKey.generate()
    with pytest.raises(licensing.LicenseError):
        licensing.parse_and_verify(make_key(other))


def test_malformed_key_rejected(signing_key):
    for bad in ("", "TDNA1", "TDNA1.abc", "NOPE.abc.def", "TDNA1.!!!.???"):
        with pytest.raises(licensing.LicenseError):
            licensing.parse_and_verify(bad)


def test_enforcement_defaults_off(signing_key):
    assert licensing.enforcement_mode() == "off"


def test_enforce_without_license_grants_community(signing_key, monkeypatch):
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    licensing.reload()
    assert licensing.enforcement_mode() == "enforce"
    assert licensing.licensed_tier() == "community"
    assert licensing.get_license() is None
    assert licensing.status()["state"] == "missing"


def test_enforce_with_license_grants_tier(signing_key, monkeypatch):
    raw = make_key(signing_key, tier="enterprise", features=("ent.blast_radius",))
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    monkeypatch.setenv("TOKENDNA_LICENSE_KEY", raw)
    licensing.reload()
    assert licensing.licensed_tier() == "enterprise"
    assert licensing.feature_granted("ent.blast_radius")
    assert not licensing.feature_granted("ent.mcp_gateway")
    assert licensing.status()["state"] == "valid"


def test_activate_persists_to_file(signing_key, monkeypatch, tmp_path):
    target = tmp_path / "license.key"
    monkeypatch.setenv("TOKENDNA_LICENSE_FILE", str(target))
    raw = make_key(signing_key, tier="pro")
    lic = licensing.activate(raw)
    assert lic.tier == "pro"
    assert target.read_text().strip() == raw
    licensing.reload()
    assert licensing.licensed_tier() == "pro"


def test_license_cap_applies_in_require_feature(signing_key, monkeypatch):
    """enforce + no license => enterprise-plan tenant loses ent.* access."""
    from modules.product import commercial_tiers as ct

    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.COMMUNITY]
    assert state == "missing"

    # With a valid enterprise license the cap lifts.
    monkeypatch.setenv(
        "TOKENDNA_LICENSE_KEY", make_key(signing_key, tier="enterprise")
    )
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.ENTERPRISE]
    assert state is None

    # Mode off => never caps (back-compat default).
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "off")
    monkeypatch.delenv("TOKENDNA_LICENSE_KEY", raising=False)
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.ENTERPRISE]
    assert state is None
PYEOF

# ──────────────────────────────────────────────────────────────────────────────
# 7. docs/LICENSING.md
# ──────────────────────────────────────────────────────────────────────────────
mkdir -p docs
cat > docs/LICENSING.md <<'MDEOF'
# TokenDNA Commercial Licensing

TokenDNA is source-available under BUSL-1.1. The core runtime (UIS
normalization, attestation, basic policy bundles, token integrity) is free to
use. The enterprise capabilities — the `ent.*` gates: Blast Radius, the
Real-Time Enforcement Plane, Intent Correlation, the MCP Security Gateway,
Behavioral DNA drift, and Federated Agent Trust — require a commercial
license key tied to an active subscription.

## How it works

A license key is an Ed25519-signed payload issued by the TokenDNA license
service when a Stripe subscription is created:

    TDNA1.<base64url payload>.<base64url signature>

Only the public key ships in this repository
(`modules/product/licensing.py`). Verification is offline; TokenDNA never
phones home. The payload carries your Stripe customer id, granted tier,
optional à-la-carte features, and expiry (subscription period end plus a
grace window).

## Activating a license

Any one of:

1. Environment: `TOKENDNA_LICENSE_KEY=TDNA1...`
2. File: write the key to the path in `TOKENDNA_LICENSE_FILE`
   (default `./license.key`)
3. API: `POST /api/license/activate` with `{"license_key": "TDNA1..."}`
   (admin/owner role)

Check state at any time: `GET /api/license/status`.

## Enforcement modes (`TOKENDNA_LICENSE_ENFORCEMENT`)

| Mode | Behavior |
|---|---|
| `off` (default) | Plan-based gating only. Dev, CI, and demos are unaffected. |
| `warn` | Logs when the tenant plan exceeds the license, but allows. |
| `enforce` | The license caps the effective commercial tier. Use in production. |

Production deployments should set `TOKENDNA_LICENSE_ENFORCEMENT=enforce`.

## FAQ

**Can't a self-hoster just patch the check out?** Technically yes — the repo
is public. The gate is a compliance boundary, not DRM. Commercial use of the
enterprise features without a license violates the BUSL-1.1 terms; the
signed key is what makes honest commercial use frictionless and auditable.

**Does the license expire when my subscription lapses?** Keys are issued
with an expiry of your current billing period end plus a grace window, and
re-issued on renewal. If your subscription cancels, the current key simply
expires.

**Trials?** `DEV_MODE=true` (which additionally requires
`TOKENDNA_ENV=dev` or another recognized development environment — DEV_MODE
is deny-by-default outside dev contexts) runs everything unrestricted for
local evaluation, and time-boxed trial keys can be issued on request.
MDEOF

# ──────────────────────────────────────────────────────────────────────────────
# 8. .env.example additions
# ──────────────────────────────────────────────────────────────────────────────
cat >> .env.example <<'ENVEOF'

# ── Commercial licensing (open-core entitlement boundary) ────────────────────
# off (default) | warn | enforce — production should use enforce.
TOKENDNA_LICENSE_ENFORCEMENT=off
# Provide the license via env...
# TOKENDNA_LICENSE_KEY=TDNA1....
# ...or via file (default ./license.key):
# TOKENDNA_LICENSE_FILE=/etc/tokendna/license.key
ENVEOF

# ──────────────────────────────────────────────────────────────────────────────
# 9. Generate YOUR signing keypair and inject the public key
# ──────────────────────────────────────────────────────────────────────────────
python3 scripts/generate_license_keys.py --inject modules/product/licensing.py

# ──────────────────────────────────────────────────────────────────────────────
# 10. Re-baseline the CI route-surface snapshot (2 new endpoints), run tests
# ──────────────────────────────────────────────────────────────────────────────
# NOTE (post-#140): the route guard sets DEV_MODE=true internally, and config.py
# now hard-exits when DEV_MODE is active without a recognized dev environment.
# TOKENDNA_ENV=ci satisfies the deny-by-default guard, matching ci.yml.
TOKENDNA_ENV=ci python3 scripts/ci/openapi_route_guard.py --update
python3 -m pytest -q tests/test_licensing.py

# Optional but recommended before committing: full local sanity (matches CI)
# make test

git add modules/product/licensing.py modules/product/commercial_tiers.py \
        api_routers/license.py api_routers/__init__.py \
        scripts/generate_license_keys.py tests/test_licensing.py \
        docs/LICENSING.md .env.example scripts/ci/openapi_routes.json

git commit -m "feat: Ed25519 signed-license entitlement boundary for ent.* features

- modules/product/licensing.py: offline license verification (TDNA1 format),
  env/file loading, cached state, activate/persist, status surface
- commercial_tiers: license caps effective tier when
  TOKENDNA_LICENSE_ENFORCEMENT=enforce (default off — fully back-compat);
  a-la-carte ent.* feature grants supported
- api_routers/license.py: GET /api/license/status, POST /api/license/activate
- scripts/generate_license_keys.py: vendor keypair generation + pubkey inject
- tests/test_licensing.py: signature, tamper, expiry, cap semantics
- docs/LICENSING.md + .env.example: operator documentation
- route-surface snapshot re-baselined for the two new endpoints

Licenses are issued by the private license service from Stripe subscription
events; only the public key ships in this repo."

echo ""
echo "=============================================================="
echo " Done. Review the diff, then push:"
echo "     git push -u origin feat/stripe-license-gating"
echo ""
echo " Your PRIVATE signing key: ~/.tokendna/license_signing_private.pem"
echo " -> Back it up now. Never commit it. Never share it."
echo ""
echo " Next: run tokendna_license_server_install.sh to scaffold the"
echo " PRIVATE Stripe-driven license service."
echo "=============================================================="
