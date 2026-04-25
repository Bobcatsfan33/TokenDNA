"""Static structural tests for the Helm chart and plain-k8s manifests.

These do not invoke Helm (which may not be installed). They verify that
the chart files exist with the correct shape and that key hardening
defaults are present in values.yaml.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_CHART = _REPO / "deploy" / "helm" / "tokendna"
_K8S = _REPO / "deploy" / "k8s"


def test_chart_structure_exists():
    assert (_CHART / "Chart.yaml").exists()
    assert (_CHART / "values.yaml").exists()
    assert (_CHART / "templates" / "_helpers.tpl").exists()
    assert (_CHART / "templates" / "deployment.yaml").exists()
    assert (_CHART / "templates" / "service.yaml").exists()
    assert (_CHART / "templates" / "hpa.yaml").exists()
    assert (_CHART / "templates" / "pdb.yaml").exists()
    assert (_CHART / "templates" / "networkpolicy.yaml").exists()
    assert (_CHART / "templates" / "migration-job.yaml").exists()


def test_values_enforces_production_defaults():
    body = (_CHART / "values.yaml").read_text()
    assert "TOKENDNA_ENV: production" in body
    assert "DEV_MODE: \"false\"" in body
    assert "DATA_BACKEND: postgres" in body
    assert "runAsNonRoot: true" in body
    assert "readOnlyRootFilesystem: true" in body
    assert "allowPrivilegeEscalation: false" in body


def test_values_does_not_inline_secrets():
    body = (_CHART / "values.yaml").read_text()
    # No secret values should appear in tracked yaml.
    forbidden = (
        "dev-delegation-secret",
        "dev-workflow-secret",
        "dev-honeypot-secret",
        "dev-posture-secret",
    )
    for marker in forbidden:
        assert marker not in body


def test_deployment_template_uses_existing_secret():
    body = (_CHART / "templates" / "deployment.yaml").read_text()
    assert "secretRef" in body
    assert ".Values.secrets.existingSecret" in body


def test_migration_job_runs_alembic_upgrade_head():
    body = (_CHART / "templates" / "migration-job.yaml").read_text()
    assert "alembic" in body
    assert "upgrade" in body
    assert "head" in body
    assert '"helm.sh/hook": pre-install,pre-upgrade' in body


def test_plain_k8s_manifests_exist():
    assert (_K8S / "deployment.yaml").exists()
    assert (_K8S / "service.yaml").exists()
    assert (_K8S / "README.md").exists()


def test_plain_k8s_deployment_has_health_probes():
    body = (_K8S / "deployment.yaml").read_text()
    assert "/healthz" in body
    assert "/readyz" in body
    assert "readOnlyRootFilesystem: true" in body
    assert "runAsNonRoot: true" in body
