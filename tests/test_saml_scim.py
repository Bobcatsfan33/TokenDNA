from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auth import saml, scim


# ── SAML unit tests ───────────────────────────────────────────────────────────


def test_saml_metadata_contains_sp_entity(monkeypatch):
    monkeypatch.setenv("SAML_SP_ENTITY_ID", "https://test.tokendna/sp")
    monkeypatch.setenv("SAML_SP_ACS_URL", "https://test.tokendna/saml/acs")
    cfg = saml.SAMLConfig.from_env()
    xml = saml.generate_metadata(cfg)
    assert "https://test.tokendna/sp" in xml
    assert "https://test.tokendna/saml/acs" in xml
    assert "WantAssertionsSigned=\"true\"" in xml


def test_saml_authn_request_requires_idp_url(monkeypatch):
    monkeypatch.delenv("SAML_IDP_SSO_URL", raising=False)
    cfg = saml.SAMLConfig.from_env()
    with pytest.raises(saml.SAMLError):
        saml.build_authn_request(cfg)


def test_saml_authn_request_emits_redirect_url(monkeypatch):
    monkeypatch.setenv("SAML_SP_ENTITY_ID", "https://test/sp")
    monkeypatch.setenv("SAML_SP_ACS_URL", "https://test/acs")
    monkeypatch.setenv("SAML_IDP_SSO_URL", "https://idp.example/sso")
    cfg = saml.SAMLConfig.from_env()
    req = saml.build_authn_request(cfg, relay_state="rs-fixed")
    assert req.relay_state == "rs-fixed"
    assert req.redirect_url.startswith("https://idp.example/sso?SAMLRequest=")
    assert "RelayState=rs-fixed" in req.redirect_url
    assert req.request_id.startswith("_")


def test_saml_parse_assertion_refuses_without_cert(monkeypatch):
    monkeypatch.delenv("SAML_IDP_X509_CERT", raising=False)
    cfg = saml.SAMLConfig.from_env()
    with pytest.raises(saml.SAMLError):
        saml.parse_assertion("base64-blob", cfg)


# ── SCIM unit tests ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _scim_clean():
    scim._reset_for_tests()
    yield
    scim._reset_for_tests()


def test_scim_create_user_minimal():
    user = scim.create_user(
        {"schemas": [scim.SCHEMA_USER], "userName": "alice@example.com", "active": True},
        tenant_id="t-1",
    )
    assert user["userName"] == "alice@example.com"
    assert user["active"] is True
    assert "tenant_id" not in user
    assert user["meta"]["resourceType"] == "User"


def test_scim_create_user_rejects_missing_username():
    with pytest.raises(scim.SCIMError) as exc:
        scim.create_user({"schemas": [scim.SCHEMA_USER]}, tenant_id="t-1")
    assert exc.value.status == 400


def test_scim_create_user_rejects_duplicate_username():
    payload = {"schemas": [scim.SCHEMA_USER], "userName": "alice@example.com"}
    scim.create_user(payload, tenant_id="t-1")
    with pytest.raises(scim.SCIMError) as exc:
        scim.create_user(payload, tenant_id="t-1")
    assert exc.value.status == 409


def test_scim_user_isolation_across_tenants():
    payload = {"schemas": [scim.SCHEMA_USER], "userName": "alice@example.com"}
    a = scim.create_user(payload, tenant_id="t-A")
    b = scim.create_user(payload, tenant_id="t-B")
    assert a["id"] != b["id"]
    with pytest.raises(scim.SCIMError):
        scim.get_user(a["id"], tenant_id="t-B")


def test_scim_replace_and_delete_user():
    payload = {"schemas": [scim.SCHEMA_USER], "userName": "alice@example.com"}
    user = scim.create_user(payload, tenant_id="t-1")
    updated = scim.replace_user(
        user["id"],
        {"userName": "alice@example.com", "active": False},
        tenant_id="t-1",
    )
    assert updated["active"] is False
    scim.delete_user(user["id"], tenant_id="t-1")
    with pytest.raises(scim.SCIMError):
        scim.get_user(user["id"], tenant_id="t-1")


def test_scim_list_users_pagination():
    for i in range(5):
        scim.create_user(
            {"schemas": [scim.SCHEMA_USER], "userName": f"u{i}@example.com"},
            tenant_id="t-1",
        )
    page = scim.list_users(tenant_id="t-1", start_index=2, count=2)
    assert page["totalResults"] == 5
    assert len(page["Resources"]) == 2
    assert page["startIndex"] == 2


def test_scim_create_group_and_lookup():
    g = scim.create_group(
        {"schemas": [scim.SCHEMA_GROUP], "displayName": "engineers"},
        tenant_id="t-1",
    )
    assert g["displayName"] == "engineers"
    fetched = scim.get_group(g["id"], tenant_id="t-1")
    assert fetched["id"] == g["id"]


def test_scim_service_provider_config_advertises_bearer():
    cfg = scim.service_provider_config()
    schemes = cfg.get("authenticationSchemes", [])
    assert any(s["type"] == "oauthbearertoken" for s in schemes)


# ── SAML / SCIM route smoke tests ─────────────────────────────────────────────


@pytest.fixture()
def api_client():
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext
    import api as api_module

    tenant = TenantContext(
        tenant_id="t-saml-test",
        tenant_name="SAMLTest",
        plan=Plan.ENTERPRISE,
        api_key_id="k",
        role="owner",
    )

    def _override():
        return tenant

    api_module.app.dependency_overrides[get_tenant] = _override
    yield TestClient(api_module.app, raise_server_exceptions=True)
    api_module.app.dependency_overrides.clear()


def test_saml_metadata_route(api_client):
    r = api_client.get("/saml/metadata")
    assert r.status_code == 200
    assert "EntityDescriptor" in r.text


def test_saml_login_returns_503_without_idp(api_client, monkeypatch):
    monkeypatch.delenv("SAML_IDP_SSO_URL", raising=False)
    r = api_client.get("/saml/login")
    assert r.status_code == 503


def test_scim_spc_route(api_client):
    r = api_client.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/scim+json")
    body = r.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True


def test_scim_patch_user_via_route(api_client):
    create = api_client.post(
        "/scim/v2/Users",
        json={"schemas": [scim.SCHEMA_USER], "userName": "patch@example.com", "active": True},
    )
    user_id = create.json()["id"]

    patch = api_client.patch(
        f"/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert patch.status_code == 200
    assert patch.json()["active"] is False


def test_scim_patch_unsupported_filtered_path_returns_501(api_client):
    create = api_client.post(
        "/scim/v2/Users",
        json={"schemas": [scim.SCHEMA_USER], "userName": "filt@example.com"},
    )
    user_id = create.json()["id"]
    r = api_client.patch(
        f"/scim/v2/Users/{user_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": 'emails[type eq "work"].value', "value": "x"}],
        },
    )
    assert r.status_code == 501


def test_scim_filter_via_list_route(api_client):
    for name in ("alpha@example.com", "bravo@example.com", "charlie@other.com"):
        api_client.post(
            "/scim/v2/Users",
            json={"schemas": [scim.SCHEMA_USER], "userName": name},
        )
    r = api_client.get('/scim/v2/Users', params={"filter": 'userName ew "@example.com"'})
    assert r.status_code == 200
    body = r.json()
    names = {u["userName"] for u in body["Resources"]}
    assert "alpha@example.com" in names
    assert "bravo@example.com" in names
    assert "charlie@other.com" not in names


def test_scim_filter_invalid_returns_400(api_client):
    r = api_client.get('/scim/v2/Users', params={"filter": 'userName eq'})
    assert r.status_code == 400
    body = r.json()
    assert body.get("scimType") == "invalidFilter"


def test_scim_user_lifecycle_via_routes(api_client):
    create_resp = api_client.post(
        "/scim/v2/Users",
        json={"schemas": [scim.SCHEMA_USER], "userName": "alice@example.com"},
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]

    get_resp = api_client.get(f"/scim/v2/Users/{user_id}")
    assert get_resp.status_code == 200

    list_resp = api_client.get("/scim/v2/Users")
    assert list_resp.status_code == 200
    assert list_resp.json()["totalResults"] >= 1

    del_resp = api_client.delete(f"/scim/v2/Users/{user_id}")
    assert del_resp.status_code == 204
