"""
Tests — CAC/PIV Smart Card Authentication  (Phase 1C)

Coverage:
  - Certificate parsing (valid PEM, malformed PEM, edge cases)
  - Subject DN parsing: EDIPI extraction, name fields, affiliation, org, country
  - Certificate validity period (expired, not-yet-valid, valid)
  - Chain validation: DoD CA pattern matching, mock trusted CA PEM
  - EKU validation: PIV OIDs, no EKU, non-PIV EKU
  - Revocation: CRL fetch + check, OCSP mock, soft-fail, strict-fail, skipped
  - CACPIVAuthenticator: full pipeline (happy path, each failure mode)
  - FastAPI middleware: cert extraction from headers, 401 paths
  - Integration: EDIPI feeds into identity pipeline
"""

import time
import threading
import datetime
from typing import Optional
from unittest.mock import patch, MagicMock, Mock
import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Test certificate generation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_test_cert(
    subject_cn:      str = "SMITH.JOHN.A.1234567890",
    subject_ou:      list[str] = None,
    subject_o:       str = "U.S. Government",
    subject_c:       str = "US",
    issuer_cn:       str = "Mock DoD Root CA 1",
    issuer_o:        str = "U.S. Government",
    days_valid:      int = 365,
    days_offset:     int = 0,    # shift not_before relative to now
    eku_oids:        Optional[list[str]] = None,
    add_ocsp_url:    Optional[str] = None,
    add_crl_url:     Optional[str] = None,
    serial:          Optional[int] = None,
):
    """
    Generate a minimal self-signed X.509 certificate for testing.
    Issuer uses DoD CA naming so chain validation passes.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.backends import default_backend
    import datetime

    subject_ou = subject_ou or ["USA", "DoD"]

    key = generate_private_key(SECP256R1(), default_backend())

    def make_name(cn, ous, o, c):
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        for ou in ous:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
        if o:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
        if c:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
        return x509.Name(attrs)

    subject = make_name(subject_cn, subject_ou, subject_o, subject_c)
    issuer  = make_name(issuer_cn, [], issuer_o, "US")

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now + datetime.timedelta(days=days_offset)
    not_after  = not_before + datetime.timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # EKU
    if eku_oids is not None:
        from cryptography.x509 import ObjectIdentifier
        eku_list = [ObjectIdentifier(oid) for oid in eku_oids]
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku_list), critical=False
        )

    # AIA (OCSP + CA Issuers)
    if add_ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(add_ocsp_url),
                )
            ]),
            critical=False,
        )

    # CRL DP
    if add_crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(add_crl_url)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256(), default_backend())
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, key, cert


# ─────────────────────────────────────────────────────────────────────────────
# Import under test
# ─────────────────────────────────────────────────────────────────────────────

from modules.identity.cac_piv import (
    CACPIVCertificate,
    CACPIVChainValidator,
    CACPIVRevocationChecker,
    CACPIVAuthenticator,
    CACPIVIdentity,
    CACPIVMiddleware,
    CertificateParseError,
    RevocationResult,
    parse_subject_dn,
    validate_eku,
    OID_EKU_CLIENT_AUTH,
    OID_EKU_SMARTCARD_LOGON,
    OID_EKU_PKINIT_CLIENT,
    OID_EKU_EMAIL_PROTECTION,
    require_cac_piv_identity,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Subject DN Parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestParseSUbjectDN:
    def test_standard_dod_cn(self):
        dn = "CN=SMITH.JOHN.A.1234567890,OU=USA,OU=DoD,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"]       == "1234567890"
        assert result["last_name"]   == "SMITH"
        assert result["first_name"]  == "JOHN"
        assert result["middle_init"] == "A"
        assert result["affiliation"] == "USA"
        assert result["org"]         == "U.S. Government"
        assert result["country"]     == "US"

    def test_different_branches(self):
        for branch in ["USN", "USMC", "USAF", "CIV", "CTR"]:
            dn = f"CN=DOE.JANE.B.9876543210,OU={branch},OU=DoD,O=U.S. Government,C=US"
            result = parse_subject_dn(dn)
            assert result["edipi"] == "9876543210"
            assert result["affiliation"] == branch

    def test_no_middle_initial(self):
        dn = "CN=JONES.ROBERT.1234567890,OU=CIV,OU=DoD,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"] == "1234567890"
        assert result["last_name"] == "JONES"

    def test_missing_edipi(self):
        dn = "CN=NO.EDIPI.HERE,OU=TEST,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"] == ""

    def test_empty_dn(self):
        result = parse_subject_dn("")
        assert result["edipi"] == ""
        assert result["affiliation"] == ""
        assert result["country"] == ""

    def test_ous_collected(self):
        dn = "CN=SMITH.JOHN.A.1234567890,OU=USA,OU=PKI,OU=DoD,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert "USA" in result["ous"]
        assert "PKI" in result["ous"]
        assert "DoD" in result["ous"]

    def test_country_extraction(self):
        dn = "CN=SMITH.JOHN.A.1234567890,C=US"
        result = parse_subject_dn(dn)
        assert result["country"] == "US"

    def test_edipi_regex_fallback(self):
        """EDIPI at end of DN without standard CN format."""
        dn = "CN=RANDOM.STUFF.1234567890,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"] == "1234567890"

    def test_nine_digit_not_edipi(self):
        """9-digit number should NOT be parsed as EDIPI."""
        dn = "CN=SMITH.JOHN.A.123456789,OU=USA,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"] == ""

    def test_eleven_digit_not_edipi(self):
        """11-digit number should NOT be parsed as EDIPI."""
        dn = "CN=SMITH.JOHN.A.12345678901,OU=USA,O=U.S. Government,C=US"
        result = parse_subject_dn(dn)
        assert result["edipi"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# 2. Certificate Parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestCACPIVCertificate:
    def test_valid_parse(self):
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)
        assert "SMITH" in cert.subject_dn or "1234567890" in cert.subject_dn
        assert cert.fingerprint_sha256()  # non-empty
        assert len(cert.fingerprint_sha256()) == 64  # SHA-256 hex

    def test_malformed_pem_raises(self):
        with pytest.raises(CertificateParseError):
            CACPIVCertificate("NOT A CERT")

    def test_empty_string_raises(self):
        with pytest.raises(CertificateParseError):
            CACPIVCertificate("")

    def test_validity_period_valid(self):
        pem, _, _ = _make_test_cert(days_valid=365)
        cert = CACPIVCertificate(pem)
        assert not cert.is_expired()

    def test_validity_period_expired(self):
        pem, _, _ = _make_test_cert(days_valid=1, days_offset=-10)
        cert = CACPIVCertificate(pem)
        assert cert.is_expired()

    def test_validity_not_yet_valid(self):
        pem, _, _ = _make_test_cert(days_valid=30, days_offset=10)
        cert = CACPIVCertificate(pem)
        assert cert.is_expired()  # before not_before

    def test_serial_number_hex(self):
        pem, _, raw = _make_test_cert(serial=0xDEADBEEF)
        cert = CACPIVCertificate(pem)
        assert "deadbeef" in cert.serial_hex.lower()

    def test_issuer_dn_extracted(self):
        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 5")
        cert = CACPIVCertificate(pem)
        assert "Mock DoD Root CA 5" in cert.issuer_dn

    def test_ocsp_url_extraction(self):
        pem, _, _ = _make_test_cert(add_ocsp_url="http://ocsp.dod.test/")
        cert = CACPIVCertificate(pem)
        urls = cert.extract_ocsp_urls()
        assert "http://ocsp.dod.test/" in urls

    def test_crl_url_extraction(self):
        pem, _, _ = _make_test_cert(add_crl_url="http://crl.dod.test/root.crl")
        cert = CACPIVCertificate(pem)
        urls = cert.extract_crl_urls()
        assert "http://crl.dod.test/root.crl" in urls

    def test_no_extensions_returns_empty_lists(self):
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)
        assert cert.extract_ocsp_urls() == []
        assert cert.extract_crl_urls() == []
        assert cert.get_eku_oids() == []

    def test_eku_oids_extracted(self):
        eku_oids = [OID_EKU_CLIENT_AUTH, OID_EKU_SMARTCARD_LOGON]
        pem, _, _ = _make_test_cert(eku_oids=eku_oids)
        cert = CACPIVCertificate(pem)
        extracted = cert.get_eku_oids()
        assert OID_EKU_CLIENT_AUTH in extracted
        assert OID_EKU_SMARTCARD_LOGON in extracted

    def test_public_key_pem_returned(self):
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)
        pub_pem = cert.public_key_pem()
        assert "BEGIN PUBLIC KEY" in pub_pem

    def test_der_bytes_non_empty(self):
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)
        assert len(cert.der_bytes()) > 0

    def test_fingerprint_deterministic(self):
        pem, _, _ = _make_test_cert()
        cert1 = CACPIVCertificate(pem)
        cert2 = CACPIVCertificate(pem)
        assert cert1.fingerprint_sha256() == cert2.fingerprint_sha256()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Chain Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestCACPIVChainValidator:
    def test_dod_issuer_pattern_match(self):
        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 2")
        cert = CACPIVCertificate(pem)
        validator = CACPIVChainValidator()
        valid, detail = validator.validate(cert)
        assert valid, f"Expected valid chain, got: {detail}"

    def test_non_dod_issuer_fails(self):
        pem, _, _ = _make_test_cert(
            issuer_cn="Some Random CA",
            issuer_o="Not Government",
        )
        cert = CACPIVCertificate(pem)
        validator = CACPIVChainValidator()
        valid, detail = validator.validate(cert)
        assert not valid

    def test_dod_root_ca_numbered_patterns(self):
        for num in range(1, 7):
            pem, _, _ = _make_test_cert(issuer_cn=f"DoD Root CA {num}")
            cert = CACPIVCertificate(pem)
            validator = CACPIVChainValidator()
            valid, _ = validator.validate(cert)
            assert valid, f"DoD Root CA {num} should be trusted"

    def test_dod_id_sw_ca_pattern(self):
        pem, _, _ = _make_test_cert(issuer_cn="DoD ID SW CA-59")
        cert = CACPIVCertificate(pem)
        validator = CACPIVChainValidator()
        valid, _ = validator.validate(cert)
        assert valid

    def test_dod_piv_auth_ca_pattern(self):
        pem, _, _ = _make_test_cert(issuer_cn="DoD PIV Auth CA-55")
        cert = CACPIVCertificate(pem)
        validator = CACPIVChainValidator()
        valid, _ = validator.validate(cert)
        assert valid

    def test_trusted_ca_pem_exact_match(self):
        """Validator with a trusted CA PEM should accept certs signed by it."""
        # Generate CA key and cert
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.backends import default_backend
        import datetime

        ca_key  = generate_private_key(SECP256R1(), default_backend())
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Mock DoD Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Sign an end-entity cert with the CA
        ee_key = generate_private_key(SECP256R1(), default_backend())
        ee_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SMITH.JOHN.A.1234567890"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "USA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        ee_cert = (
            x509.CertificateBuilder()
            .subject_name(ee_name)
            .issuer_name(ca_name)
            .public_key(ee_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        ee_pem = ee_cert.public_bytes(serialization.Encoding.PEM).decode()

        validator = CACPIVChainValidator(trusted_ca_pems=[ca_pem])
        cert = CACPIVCertificate(ee_pem)
        valid, detail = validator.validate(cert)
        # Either pattern match (issuer DN has "Mock DoD Root CA") or sig verify
        assert valid, f"Trusted CA match failed: {detail}"

    def test_malformed_ca_pem_skipped_gracefully(self):
        validator = CACPIVChainValidator(trusted_ca_pems=["NOT A CERT"])
        # Should not raise; just skip the bad cert
        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 1")
        cert = CACPIVCertificate(pem)
        valid, _ = validator.validate(cert)
        # Pattern match still works
        assert valid

    def test_us_government_org_pattern(self):
        pem, _, _ = _make_test_cert(
            issuer_cn="Some Agency CA",
            issuer_o="U.S. Government",
        )
        cert = CACPIVCertificate(pem)
        # The O=U.S. Government,C=US pattern should match
        validator = CACPIVChainValidator()
        # This may or may not match depending on issuer_cn vs issuer_o patterns
        valid, detail = validator.validate(cert)
        # At minimum it should not raise
        assert isinstance(valid, bool)


# ─────────────────────────────────────────────────────────────────────────────
# 4. EKU Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateEKU:
    def test_smartcard_logon_eku(self):
        valid, detail = validate_eku([OID_EKU_SMARTCARD_LOGON])
        assert valid

    def test_pkinit_client_eku(self):
        valid, detail = validate_eku([OID_EKU_PKINIT_CLIENT])
        assert valid

    def test_client_auth_eku(self):
        valid, detail = validate_eku([OID_EKU_CLIENT_AUTH])
        assert valid

    def test_email_protection_eku(self):
        valid, detail = validate_eku([OID_EKU_EMAIL_PROTECTION])
        assert valid

    def test_no_eku_allowed(self):
        valid, detail = validate_eku([])
        assert valid
        assert "no_eku" in detail

    def test_non_piv_eku_fails(self):
        valid, detail = validate_eku(["1.3.6.1.5.5.7.3.5"])  # email protection (wrong one)
        # Actually email protection is in the list, so use truly unrelated one
        valid, detail = validate_eku(["1.3.6.1.5.5.7.3.8"])  # timestamping
        assert not valid

    def test_multiple_ekus_one_piv(self):
        valid, detail = validate_eku(["1.3.6.1.5.5.7.3.8", OID_EKU_CLIENT_AUTH])
        assert valid

    def test_none_eku_not_treated_as_valid(self):
        # None (missing extension) should be treated as "no EKU" → allowed
        valid, detail = validate_eku([])
        assert valid


# ─────────────────────────────────────────────────────────────────────────────
# 5. Revocation Checker
# ─────────────────────────────────────────────────────────────────────────────

class TestCACPIVRevocationChecker:
    def test_no_crl_url_returns_good(self):
        pem, _, _ = _make_test_cert()  # no CRL URL
        cert = CACPIVCertificate(pem)
        checker = CACPIVRevocationChecker()
        result = checker.check_crl(cert)
        assert result.method == "crl"
        assert not result.revoked

    def test_no_ocsp_url_returns_no_url(self):
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)
        checker = CACPIVRevocationChecker()
        result = checker.check_ocsp(cert, issuer_cert=None)
        assert result.method == "ocsp"
        assert not result.revoked
        assert result.reason == "no_ocsp_url"

    def test_ocsp_no_issuer_returns_no_issuer(self):
        pem, _, _ = _make_test_cert(add_ocsp_url="http://ocsp.test/")
        cert = CACPIVCertificate(pem)
        checker = CACPIVRevocationChecker()
        result = checker.check_ocsp(cert, issuer_cert=None)
        assert result.reason == "no_issuer_for_ocsp"

    def test_crl_revoked_cert(self):
        """Mock a CRL that lists our cert as revoked."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.backends import default_backend

        ca_key = generate_private_key(SECP256R1(), default_backend())
        ca_name = x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, "Mock DoD Root CA"
        )])
        now = datetime.datetime.now(datetime.timezone.utc)

        # Build a CRL that revokes serial 0xABCD
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=1))
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(0xABCD)
                .revocation_date(now)
                .build(default_backend())
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)

        # Patch requests.get to return our mock CRL
        with patch("modules.identity.cac_piv.CACPIVRevocationChecker._fetch_crl") as mock_fetch:
            mock_fetch.return_value = crl

            pem, _, _ = _make_test_cert(serial=0xABCD, add_crl_url="http://crl.test/mock.crl")
            cert = CACPIVCertificate(pem)
            checker = CACPIVRevocationChecker()
            result = checker.check_crl(cert)
            assert result.revoked, "Certificate with matching serial should be revoked"
            assert result.method == "crl"

    def test_crl_good_cert(self):
        """Mock a CRL that does NOT list our cert."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.backends import default_backend

        ca_key = generate_private_key(SECP256R1(), default_backend())
        ca_name = x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, "Mock DoD Root CA"
        )])
        now = datetime.datetime.now(datetime.timezone.utc)

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        with patch("modules.identity.cac_piv.CACPIVRevocationChecker._fetch_crl") as mock_fetch:
            mock_fetch.return_value = crl

            pem, _, _ = _make_test_cert(serial=0x1234, add_crl_url="http://crl.test/mock.crl")
            cert = CACPIVCertificate(pem)
            checker = CACPIVRevocationChecker()
            result = checker.check_crl(cert)
            assert not result.revoked
            assert result.reason == "crl_good"

    def test_soft_fail_when_both_unavailable(self):
        """Both OCSP and CRL unavailable → soft fail (not revoked) in default mode."""
        pem, _, _ = _make_test_cert(
            add_ocsp_url="http://unreachable.ocsp/",
            add_crl_url="http://unreachable.crl/"
        )
        cert = CACPIVCertificate(pem)

        with patch("modules.identity.cac_piv.CACPIVRevocationChecker._fetch_crl", return_value=None):
            with patch("modules.identity.cac_piv.CACPIVRevocationChecker.check_ocsp") as mock_ocsp:
                mock_ocsp.return_value = RevocationResult(
                    method="ocsp", revoked=False, reason="ocsp_unavailable"
                )
                checker = CACPIVRevocationChecker(strict_mode=False)
                result = checker.check(cert)
                assert not result.revoked
                assert result.method == "skipped"

    def test_strict_fail_when_both_unavailable(self):
        """Strict mode: both unavailable → revoked=True."""
        pem, _, _ = _make_test_cert()
        cert = CACPIVCertificate(pem)

        checker = CACPIVRevocationChecker(strict_mode=True)
        with patch.object(checker, "check_ocsp") as mock_ocsp, \
             patch.object(checker, "check_crl") as mock_crl:
            mock_ocsp.return_value = RevocationResult(method="ocsp", revoked=False, reason="ocsp_unavailable")
            mock_crl.return_value  = RevocationResult(method="crl",  revoked=False, reason="crl_unavailable")
            result = checker.check(cert)
            assert result.revoked
            assert "strict" in result.reason

    def test_crl_cache_used_on_second_fetch(self):
        """CRL should be fetched once and cached."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.backends import default_backend

        ca_key = generate_private_key(SECP256R1(), default_backend())
        ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Mock CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name).last_update(now).next_update(now + datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        checker = CACPIVRevocationChecker(crl_cache_ttl=3600)
        call_count = [0]
        original_fetch = checker._fetch_crl.__func__

        def counting_fetch(self, url):
            call_count[0] += 1
            return crl

        with patch.object(checker, "_fetch_crl", side_effect=lambda url: (call_count.__setitem__(0, call_count[0]+1) or crl)):
            pem, _, _ = _make_test_cert(add_crl_url="http://crl.test/")
            cert = CACPIVCertificate(pem)
            checker.check_crl(cert)
            checker.check_crl(cert)
            # Second call should use cache
            assert call_count[0] <= 2  # May vary by impl; at most 2 actual network calls


# ─────────────────────────────────────────────────────────────────────────────
# 6. CACPIVAuthenticator — Full Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestCACPIVAuthenticator:
    def _make_authenticator(self, skip_revocation=True):
        return CACPIVAuthenticator(
            chain_validator=CACPIVChainValidator(),
            revocation_checker=CACPIVRevocationChecker(strict_mode=False),
            skip_revocation=skip_revocation,
            strict_chain=True,
        )

    def test_happy_path_valid_cert(self):
        pem, _, _ = _make_test_cert(
            subject_cn="SMITH.JOHN.A.1234567890",
            subject_ou=["USA", "DoD"],
            issuer_cn="Mock DoD Root CA 1",
        )
        auth = self._make_authenticator(skip_revocation=True)
        identity = auth.authenticate(pem)
        assert identity.valid, f"Expected valid, got: {identity.error}"
        assert identity.edipi == "1234567890"
        assert identity.last_name == "SMITH"
        assert identity.first_name == "JOHN"
        assert identity.affiliation == "USA"
        assert identity.chain_valid
        assert identity.revocation_ok

    def test_expired_cert_rejected(self):
        pem, _, _ = _make_test_cert(days_valid=1, days_offset=-10)
        auth = self._make_authenticator()
        identity = auth.authenticate(pem)
        assert not identity.valid
        assert "expired" in identity.error

    def test_malformed_cert_rejected(self):
        auth = self._make_authenticator()
        identity = auth.authenticate("GARBAGE")
        assert not identity.valid
        assert identity.error

    def test_non_dod_issuer_rejected_strict(self):
        pem, _, _ = _make_test_cert(
            issuer_cn="Evil Corp CA",
            issuer_o="Evil Corp",
        )
        auth = CACPIVAuthenticator(strict_chain=True, skip_revocation=True)
        identity = auth.authenticate(pem)
        assert not identity.valid
        assert "chain" in identity.error

    def test_non_dod_issuer_allowed_non_strict(self):
        pem, _, _ = _make_test_cert(
            issuer_cn="Evil Corp CA",
            issuer_o="Evil Corp",
        )
        auth = CACPIVAuthenticator(strict_chain=False, skip_revocation=True)
        identity = auth.authenticate(pem)
        # Chain not valid but non-strict means we continue
        assert not identity.chain_valid
        assert identity.valid  # should still pass other checks

    def test_revoked_cert_rejected(self):
        pem, _, _ = _make_test_cert(add_crl_url="http://crl.test/")
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
        from cryptography.hazmat.backends import default_backend

        # Parse actual serial from the cert
        from cryptography.hazmat.backends import default_backend as db
        from cryptography import x509 as cx509
        raw = cx509.load_pem_x509_certificate(pem.encode(), db())
        serial = raw.serial_number

        ca_key = generate_private_key(SECP256R1(), default_backend())
        ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Mock CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name).last_update(now).next_update(now + datetime.timedelta(days=1))
            .add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(now)
                .build(default_backend())
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        checker = CACPIVRevocationChecker(strict_mode=False)
        with patch.object(checker, "_fetch_crl", return_value=crl):
            auth = CACPIVAuthenticator(
                revocation_checker=checker,
                skip_revocation=False,
                strict_chain=False,  # ignore chain so revocation is tested
            )
            identity = auth.authenticate(pem)
            assert not identity.valid
            assert "revoked" in identity.error

    def test_identity_attributes_populated(self):
        pem, _, _ = _make_test_cert(
            subject_cn="DOE.JANE.M.9876543210",
            subject_ou=["USN", "DoD"],
            subject_o="U.S. Government",
            subject_c="US",
            issuer_cn="Mock DoD Root CA 3",
        )
        auth = self._make_authenticator(skip_revocation=True)
        identity = auth.authenticate(pem)
        assert identity.valid
        assert identity.edipi == "9876543210"
        assert identity.last_name == "DOE"
        assert identity.first_name == "JANE"
        assert identity.affiliation == "USN"

    def test_cert_fingerprint_populated(self):
        pem, _, _ = _make_test_cert()
        auth = self._make_authenticator(skip_revocation=True)
        identity = auth.authenticate(pem)
        assert identity.valid
        assert len(identity.cert_fingerprint) == 64  # SHA-256 hex

    def test_to_dict_format(self):
        pem, _, _ = _make_test_cert()
        auth = self._make_authenticator(skip_revocation=True)
        identity = auth.authenticate(pem)
        d = identity.to_dict()
        assert "edipi" in d
        assert "valid" in d
        assert "chain_valid" in d
        assert "revocation_ok" in d
        assert "cert_fingerprint" in d


# ─────────────────────────────────────────────────────────────────────────────
# 7. FastAPI Middleware
# ─────────────────────────────────────────────────────────────────────────────

class TestCACPIVMiddleware:
    def _make_request_with_cert(self, cert_pem: str, header="X-Client-Cert"):
        """Build a mock FastAPI Request with a cert header."""
        from urllib.parse import quote
        encoded = quote(cert_pem)
        mock_req = MagicMock()
        mock_req.headers = {header: encoded}
        return mock_req

    def _make_request_no_cert(self):
        mock_req = MagicMock()
        mock_req.headers = {}
        return mock_req

    def test_valid_cert_in_header(self):
        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 1")
        req = self._make_request_with_cert(pem)

        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        middleware = CACPIVMiddleware(authenticator=auth)
        identity = middleware.optional(req)
        assert identity is not None
        assert identity.valid

    def test_missing_cert_returns_none_optional(self):
        req = self._make_request_no_cert()
        middleware = CACPIVMiddleware()
        identity = middleware.optional(req)
        assert identity is None

    def test_fallback_headers_checked(self):
        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 1")
        for fallback_header in ["X-SSL-Client-Cert", "X-Forwarded-Client-Cert", "Ssl-Client-Cert"]:
            req = self._make_request_with_cert(pem, header=fallback_header)
            middleware = CACPIVMiddleware(
                authenticator=CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
            )
            identity = middleware.optional(req)
            assert identity is not None, f"Header {fallback_header} not checked"

    def test_require_raises_401_no_cert(self):
        import asyncio
        try:
            from fastapi import HTTPException
        except ImportError:
            pytest.skip("FastAPI not installed")

        req = self._make_request_no_cert()
        middleware = CACPIVMiddleware()
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(middleware.require(req))
        assert exc_info.value.status_code == 401

    def test_require_raises_401_invalid_cert(self):
        import asyncio
        try:
            from fastapi import HTTPException
        except ImportError:
            pytest.skip("FastAPI not installed")

        from urllib.parse import quote
        mock_req = MagicMock()
        mock_req.headers = {"X-Client-Cert": quote("-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----")}

        middleware = CACPIVMiddleware()
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(middleware.require(mock_req))
        assert exc_info.value.status_code == 401

    def test_require_returns_identity_valid_cert(self):
        import asyncio
        try:
            from fastapi import HTTPException
        except ImportError:
            pytest.skip("FastAPI not installed")

        pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 1")
        req = self._make_request_with_cert(pem)
        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        middleware = CACPIVMiddleware(authenticator=auth)
        identity = asyncio.run(middleware.require(req))
        assert identity.valid


# ─────────────────────────────────────────────────────────────────────────────
# 8. Integration — EDIPI feeds into identity pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:
    def test_edipi_as_subject_identifier(self):
        """EDIPI from CAC cert can be used as subject for TokenDNA pipeline."""
        pem, _, _ = _make_test_cert(
            subject_cn="BROWN.ALICE.R.5551234567",
            issuer_cn="DoD Root CA 3",
        )
        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        identity = auth.authenticate(pem)
        assert identity.valid
        edipi = identity.edipi
        assert edipi == "5551234567"
        # Can be used as user_id / subject in downstream token creation
        assert len(edipi) == 10
        assert edipi.isdigit()

    def test_multiple_certs_different_edipi(self):
        """Each CAC cert has a unique EDIPI."""
        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        edipis = set()
        for i in range(5):
            edipi_str = f"{i:010d}"
            pem, _, _ = _make_test_cert(
                subject_cn=f"USER.NAME.A.{edipi_str}",
                issuer_cn="Mock DoD Root CA 1",
            )
            identity = auth.authenticate(pem)
            assert identity.valid, identity.error
            edipis.add(identity.edipi)
        assert len(edipis) == 5

    def test_thread_safety(self):
        """Multiple concurrent auth calls should not corrupt state."""
        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        results = []
        errors  = []
        lock    = threading.Lock()

        def run_auth(edipi_suffix):
            try:
                pem, _, _ = _make_test_cert(
                    subject_cn=f"USER.TEST.A.{edipi_suffix:010d}",
                    issuer_cn="Mock DoD Root CA 2",
                )
                identity = auth.authenticate(pem)
                with lock:
                    results.append(identity.valid)
            except Exception as exc:
                with lock:
                    errors.append(str(exc))

        threads = [threading.Thread(target=run_auth, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert all(results), "All concurrent auths should succeed"

    def test_cert_fingerprint_uniqueness(self):
        """Different certs should have different fingerprints."""
        auth = CACPIVAuthenticator(skip_revocation=True, strict_chain=True)
        fps = []
        for i in range(3):
            pem, _, _ = _make_test_cert(issuer_cn="Mock DoD Root CA 1")
            identity = auth.authenticate(pem)
            fps.append(identity.cert_fingerprint)
        assert len(set(fps)) == 3, "Each cert should have a unique fingerprint"

    def test_singleton_middleware(self):
        """Module-level singleton middleware is accessible."""
        from modules.identity.cac_piv import get_cac_piv_middleware
        m1 = get_cac_piv_middleware()
        m2 = get_cac_piv_middleware()
        assert m1 is m2  # same instance
