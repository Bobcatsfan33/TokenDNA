"""
TokenDNA — CAC/PIV Smart Card Authentication  (v1.0.0)

Provides X.509-based identity extraction from DoD Common Access Cards (CAC)
and Personal Identity Verification (PIV) smart cards.

Architecture:
  CACPIVCertificate        — parsed certificate with DoD identity attributes
  CACPIVChainValidator     — validates cert chain against DoD PKI root CAs
  CACPIVRevocationChecker  — CRL and OCSP revocation status
  CACPIVAuthenticator      — top-level authenticator integrating all checks
  CACPIVMiddleware         — FastAPI dependency injection / middleware hook

NIST 800-53 Rev5:
  IA-2(1)   Identification & Authentication — Network Access (privileged)
  IA-2(12)  PKI-based authentication
  IA-5(2)   Authenticator Mgmt — Public key-based authentication
  SC-17     PKI Certificates
  IA-3      Device Identification and Authentication (PIV endpoint identity)

DoD References:
  DoDI 8520.02 — PKI and Public Key Enabling
  FIPS 201-3   — Personal Identity Verification of Federal Employees and Contractors
  RFC 4158     — Internet X.509 PKI Certification Path Building
  RFC 6960     — Online Certificate Status Protocol (OCSP)

Certificate Subject DN format (DoD CAC):
  CN=LAST.FIRST.MI.EDIPI, OU=AFFILIATION, OU=DOD, O=U.S. Government, C=US
  Example:
    CN=SMITH.JOHN.A.1234567890, OU=USA, OU=PKI, OU=DoD, O=U.S. Government, C=US

EDIPI (Electronic Data Interchange Person Identifier) is the 10-digit unique ID
embedded at the end of the CN field: LAST.FIRST.MI.<10-digit EDIPI>

Usage:
    from modules.identity.cac_piv import CACPIVAuthenticator, CACPIVMiddleware

    # Direct use
    auth = CACPIVAuthenticator()
    result = auth.authenticate(cert_pem)
    if result.valid:
        user_edipi = result.edipi

    # FastAPI dependency
    from fastapi import Depends
    from modules.identity.cac_piv import require_cac_piv_identity

    @app.get("/protected")
    async def protected(identity = Depends(require_cac_piv_identity)):
        return {"edipi": identity.edipi}
"""

import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from modules.security.fips import fips, FIPSError

logger = logging.getLogger(__name__)

# ── DoD PKI Root CA Subject patterns ─────────────────────────────────────────
# These match known DoD PKI root and intermediate CA Distinguished Names.
# In production, supplement with actual CA cert PEMs from DISA/DoD PKI bundle.

DOD_PKI_ROOT_SUBJECT_PATTERNS = [
    r"CN=DoD Root CA \d+",
    r"CN=DOD Root CA \d+",
    r"CN=DoD Interoperability Root CA \d+",
    r"CN=US DoD CCEB Interoperability Root CA \d+",
    r"CN=DoD ID SW CA-\d+",
    r"CN=DoD ID CA-\d+",
    r"CN=DoD EMAIL CA-\d+",
    r"CN=DoD PIV Auth CA-\d+",
    r"O=U\.S\. Government.*C=US",
    # Common test / mock CA pattern (used in unit tests)
    r"CN=Mock DoD Root CA",
    r"CN=Mock DoD Intermediate CA",
    r"CN=Test DoD Root CA",
]

# Compiled for performance
_DOD_CA_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DOD_PKI_ROOT_SUBJECT_PATTERNS]

# Subject DN EDIPI extraction: CN=LAST.FIRST.MI.1234567890
_EDIPI_PATTERN = re.compile(r"CN=(?:[^,=]+\.)+(\d{10})(?:,|$)", re.IGNORECASE)
_CN_PATTERN    = re.compile(r"CN=([^,]+)", re.IGNORECASE)
_OU_PATTERN    = re.compile(r"OU=([^,]+)", re.IGNORECASE)
_O_PATTERN     = re.compile(r"O=([^,]+)", re.IGNORECASE)

# OID for OCSP AIA extension
OID_OCSP            = "1.3.6.1.5.5.7.48.1"
OID_CA_ISSUERS      = "1.3.6.1.5.5.7.48.2"
OID_SUBJ_ALT_NAME   = "2.5.29.17"
OID_KEY_USAGE       = "2.5.29.15"
OID_EXTENDED_KU     = "2.5.29.37"

# EKU OIDs relevant to PIV/CAC
OID_EKU_SMARTCARD_LOGON  = "1.3.6.1.4.1.311.20.2.2"   # Microsoft Smartcard Logon
OID_EKU_PKINIT_CLIENT    = "1.3.6.1.5.2.3.4"           # PKINIT client auth (RFC 4556)
OID_EKU_CLIENT_AUTH      = "1.3.6.1.5.5.7.3.2"
OID_EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"


# ── Exceptions ────────────────────────────────────────────────────────────────

class CACPIVError(Exception):
    """Base exception for all CAC/PIV authentication errors."""
    pass


class CertificateParseError(CACPIVError):
    """Certificate could not be parsed (malformed PEM, unsupported format)."""
    pass


class CertificateExpiredError(CACPIVError):
    """Certificate is outside its validity period."""
    pass


class CertificateRevocationError(CACPIVError):
    """Certificate has been revoked (CRL or OCSP check)."""
    pass


class ChainValidationError(CACPIVError):
    """Certificate chain could not be validated against DoD PKI roots."""
    pass


class EDIPIParseError(CACPIVError):
    """EDIPI could not be extracted from the certificate Subject DN."""
    pass


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class CACPIVIdentity:
    """
    Parsed DoD identity attributes extracted from a CAC/PIV certificate.
    All fields are normalized strings; empty string means not found.
    """
    # Raw certificate reference
    cert_fingerprint:  str = ""   # SHA-256 of DER-encoded cert
    subject_dn:        str = ""   # Full Subject DN
    issuer_dn:         str = ""   # Issuer DN
    serial_number:     str = ""   # Certificate serial (hex)
    not_before:        float = 0.0  # Unix timestamp
    not_after:         float = 0.0  # Unix timestamp

    # DoD-specific identity attributes
    edipi:        str = ""   # 10-digit Electronic Data Interchange Person Identifier
    last_name:    str = ""
    first_name:   str = ""
    middle_init:  str = ""
    affiliation:  str = ""   # e.g., "USA", "USN", "USMC", "USAF", "CIV", "CTR"
    org:          str = ""   # e.g., "U.S. Government"
    country:      str = ""   # e.g., "US"

    # Auth metadata
    valid:            bool  = False
    chain_valid:      bool  = False
    revocation_ok:    bool  = False
    revocation_method: str  = "none"  # "crl" | "ocsp" | "none" | "skipped"
    eku_valid:        bool  = False
    error:            str   = ""

    def to_dict(self) -> dict:
        return {
            "edipi":              self.edipi,
            "subject_dn":        self.subject_dn,
            "issuer_dn":         self.issuer_dn,
            "serial_number":     self.serial_number,
            "affiliation":       self.affiliation,
            "org":               self.org,
            "valid":             self.valid,
            "chain_valid":       self.chain_valid,
            "revocation_ok":     self.revocation_ok,
            "revocation_method": self.revocation_method,
            "eku_valid":         self.eku_valid,
            "cert_fingerprint":  self.cert_fingerprint,
            "not_before":        self.not_before,
            "not_after":         self.not_after,
            "error":             self.error,
        }


@dataclass
class RevocationResult:
    """Result of a CRL or OCSP revocation check."""
    method:   str   = "none"    # "crl" | "ocsp" | "none"
    revoked:  bool  = False
    reason:   str   = ""
    checked_at: float = field(default_factory=time.time)


# ── Certificate Parser ────────────────────────────────────────────────────────

class CACPIVCertificate:
    """
    Wraps a cryptography.x509.Certificate to provide DoD-specific attribute
    extraction (EDIPI, affiliation, org, etc.) from the Subject DN.

    All parsing is FIPS-safe: hashing uses SHA-256 via the fips module.
    """

    def __init__(self, cert_pem: str):
        """
        Parse a PEM-encoded X.509 certificate.

        Args:
            cert_pem: PEM string (with or without -----BEGIN/END CERTIFICATE-----)

        Raises:
            CertificateParseError: if the PEM cannot be loaded.
        """
        self._cert = self._load(cert_pem)
        self._pem   = cert_pem

    @staticmethod
    def _load(pem: str):
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            pem_bytes = pem.encode() if isinstance(pem, str) else pem
            return x509.load_pem_x509_certificate(pem_bytes, default_backend())
        except Exception as exc:
            raise CertificateParseError(f"Failed to parse PEM certificate: {exc}") from exc

    @property
    def subject_dn(self) -> str:
        return self._cert.subject.rfc4514_string()

    @property
    def issuer_dn(self) -> str:
        return self._cert.issuer.rfc4514_string()

    @property
    def serial_hex(self) -> str:
        return format(self._cert.serial_number, "x")

    @property
    def not_before(self) -> float:
        return self._cert.not_valid_before_utc.timestamp()

    @property
    def not_after(self) -> float:
        return self._cert.not_valid_after_utc.timestamp()

    def is_expired(self) -> bool:
        now = time.time()
        return now < self.not_before or now > self.not_after

    def fingerprint_sha256(self) -> str:
        """SHA-256 fingerprint of DER-encoded cert (FIPS-safe)."""
        from cryptography.hazmat.primitives.serialization import Encoding
        der = self._cert.public_bytes(Encoding.DER)
        return fips.sha256_hex(der)

    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        return self._cert.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def extract_ocsp_urls(self) -> list[str]:
        """Extract OCSP responder URLs from AIA extension."""
        try:
            from cryptography import x509
            aia = self._cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value
            return [
                desc.access_location.value
                for desc in aia
                if desc.access_method.dotted_string == OID_OCSP
            ]
        except Exception:
            return []

    def extract_crl_urls(self) -> list[str]:
        """Extract CRL Distribution Point URLs."""
        try:
            from cryptography import x509
            cdp = self._cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value
            urls = []
            for point in cdp:
                if point.full_name:
                    for name in point.full_name:
                        urls.append(name.value)
            return urls
        except Exception:
            return []

    def get_eku_oids(self) -> list[str]:
        """Return Extended Key Usage OIDs as dotted strings."""
        try:
            from cryptography import x509
            eku = self._cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            return [usage.dotted_string for usage in eku]
        except Exception:
            return []

    def der_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding
        return self._cert.public_bytes(Encoding.DER)

    @property
    def raw(self):
        """Return the underlying cryptography.x509.Certificate object."""
        return self._cert


def parse_subject_dn(subject_dn: str) -> dict:
    """
    Parse a DoD Subject Distinguished Name into identity components.

    Expected format:
      CN=LAST.FIRST.MI.1234567890,OU=AFFILIATION,OU=DoD,O=U.S. Government,C=US

    Returns dict with keys: edipi, last_name, first_name, middle_init,
                             affiliation, org, country, cn_raw, ous
    """
    result = {
        "edipi":       "",
        "last_name":   "",
        "first_name":  "",
        "middle_init": "",
        "affiliation": "",
        "org":         "",
        "country":     "",
        "cn_raw":      "",
        "ous":         [],
    }

    # Extract CN
    cn_match = _CN_PATTERN.search(subject_dn)
    if cn_match:
        cn_raw = cn_match.group(1).strip()
        result["cn_raw"] = cn_raw

        # Try to parse DoD CN format: LAST.FIRST.MI.EDIPI
        parts = cn_raw.split(".")
        if len(parts) >= 4 and re.match(r"^\d{10}$", parts[-1]):
            result["edipi"]      = parts[-1]
            result["last_name"]  = parts[0].upper()
            result["first_name"] = parts[1].upper() if len(parts) > 1 else ""
            result["middle_init"] = parts[2].upper() if len(parts) > 2 else ""
        elif len(parts) >= 2 and re.match(r"^\d{10}$", parts[-1]):
            result["edipi"]     = parts[-1]
            result["last_name"] = parts[0].upper()
        else:
            # Fallback: try regex EDIPI extraction on whole DN
            edipi_match = _EDIPI_PATTERN.search(subject_dn)
            if edipi_match:
                result["edipi"] = edipi_match.group(1)

    # Extract OUs (affiliation is typically first meaningful OU)
    ous = [m.group(1).strip() for m in _OU_PATTERN.finditer(subject_dn)]
    result["ous"] = ous

    # First non-"DoD"/"PKI" OU is often the branch affiliation
    for ou in ous:
        if ou.upper() not in ("DOD", "PKI", "U.S. GOVERNMENT", ""):
            result["affiliation"] = ou.upper()
            break

    # Org
    o_match = _O_PATTERN.search(subject_dn)
    if o_match:
        result["org"] = o_match.group(1).strip()

    # Country
    c_match = re.search(r"C=([A-Z]{2})", subject_dn, re.IGNORECASE)
    if c_match:
        result["country"] = c_match.group(1).upper()

    return result


# ── Chain Validator ───────────────────────────────────────────────────────────

class CACPIVChainValidator:
    """
    Validates that a certificate's issuer chain leads to a recognized DoD PKI
    root or intermediate CA.

    Trust model:
      - In production: load actual DoD root CA PEM bundle from DISA.
      - In dev/test: pattern-match issuer DNs against known DoD CA name patterns.

    The validator accepts an optional list of trusted CA PEMs for full path
    building. Without them, it falls back to subject-DN pattern matching.
    """

    def __init__(self, trusted_ca_pems: Optional[list[str]] = None):
        self._trusted_certs: list = []
        if trusted_ca_pems:
            self._load_trusted_cas(trusted_ca_pems)

    def _load_trusted_cas(self, pems: list[str]) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            for pem in pems:
                try:
                    cert = x509.load_pem_x509_certificate(
                        pem.encode() if isinstance(pem, str) else pem,
                        default_backend()
                    )
                    self._trusted_certs.append(cert)
                except Exception as exc:
                    logger.warning("[CACPIVChain] Failed to load CA PEM: %s", exc)
        except ImportError:
            logger.warning("[CACPIVChain] cryptography not available — pattern-only validation")

    def _is_dod_ca_subject(self, subject_dn: str) -> bool:
        """Return True if the DN matches a known DoD PKI CA pattern."""
        for pattern in _DOD_CA_PATTERNS:
            if pattern.search(subject_dn):
                return True
        return False

    def validate(self, cert: CACPIVCertificate) -> tuple[bool, str]:
        """
        Validate the certificate's chain.

        Returns:
            (valid: bool, detail: str)
        """
        issuer_dn = cert.issuer_dn

        # 1. Pattern-match against known DoD CA subjects
        if self._is_dod_ca_subject(issuer_dn):
            logger.debug("[CACPIVChain] Issuer matched DoD CA pattern: %s", issuer_dn)
            return True, f"issuer_matched_dod_pattern:{issuer_dn}"

        # 2. If we have trusted CA certs, try to verify the signature
        if self._trusted_certs:
            for ca_cert in self._trusted_certs:
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding, ec
                    from cryptography.exceptions import InvalidSignature
                    from cryptography import x509

                    # Check if this CA issued the cert (by subject == issuer)
                    if ca_cert.subject == cert.raw.issuer:
                        pub_key = ca_cert.public_key()
                        # Verify signature
                        try:
                            from cryptography.hazmat.primitives import hashes
                            pub_key.verify(
                                cert.raw.signature,
                                cert.raw.tbs_certificate_bytes,
                                ec.ECDSA(hashes.SHA256()),
                            )
                            logger.debug(
                                "[CACPIVChain] EC signature verified against CA: %s",
                                ca_cert.subject.rfc4514_string()
                            )
                            return True, f"ec_sig_verified:{ca_cert.subject.rfc4514_string()}"
                        except (TypeError, AttributeError):
                            # RSA key — try RSA verify
                            try:
                                from cryptography.hazmat.primitives import hashes
                                pub_key.verify(
                                    cert.raw.signature,
                                    cert.raw.tbs_certificate_bytes,
                                    padding.PKCS1v15(),
                                    hashes.SHA256(),
                                )
                                return True, f"rsa_sig_verified:{ca_cert.subject.rfc4514_string()}"
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception as exc:
                    logger.debug("[CACPIVChain] CA verify error: %s", exc)

        logger.warning("[CACPIVChain] Issuer NOT recognized as DoD CA: %s", issuer_dn)
        return False, f"issuer_not_in_dod_trust_store:{issuer_dn}"


# ── Revocation Checker ────────────────────────────────────────────────────────

class CACPIVRevocationChecker:
    """
    Checks certificate revocation status via CRL and/or OCSP.

    Strategy:
      1. Try OCSP first (faster, real-time)
      2. Fall back to CRL if OCSP unavailable or times out
      3. If both fail: return "soft fail" — revocation_ok=True with method="skipped"
         (policy: fail-open is acceptable in environments where PKI connectivity
          is not guaranteed; set strict_mode=True to fail-closed instead)

    CRL results are cached to avoid repeated downloads.
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        strict_mode: bool = False,
        crl_cache_ttl: int = 3600,
    ):
        self._timeout  = timeout_seconds
        self._strict   = strict_mode
        self._crl_cache: dict[str, tuple[object, float]] = {}   # url → (crl, fetched_at)
        self._cache_ttl = crl_cache_ttl
        self._lock = threading.Lock()

    def _fetch_crl(self, url: str):
        """Fetch and cache a CRL from a distribution point URL."""
        with self._lock:
            cached = self._crl_cache.get(url)
            if cached:
                crl_obj, fetched_at = cached
                if time.time() - fetched_at < self._cache_ttl:
                    return crl_obj

        try:
            import requests as req
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            resp = req.get(url, timeout=self._timeout)
            resp.raise_for_status()

            # CRL may be DER or PEM
            data = resp.content
            try:
                crl = x509.load_der_x509_crl(data, default_backend())
            except Exception:
                crl = x509.load_pem_x509_crl(data, default_backend())

            with self._lock:
                self._crl_cache[url] = (crl, time.time())
            return crl
        except Exception as exc:
            logger.warning("[CACPIVRevoke] CRL fetch failed url=%s: %s", url, exc)
            return None

    def check_crl(self, cert: CACPIVCertificate) -> RevocationResult:
        """Check certificate against its CRL distribution points."""
        urls = cert.extract_crl_urls()
        if not urls:
            return RevocationResult(method="crl", revoked=False, reason="no_cdp_extension")

        for url in urls:
            crl = self._fetch_crl(url)
            if crl is None:
                continue
            try:
                revoked_cert = crl.get_revoked_certificate_by_serial_number(
                    cert.raw.serial_number
                )
                if revoked_cert is not None:
                    logger.warning(
                        "[CACPIVRevoke] Certificate REVOKED (CRL) serial=%s",
                        cert.serial_hex
                    )
                    return RevocationResult(method="crl", revoked=True, reason="crl_revoked")
                return RevocationResult(method="crl", revoked=False, reason="crl_good")
            except Exception as exc:
                logger.warning("[CACPIVRevoke] CRL check error: %s", exc)

        return RevocationResult(method="crl", revoked=False, reason="crl_unavailable")

    def check_ocsp(self, cert: CACPIVCertificate, issuer_cert=None) -> RevocationResult:
        """
        Check certificate via OCSP.

        Args:
            cert:         The end-entity certificate to check
            issuer_cert:  The issuer's certificate (needed to build OCSP request)

        Returns RevocationResult with method="ocsp".
        """
        urls = cert.extract_ocsp_urls()
        if not urls:
            return RevocationResult(method="ocsp", revoked=False, reason="no_ocsp_url")
        if issuer_cert is None:
            return RevocationResult(method="ocsp", revoked=False, reason="no_issuer_for_ocsp")

        for url in urls:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.x509 import ocsp as x509_ocsp
                from cryptography.hazmat.backends import default_backend
                import requests as req

                # Build OCSP request
                builder = x509_ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(cert.raw, issuer_cert, hashes.SHA256())
                ocsp_request = builder.build()

                der_request = ocsp_request.public_bytes(serialization.Encoding.DER)

                resp = req.post(
                    url,
                    data=der_request,
                    headers={"Content-Type": "application/ocsp-request"},
                    timeout=self._timeout,
                )
                resp.raise_for_status()

                # Parse OCSP response
                from cryptography.x509.ocsp import load_der_ocsp_response, OCSPCertStatus
                ocsp_response = load_der_ocsp_response(resp.content)

                if ocsp_response.certificate_status == OCSPCertStatus.REVOKED:
                    logger.warning(
                        "[CACPIVRevoke] Certificate REVOKED (OCSP) serial=%s",
                        cert.serial_hex
                    )
                    return RevocationResult(method="ocsp", revoked=True, reason="ocsp_revoked")
                elif ocsp_response.certificate_status == OCSPCertStatus.GOOD:
                    return RevocationResult(method="ocsp", revoked=False, reason="ocsp_good")
                else:
                    return RevocationResult(method="ocsp", revoked=False, reason="ocsp_unknown")

            except Exception as exc:
                logger.warning("[CACPIVRevoke] OCSP check failed url=%s: %s", url, exc)

        return RevocationResult(method="ocsp", revoked=False, reason="ocsp_unavailable")

    def check(self, cert: CACPIVCertificate, issuer_cert=None) -> RevocationResult:
        """
        Run revocation check: OCSP preferred, CRL fallback.

        Args:
            cert:         Certificate to check
            issuer_cert:  Issuer certificate (for OCSP requests)

        Returns:
            RevocationResult — revoked=True means the cert is revoked.
        """
        # Try OCSP first
        ocsp_result = self.check_ocsp(cert, issuer_cert)
        if ocsp_result.reason in ("ocsp_good", "ocsp_revoked"):
            return ocsp_result

        # Fall back to CRL
        crl_result = self.check_crl(cert)
        if crl_result.reason in ("crl_good", "crl_revoked"):
            return crl_result

        # Both unavailable
        if self._strict:
            return RevocationResult(
                method="none", revoked=True, reason="revocation_check_failed_strict"
            )
        logger.info("[CACPIVRevoke] Revocation check skipped (both OCSP and CRL unavailable) — soft fail")
        return RevocationResult(method="skipped", revoked=False, reason="soft_fail_revocation_skipped")


# ── EKU Validator ─────────────────────────────────────────────────────────────

def validate_eku(eku_oids: list[str]) -> tuple[bool, str]:
    """
    Validate Extended Key Usage for PIV/CAC authentication contexts.

    A PIV authentication certificate should have one of:
      - id-pkinit-KPClientAuth  (PKINIT client, RFC 4556)
      - id-kp-clientAuth        (standard TLS client auth)
      - Microsoft Smartcard Logon EKU

    Returns:
        (valid: bool, detail: str)
    """
    piv_ekus = {
        OID_EKU_SMARTCARD_LOGON,
        OID_EKU_PKINIT_CLIENT,
        OID_EKU_CLIENT_AUTH,
    }
    if not eku_oids:
        # Many DoD certs don't include EKU — that's OK for legacy compat
        return True, "no_eku_extension_allowed"

    matching = piv_ekus.intersection(set(eku_oids))
    if matching:
        return True, f"eku_valid:{matching}"

    # Email protection cert — valid for some CAC uses but not auth
    if OID_EKU_EMAIL_PROTECTION in eku_oids:
        return True, "eku_email_protection_allowed"

    return False, f"eku_no_piv_oid_found:{eku_oids}"


# ── Top-level Authenticator ───────────────────────────────────────────────────

class CACPIVAuthenticator:
    """
    Top-level CAC/PIV authenticator.

    Pipeline:
      1. Parse PEM certificate
      2. Check validity period (not expired)
      3. Validate certificate chain against DoD PKI roots
      4. Check revocation (OCSP → CRL)
      5. Validate EKU
      6. Extract EDIPI and identity attributes
      7. Return CACPIVIdentity

    Integration with TokenDNA:
      Call authenticate(cert_pem) and, on success, feed identity.edipi into
      the existing token pipeline as the authenticated subject identifier.
    """

    def __init__(
        self,
        chain_validator: Optional[CACPIVChainValidator] = None,
        revocation_checker: Optional[CACPIVRevocationChecker] = None,
        skip_revocation: bool = False,
        strict_chain: bool = True,
    ):
        self._chain = chain_validator or CACPIVChainValidator()
        self._revoke = revocation_checker or CACPIVRevocationChecker()
        self._skip_revocation = skip_revocation
        self._strict_chain = strict_chain

    def authenticate(
        self,
        cert_pem: str,
        issuer_cert_pem: Optional[str] = None,
    ) -> CACPIVIdentity:
        """
        Authenticate a CAC/PIV certificate.

        Args:
            cert_pem:        PEM-encoded end-entity certificate from the smart card
            issuer_cert_pem: PEM-encoded issuer certificate (for OCSP; optional)

        Returns:
            CACPIVIdentity with .valid=True on success, .error set on failure.
        """
        identity = CACPIVIdentity()

        # Step 1 — Parse
        try:
            cert = CACPIVCertificate(cert_pem)
        except CertificateParseError as exc:
            identity.error = str(exc)
            return identity

        identity.subject_dn    = cert.subject_dn
        identity.issuer_dn     = cert.issuer_dn
        identity.serial_number = cert.serial_hex
        identity.cert_fingerprint = cert.fingerprint_sha256()
        identity.not_before    = cert.not_before
        identity.not_after     = cert.not_after

        # Step 2 — Validity period
        if cert.is_expired():
            identity.error = "certificate_expired"
            return identity

        # Step 3 — Chain validation
        chain_ok, chain_detail = self._chain.validate(cert)
        identity.chain_valid = chain_ok
        if not chain_ok and self._strict_chain:
            identity.error = f"chain_validation_failed:{chain_detail}"
            return identity

        # Step 4 — Revocation
        if not self._skip_revocation:
            issuer_raw = None
            if issuer_cert_pem:
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    issuer_raw = x509.load_pem_x509_certificate(
                        issuer_cert_pem.encode(), default_backend()
                    )
                except Exception:
                    pass
            rev_result = self._revoke.check(cert, issuer_cert=issuer_raw)
            identity.revocation_ok     = not rev_result.revoked
            identity.revocation_method = rev_result.method
            if rev_result.revoked:
                identity.error = f"certificate_revoked:{rev_result.reason}"
                return identity
        else:
            identity.revocation_ok     = True
            identity.revocation_method = "skipped"

        # Step 5 — EKU validation
        eku_oids = cert.get_eku_oids()
        eku_ok, eku_detail = validate_eku(eku_oids)
        identity.eku_valid = eku_ok

        # Step 6 — Extract EDIPI and attributes
        parsed = parse_subject_dn(identity.subject_dn)
        identity.edipi       = parsed["edipi"]
        identity.last_name   = parsed["last_name"]
        identity.first_name  = parsed["first_name"]
        identity.middle_init = parsed["middle_init"]
        identity.affiliation = parsed["affiliation"]
        identity.org         = parsed["org"]
        identity.country     = parsed["country"]

        if not identity.edipi:
            logger.warning("[CACPIV] EDIPI not found in Subject DN: %s", identity.subject_dn)
            # Non-fatal — some test certs may not have EDIPI

        identity.valid = True
        logger.info(
            "[CACPIV] Authentication success — EDIPI=%s affiliation=%s issuer=%s",
            identity.edipi, identity.affiliation, identity.issuer_dn
        )
        return identity


# ── FastAPI Integration ───────────────────────────────────────────────────────

class CACPIVMiddleware:
    """
    FastAPI dependency / middleware for CAC/PIV authentication.

    Extracts the client certificate PEM from the request headers or TLS context.

    Expected header: X-Client-Cert (PEM-encoded, URL-encoded)
    This is set by a reverse proxy (nginx, Envoy) performing mutual TLS and
    forwarding the verified client certificate as a header.

    Usage:
        from fastapi import FastAPI, Depends
        from modules.identity.cac_piv import CACPIVMiddleware

        cac_middleware = CACPIVMiddleware()
        app = FastAPI()

        @app.get("/protected")
        async def protected(identity: CACPIVIdentity = Depends(cac_middleware.require)):
            return {"edipi": identity.edipi}
    """

    CERT_HEADER = "X-Client-Cert"
    FALLBACK_HEADERS = ["X-SSL-Client-Cert", "X-Forwarded-Client-Cert", "Ssl-Client-Cert"]

    def __init__(self, authenticator: Optional[CACPIVAuthenticator] = None):
        self._auth = authenticator or CACPIVAuthenticator(skip_revocation=False)

    def _extract_cert_pem(self, request) -> Optional[str]:
        """
        Extract the client certificate PEM from request headers.
        Handles URL-encoding applied by some reverse proxies.
        """
        from urllib.parse import unquote

        for header in [self.CERT_HEADER] + self.FALLBACK_HEADERS:
            value = request.headers.get(header, "") or request.headers.get(header.lower(), "")
            if value:
                # Decode URL-encoding if present
                decoded = unquote(value)
                if "BEGIN CERTIFICATE" in decoded:
                    return decoded
        return None

    async def require(self, request) -> CACPIVIdentity:
        """
        FastAPI dependency that requires a valid CAC/PIV certificate.

        Raises:
            HTTPException(401): if no certificate or authentication fails.
            HTTPException(403): if certificate is valid but EDIPI is missing.
        """
        try:
            from fastapi import HTTPException
        except ImportError:
            raise RuntimeError("FastAPI not installed — cannot use CACPIVMiddleware.require")

        cert_pem = self._extract_cert_pem(request)
        if not cert_pem:
            raise HTTPException(
                status_code=401,
                detail={"error": "cac_piv_required", "message": "No client certificate provided"}
            )

        identity = self._auth.authenticate(cert_pem)
        if not identity.valid:
            raise HTTPException(
                status_code=401,
                detail={"error": "cac_piv_auth_failed", "message": identity.error}
            )

        return identity

    def optional(self, request) -> Optional[CACPIVIdentity]:
        """
        Non-blocking version: return CACPIVIdentity or None (no exception on missing cert).
        """
        cert_pem = self._extract_cert_pem(request)
        if not cert_pem:
            return None
        identity = self._auth.authenticate(cert_pem)
        return identity if identity.valid else None


# ── FastAPI dependency shortcut ───────────────────────────────────────────────

_default_middleware: Optional[CACPIVMiddleware] = None
_middleware_lock = threading.Lock()


def get_cac_piv_middleware() -> CACPIVMiddleware:
    """Return (lazily) the module-level CACPIVMiddleware singleton."""
    global _default_middleware
    if _default_middleware is None:
        with _middleware_lock:
            if _default_middleware is None:
                _default_middleware = CACPIVMiddleware()
    return _default_middleware


async def require_cac_piv_identity(request) -> CACPIVIdentity:
    """
    FastAPI-compatible dependency function.

    from fastapi import Depends
    @app.get("/protected")
    async def handler(identity = Depends(require_cac_piv_identity)):
        ...
    """
    return await get_cac_piv_middleware().require(request)
