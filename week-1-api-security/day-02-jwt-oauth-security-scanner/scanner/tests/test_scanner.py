"""
Scanner integration tests.

Tests each probe against crafted JWTs covering all attack scenarios.
Uses real token encoding (without signature — structural tests only).

Run: pytest scanner/tests/ -v
"""

import base64
import json
import time
import pytest

from scanner.scanner import JWTSecurityScanner
from scanner.jwt_decoder import decode_jwt
from scanner.probes.base import Severity, FindingCategory


def _make_jwt(header: dict, payload: dict) -> str:
    """Create a JWT with no signature (for testing token structure)."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.fakesignature"


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_access_token():
    """A well-formed, unexpired access token with RS256."""
    return _make_jwt(
        header={"alg": "RS256", "typ": "JWT"},
        payload={
            "sub": "user_123",
            "iss": "https://auth.example.com",
            "aud": "api.example.com",
            "iat": int(time.time()) - 60,
            "exp": int(time.time()) + 3540,  # 59 min from now
            "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "scope": "read:orders write:orders",
        },
    )


@pytest.fixture
def expired_token():
    return _make_jwt(
        header={"alg": "RS256", "typ": "JWT"},
        payload={
            "sub": "user_123",
            "iss": "https://auth.example.com",
            "aud": "api.example.com",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
            "jti": "expired-jti-value",
            "scope": "read:orders",
        },
    )


@pytest.fixture
def none_alg_token():
    return _make_jwt(
        header={"alg": "none", "typ": "JWT"},
        payload={"sub": "admin", "scope": "admin:*"},
    )


@pytest.fixture
def no_expiry_token():
    return _make_jwt(
        header={"alg": "RS256", "typ": "JWT"},
        payload={"sub": "user_123", "scope": "read:orders"},
    )


@pytest.fixture
def kid_injection_token():
    return _make_jwt(
        header={"alg": "RS256", "kid": "' OR 1=1; --", "typ": "JWT"},
        payload={"sub": "user_123", "exp": int(time.time()) + 3600},
    )


@pytest.fixture
def scope_overflow_token():
    return _make_jwt(
        header={"alg": "RS256", "typ": "JWT"},
        payload={
            "sub": "service_account",
            "exp": int(time.time()) + 3600,
            "scope": "read:* write:* delete:* admin:*",
        },
    )


# ─── Decoder tests ────────────────────────────────────────────────────────────

class TestJWTDecoder:
    def test_decodes_valid_token(self, valid_access_token):
        analysis = decode_jwt(valid_access_token)
        assert analysis.algorithm == "RS256"
        assert analysis.subject == "user_123"
        assert analysis.issuer == "https://auth.example.com"
        assert "read:orders" in analysis.scopes
        assert not analysis.is_expired

    def test_detects_expired_token(self, expired_token):
        analysis = decode_jwt(expired_token)
        assert analysis.is_expired
        assert analysis.seconds_until_expiry < 0

    def test_strips_bearer_prefix(self, valid_access_token):
        analysis = decode_jwt(f"Bearer {valid_access_token}")
        assert analysis.algorithm == "RS256"

    def test_raises_on_malformed_token(self):
        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_jwt("not.a.valid.jwt.token.with.too.many.parts")


# ─── Expiry probe tests ───────────────────────────────────────────────────────

class TestTokenExpiryProbe:
    def test_no_findings_for_valid_token(self, valid_access_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(valid_access_token)
        expiry_findings = [f for f in report.findings if f.category == FindingCategory.TOKEN_EXPIRY]
        assert len(expiry_findings) == 0

    def test_finds_missing_exp_claim(self, no_expiry_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(no_expiry_token)
        categories = [f.category for f in report.findings]
        assert FindingCategory.TOKEN_EXPIRY in categories

    def test_finds_expired_token(self, expired_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(expired_token)
        expiry_findings = [f for f in report.findings if f.category == FindingCategory.TOKEN_EXPIRY]
        assert len(expiry_findings) >= 1
        assert expiry_findings[0].severity in (Severity.MEDIUM, Severity.HIGH)

    def test_finds_excessive_lifetime(self):
        long_lived_token = _make_jwt(
            header={"alg": "RS256", "typ": "JWT"},
            payload={
                "sub": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 86400 * 365,  # 1 year
                "scope": "read:orders",
            },
        )
        scanner = JWTSecurityScanner()
        report = scanner.scan(long_lived_token, token_type="access")
        lifetime_findings = [f for f in report.findings if f.category == FindingCategory.EXCESSIVE_LIFETIME]
        assert len(lifetime_findings) == 1
        assert lifetime_findings[0].severity == Severity.MEDIUM


# ─── Algorithm probe tests ────────────────────────────────────────────────────

class TestAlgorithmConfusionProbe:
    def test_flags_none_algorithm_as_critical(self, none_alg_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(none_alg_token)
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("none" in f.title.lower() for f in critical)

    def test_flags_algorithm_not_in_allowlist(self, valid_access_token):
        scanner = JWTSecurityScanner(allowed_algorithms=["ES256"])  # RS256 not allowed
        report = scanner.scan(valid_access_token)
        alg_findings = [f for f in report.findings if f.category == FindingCategory.ALGORITHM_CONFUSION]
        assert len(alg_findings) >= 1

    def test_flags_kid_injection(self, kid_injection_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(kid_injection_token)
        kid_findings = [f for f in report.findings if f.category == FindingCategory.KID_INJECTION]
        assert len(kid_findings) == 1
        assert kid_findings[0].severity == Severity.CRITICAL

    def test_warns_on_symmetric_algorithm(self):
        hs_token = _make_jwt(
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "user", "exp": int(time.time()) + 3600},
        )
        scanner = JWTSecurityScanner()
        report = scanner.scan(hs_token)
        alg_findings = [f for f in report.findings if f.category == FindingCategory.ALGORITHM_CONFUSION]
        assert len(alg_findings) >= 1


# ─── Scope probe tests ────────────────────────────────────────────────────────

class TestScopeOverflowProbe:
    def test_flags_wildcard_scopes(self, scope_overflow_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(scope_overflow_token)
        scope_findings = [f for f in report.findings if f.category == FindingCategory.SCOPE_OVERFLOW]
        assert len(scope_findings) >= 1
        severities = {f.severity for f in scope_findings}
        assert Severity.HIGH in severities

    def test_flags_unexpected_scopes(self, valid_access_token):
        scanner = JWTSecurityScanner(expected_scopes=["read:orders"])
        report = scanner.scan(valid_access_token)
        # valid_access_token has read:orders + write:orders; only read expected
        scope_findings = [f for f in report.findings if f.category == FindingCategory.SCOPE_OVERFLOW]
        extra_findings = [f for f in scope_findings if "unexpected" in f.title.lower()]
        assert len(extra_findings) >= 1

    def test_no_scope_findings_for_minimal_token(self, valid_access_token):
        scanner = JWTSecurityScanner(expected_scopes=["read:orders", "write:orders"])
        report = scanner.scan(valid_access_token)
        scope_findings = [f for f in report.findings if f.category == FindingCategory.SCOPE_OVERFLOW]
        assert len(scope_findings) == 0


# ─── Replay probe tests ───────────────────────────────────────────────────────

class TestReplayAttackProbe:
    def test_flags_missing_jti(self, no_expiry_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(no_expiry_token)
        replay_findings = [f for f in report.findings if f.category == FindingCategory.REPLAY_ATTACK]
        jti_findings = [f for f in replay_findings if "jti" in f.title.lower()]
        assert len(jti_findings) >= 1

    def test_flags_wrong_issuer(self, valid_access_token):
        scanner = JWTSecurityScanner(expected_issuer="https://different-auth.example.com")
        report = scanner.scan(valid_access_token)
        iss_findings = [f for f in report.findings if "issuer" in f.title.lower()]
        assert len(iss_findings) >= 1
        assert iss_findings[0].severity == Severity.HIGH

    def test_flags_wrong_audience(self, valid_access_token):
        scanner = JWTSecurityScanner(expected_audience="different-service.example.com")
        report = scanner.scan(valid_access_token)
        aud_findings = [f for f in report.findings if "audience" in f.title.lower() or "addressed" in f.title.lower()]
        assert len(aud_findings) >= 1


# ─── Report tests ─────────────────────────────────────────────────────────────

class TestScanReport:
    def test_risk_score_zero_for_clean_token(self, valid_access_token):
        scanner = JWTSecurityScanner(
            allowed_algorithms=["RS256"],
            expected_issuer="https://auth.example.com",
            expected_audience="api.example.com",
            expected_scopes=["read:orders", "write:orders"],
        )
        report = scanner.scan(valid_access_token)
        assert report.risk_score == 0.0

    def test_critical_finding_raises_risk_score(self, none_alg_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(none_alg_token)
        assert report.risk_score >= 25.0

    def test_report_serializes_to_dict(self, valid_access_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(valid_access_token)
        d = report.to_dict()
        assert "findings" in d
        assert "risk_score" in d
        assert "token" in d

    def test_summary_string_contains_severity_counts(self, none_alg_token):
        scanner = JWTSecurityScanner()
        report = scanner.scan(none_alg_token)
        summary = report.summary()
        assert "CRITICAL" in summary
        assert "Risk Score" in summary
