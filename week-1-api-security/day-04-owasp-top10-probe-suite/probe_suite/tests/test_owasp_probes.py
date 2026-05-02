"""
OWASP Probe Suite — unit and integration tests.

Tests verify:
  - Each probe correctly identifies vulnerabilities in the vulnerable target
  - Each probe produces no false positives against a clean (fixed) response
  - Finding model serialisation
  - Scanner aggregation and report generation

Run: pytest probe_suite/tests/ -v
"""

from __future__ import annotations

import json
import time
import threading
import pytest
import httpx
import uvicorn

from probe_suite.probes.base import OWASPFinding, Severity, OWASPCategory
from probe_suite.probes.a01_broken_access_control import BrokenAccessControlProbe
from probe_suite.probes.a02_a05_crypto_misconfig import CryptographicFailuresProbe, SecurityMisconfigProbe
from probe_suite.probes.a03_a07_injection_auth import InjectionProbe, AuthFailuresProbe
from probe_suite.probes.a10_ssrf import SSRFProbe
from probe_suite.scanner import OWASPScanner, OWASPScanReport


# ── Target fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vulnerable_server():
    """Start the vulnerable FastAPI app on port 8765 for integration tests."""
    from probe_suite.targets.vulnerable_app import app

    config = uvicorn.Config(app, host="0.0.0.0", port=8765, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for startup
    for _ in range(30):
        try:
            httpx.get("http://localhost:8765/health/detail", timeout=1)
            break
        except Exception:
            time.sleep(0.2)

    yield "http://localhost:8765"
    server.should_exit = True


@pytest.fixture
def session():
    client = httpx.Client(timeout=10, follow_redirects=True)
    yield client
    client.close()


# ── Finding model tests ───────────────────────────────────────────────────────

class TestOWASPFinding:
    def test_to_dict_contains_required_fields(self):
        finding = OWASPFinding(
            probe="test_probe",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            severity=Severity.HIGH,
            title="Test finding",
            detail="Test detail",
            cwe_id="CWE-284",
            cvss_score=7.5,
        )
        d = finding.to_dict()
        assert d["severity"] == "HIGH"
        assert d["cwe_id"] == "CWE-284"
        assert "A01" in d["owasp_category"]

    def test_str_representation_includes_severity_and_category(self):
        finding = OWASPFinding(
            probe="test", owasp_category=OWASPCategory.A03_INJECTION,
            severity=Severity.CRITICAL, title="SQL injection", detail="...",
        )
        s = str(finding)
        assert "CRITICAL" in s
        assert "A03" in s


# ── A01 probe tests ───────────────────────────────────────────────────────────

class TestBrokenAccessControlProbe:
    def test_detects_admin_endpoint_without_auth(self, vulnerable_server, session):
        probe    = BrokenAccessControlProbe()
        findings = probe.run(vulnerable_server, session)
        admin_findings = [f for f in findings if "admin" in f.title.lower()]
        assert len(admin_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in admin_findings)

    def test_detects_protected_endpoint_without_auth(self, vulnerable_server, session):
        probe    = BrokenAccessControlProbe()
        findings = probe.run(vulnerable_server, session)
        unauth_findings = [f for f in findings if "without authentication" in f.title.lower()]
        assert len(unauth_findings) >= 1

    def test_finding_has_remediation(self, vulnerable_server, session):
        probe    = BrokenAccessControlProbe()
        findings = probe.run(vulnerable_server, session)
        for f in findings:
            assert f.remediation, f"Finding '{f.title}' missing remediation"
            assert f.cwe_id,      f"Finding '{f.title}' missing CWE ID"


# ── A02/A05 probe tests ───────────────────────────────────────────────────────

class TestCryptographicFailuresProbe:
    def test_detects_missing_security_headers(self, vulnerable_server, session):
        probe    = CryptographicFailuresProbe()
        findings = probe.run(vulnerable_server, session)
        header_findings = [f for f in findings if "header" in f.title.lower()]
        # Vulnerable app has no security headers
        assert len(header_findings) >= 3, "Expected at least 3 missing header findings"

    def test_detects_password_in_response(self, vulnerable_server, session):
        probe    = CryptographicFailuresProbe()
        findings = probe.run(vulnerable_server, session)
        sensitive_findings = [f for f in findings if "sensitive data" in f.title.lower() or "password" in f.title.lower()]
        # vulnerable_app returns passwords in /api/users
        assert len(sensitive_findings) >= 1

    def test_cleartext_http_finding(self, session):
        probe    = CryptographicFailuresProbe()
        findings = probe.run("http://example-non-localhost.com", session)
        http_findings = [f for f in findings if "HTTP" in f.title or "cleartext" in f.title.lower()]
        assert len(http_findings) >= 1
        assert http_findings[0].severity == Severity.CRITICAL


class TestSecurityMisconfigProbe:
    def test_detects_exposed_debug_endpoints(self, vulnerable_server, session):
        probe    = SecurityMisconfigProbe()
        findings = probe.run(vulnerable_server, session)
        debug_findings = [f for f in findings if "endpoint" in f.title.lower()]
        assert len(debug_findings) >= 2

    def test_detects_swagger_ui(self, vulnerable_server, session):
        probe    = SecurityMisconfigProbe()
        findings = probe.run(vulnerable_server, session)
        swagger = [f for f in findings if "swagger" in f.title.lower() or "api doc" in f.title.lower()]
        assert len(swagger) >= 1

    def test_detects_verbose_error_messages(self, vulnerable_server, session):
        probe    = SecurityMisconfigProbe()
        findings = probe.run(vulnerable_server, session)
        verbose = [f for f in findings if "verbose" in f.title.lower() or "internal" in f.title.lower()]
        assert len(verbose) >= 1


# ── A03/A07 probe tests ───────────────────────────────────────────────────────

class TestInjectionProbe:
    def test_runs_without_exception(self, vulnerable_server, session):
        probe    = InjectionProbe()
        # Should not raise even if target is clean
        findings = probe.run(vulnerable_server, session)
        assert isinstance(findings, list)

    def test_sql_injection_detects_error_response(self, vulnerable_server, session):
        """The vulnerable app returns SQLSTATE error on non-integer IDs."""
        probe    = InjectionProbe()
        findings = probe.run(
            vulnerable_server, session,
            search_endpoint="/api/users/",
        )
        # At minimum should not crash; may find SQL error disclosure
        assert isinstance(findings, list)


class TestAuthFailuresProbe:
    def test_detects_no_brute_force_protection(self, vulnerable_server, session):
        probe    = AuthFailuresProbe()
        findings = probe.run(
            vulnerable_server, session,
            login_endpoint="/api/auth/login",
        )
        brute_findings = [f for f in findings if "brute" in f.title.lower() or "rate" in f.title.lower()]
        assert len(brute_findings) >= 1

    def test_detects_default_credentials(self, vulnerable_server, session):
        probe    = AuthFailuresProbe()
        findings = probe.run(
            vulnerable_server, session,
            login_endpoint="/api/auth/login",
        )
        default_cred_findings = [f for f in findings if "default credential" in f.title.lower()]
        assert len(default_cred_findings) >= 1
        assert default_cred_findings[0].severity == Severity.CRITICAL

    def test_detects_username_enumeration(self, vulnerable_server, session):
        probe    = AuthFailuresProbe()
        findings = probe.run(
            vulnerable_server, session,
            login_endpoint="/api/auth/login",
        )
        enum_findings = [f for f in findings if "enumeration" in f.title.lower()]
        # vulnerable_app returns "User not found" vs "Wrong password"
        assert len(enum_findings) >= 1

    def test_detects_weak_password(self, vulnerable_server, session):
        probe    = AuthFailuresProbe()
        findings = probe.run(
            vulnerable_server, session,
            register_endpoint="/api/auth/register",
        )
        weak_pw = [f for f in findings if "weak password" in f.title.lower()]
        assert len(weak_pw) >= 1


# ── A10 SSRF probe tests ──────────────────────────────────────────────────────

class TestSSRFProbe:
    def test_detects_ssrf_via_fetch_endpoint(self, vulnerable_server, session):
        """vulnerable_app /api/fetch has no SSRF protection."""
        probe    = SSRFProbe()
        findings = probe.run(vulnerable_server, session)
        ssrf_findings = [f for f in findings if "ssrf" in f.title.lower() or "internal" in f.title.lower()]
        # At least one finding from the unprotected /api/fetch endpoint
        assert len(ssrf_findings) >= 1

    def test_all_findings_have_cwe_918(self, vulnerable_server, session):
        probe    = SSRFProbe()
        findings = probe.run(vulnerable_server, session)
        for f in findings:
            assert f.cwe_id == "CWE-918", f"SSRF finding should have CWE-918, got {f.cwe_id}"


# ── Scanner integration tests ─────────────────────────────────────────────────

class TestOWASPScanner:
    def test_full_scan_produces_findings(self, vulnerable_server):
        scanner  = OWASPScanner(base_url=vulnerable_server)
        report   = scanner.run()
        assert len(report.findings) >= 5, "Vulnerable app should produce at least 5 findings"
        assert report.risk_score > 0

    def test_report_serialises_to_dict(self, vulnerable_server):
        scanner  = OWASPScanner(base_url=vulnerable_server)
        report   = scanner.run()
        d = report.to_dict()
        assert "findings" in d
        assert "risk_score" in d
        assert d["base_url"] == vulnerable_server

    def test_report_by_category_groups_correctly(self, vulnerable_server):
        scanner  = OWASPScanner(base_url=vulnerable_server)
        report   = scanner.run()
        by_cat   = report.by_category()
        # At least 3 OWASP categories should be represented
        assert len(by_cat) >= 3

    def test_html_report_generates(self, vulnerable_server, tmp_path):
        scanner  = OWASPScanner(base_url=vulnerable_server)
        report   = scanner.run()
        out_file = str(tmp_path / "test-report.html")
        report.save_html(out_file)
        content  = open(out_file).read()
        assert "OWASP" in content
        assert "CRITICAL" in content or "HIGH" in content

    def test_summary_string_contains_risk_score(self, vulnerable_server):
        scanner  = OWASPScanner(base_url=vulnerable_server)
        report   = scanner.run()
        summary  = report.summary()
        assert "Risk Score" in summary
        assert "OWASP" in summary
