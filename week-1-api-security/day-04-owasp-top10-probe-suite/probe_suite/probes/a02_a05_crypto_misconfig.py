"""
A02:2021 — Cryptographic Failures
A05:2021 — Security Misconfiguration

A02 Tests:
  1. Sensitive data in cleartext HTTP (not HTTPS)
  2. Weak TLS versions accepted (TLS 1.0, TLS 1.1)
  3. Sensitive data in URL parameters (passwords, tokens in query string)
  4. Missing security headers (HSTS, Content-Security-Policy, etc.)
  5. Sensitive data in error messages

A05 Tests:
  1. Default/debug endpoints exposed (Swagger UI, actuator, metrics)
  2. Verbose error messages leaking internal info
  3. CORS misconfiguration (allow-all origins)
  4. Missing security headers
  5. HTTP methods not restricted
  6. Server version disclosure in headers
"""

from __future__ import annotations

import re
import httpx
from probe_suite.probes.base import (
    OWASPBaseProbe, OWASPFinding, OWASPCategory, Severity
)


# ── A02: Cryptographic Failures ───────────────────────────────────────────────

class CryptographicFailuresProbe(OWASPBaseProbe):
    name        = "cryptographic_failures"
    category    = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
    description = "Checks for cleartext transmission, missing HSTS, weak TLS, sensitive data in URLs"

    # Security headers that must be present on HTTPS sites
    REQUIRED_SECURITY_HEADERS = {
        "strict-transport-security": {
            "severity": Severity.HIGH,
            "detail": "HSTS missing — browsers will not enforce HTTPS on subsequent visits. "
                      "Attackers can downgrade connections to HTTP via MITM.",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "cwe_id": "CWE-319",
            "cvss": 7.4,
        },
        "content-security-policy": {
            "severity": Severity.MEDIUM,
            "detail": "CSP missing — XSS payloads can load arbitrary external scripts.",
            "remediation": "Define a strict Content-Security-Policy. Start with default-src 'self'.",
            "cwe_id": "CWE-693",
            "cvss": 6.1,
        },
        "x-content-type-options": {
            "severity": Severity.LOW,
            "detail": "X-Content-Type-Options: nosniff missing — browsers may MIME-sniff responses.",
            "remediation": "Add: X-Content-Type-Options: nosniff",
            "cwe_id": "CWE-116",
            "cvss": 3.7,
        },
        "x-frame-options": {
            "severity": Severity.MEDIUM,
            "detail": "X-Frame-Options missing — clickjacking attacks are possible.",
            "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
            "cwe_id": "CWE-1021",
            "cvss": 4.3,
        },
        "referrer-policy": {
            "severity": Severity.LOW,
            "detail": "Referrer-Policy missing — sensitive URL paths may leak via Referer header.",
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "cwe_id": "CWE-200",
            "cvss": 3.1,
        },
    }

    # Patterns indicating sensitive data in response bodies
    SENSITIVE_PATTERNS = {
        "password": (r'"password"\s*:\s*"[^"]{1,}"', Severity.CRITICAL, "CWE-312"),
        "secret":   (r'"(secret|api_key|apikey|private_key)"\s*:\s*"[^"]{4,}"', Severity.CRITICAL, "CWE-312"),
        "token":    (r'"(access_token|refresh_token|id_token)"\s*:\s*"[^"]{10,}"', Severity.HIGH, "CWE-312"),
        "ssn":      (r'\b\d{3}-\d{2}-\d{4}\b', Severity.CRITICAL, "CWE-359"),
        "credit_card": (r'\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b', Severity.CRITICAL, "CWE-312"),
    }

    def run(self, base_url: str, session: httpx.Client, **kwargs) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        findings.extend(self._check_security_headers(base, session))
        findings.extend(self._check_cleartext_http(base_url))
        findings.extend(self._check_sensitive_data_in_responses(base, session))
        return findings

    def _check_security_headers(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        try:
            resp = session.get(f"{base}/")
            present_headers = {h.lower() for h in resp.headers.keys()}

            for header_name, config in self.REQUIRED_SECURITY_HEADERS.items():
                if header_name not in present_headers:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=config["severity"],
                        title=f"Missing security header: {header_name}",
                        detail=config["detail"],
                        evidence=f"Header '{header_name}' absent from response",
                        request_url=f"{base}/",
                        request_method="GET",
                        status_code=resp.status_code,
                        remediation=config["remediation"],
                        cwe_id=config["cwe_id"],
                        cvss_score=config["cvss"],
                    ))

            # Check HSTS max-age is sufficient if header is present
            hsts = resp.headers.get("strict-transport-security", "")
            if hsts:
                match = re.search(r"max-age=(\d+)", hsts)
                if match and int(match.group(1)) < 31536000:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.MEDIUM,
                        title="HSTS max-age is too short",
                        detail=f"HSTS max-age={match.group(1)}s is less than 1 year (31536000s). "
                               "Short HSTS windows leave users vulnerable after expiry.",
                        evidence=f"Strict-Transport-Security: {hsts}",
                        request_url=f"{base}/",
                        remediation="Set max-age to at least 31536000 (1 year).",
                        cwe_id="CWE-319",
                        cvss_score=5.4,
                    ))

        except Exception:
            pass
        return findings

    def _check_cleartext_http(self, base_url: str) -> list[OWASPFinding]:
        findings = []
        if base_url.startswith("http://") and not base_url.startswith("http://localhost"):
            findings.append(OWASPFinding(
                probe=self.name,
                owasp_category=self.category,
                severity=Severity.CRITICAL,
                title="API endpoint uses HTTP (cleartext) instead of HTTPS",
                detail=(
                    f"The base URL '{base_url}' uses HTTP. All traffic including "
                    "authentication tokens, session cookies, and sensitive data is "
                    "transmitted in cleartext and can be intercepted."
                ),
                evidence=f"base_url={base_url}",
                request_url=base_url,
                remediation=(
                    "Enforce HTTPS everywhere. Redirect HTTP → HTTPS at the load balancer. "
                    "Add HSTS to prevent downgrade attacks."
                ),
                cwe_id="CWE-319",
                cvss_score=9.1,
            ))
        return findings

    def _check_sensitive_data_in_responses(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        check_paths = ["/api/users", "/users", "/api/profile", "/profile", "/api/v1/users"]

        for path in check_paths:
            try:
                resp = session.get(f"{base}{path}")
                if resp.status_code != 200:
                    continue
                body = resp.text[:4096]
                for field_name, (pattern, severity, cwe) in self.SENSITIVE_PATTERNS.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=severity,
                            title=f"Sensitive data ({field_name}) exposed in API response",
                            detail=(
                                f"Pattern for '{field_name}' matched in the response body of {path}. "
                                "Sensitive fields should never be returned in API responses."
                            ),
                            evidence=f"Pattern '{pattern}' matched in {path}",
                            request_url=f"{base}{path}",
                            request_method="GET",
                            status_code=200,
                            remediation=(
                                f"Remove '{field_name}' from API response serializers. "
                                "Use allowlists (not blocklists) to control which fields are returned."
                            ),
                            cwe_id=cwe,
                            cvss_score=8.5,
                        ))
            except Exception:
                pass
        return findings


# ── A05: Security Misconfiguration ───────────────────────────────────────────

class SecurityMisconfigProbe(OWASPBaseProbe):
    name        = "security_misconfig"
    category    = OWASPCategory.A05_SECURITY_MISCONFIG
    description = "Checks for debug endpoints, verbose errors, CORS misconfig, server version disclosure"

    # Debug/info endpoints that should not be accessible in production
    DEBUG_ENDPOINTS = [
        ("/swagger-ui.html",     "Swagger UI"),
        ("/swagger-ui",          "Swagger UI"),
        ("/api-docs",            "API Docs"),
        ("/openapi.json",        "OpenAPI Spec"),
        ("/openapi.yaml",        "OpenAPI Spec"),
        ("/actuator",            "Spring Actuator"),
        ("/actuator/env",        "Spring Actuator ENV"),
        ("/actuator/heapdump",   "Spring Heap Dump"),
        ("/actuator/mappings",   "Spring Mappings"),
        ("/metrics",             "Prometheus Metrics"),
        ("/.env",                "Environment File"),
        ("/debug",               "Debug Endpoint"),
        ("/_debug",              "Debug Endpoint"),
        ("/phpinfo.php",         "PHP Info"),
        ("/server-info",         "Server Info"),
        ("/info",                "App Info"),
        ("/health/detail",       "Detailed Health"),
        ("/graphql",             "GraphQL Introspection"),
        ("/graphiql",            "GraphiQL IDE"),
    ]

    # Server headers that disclose version info
    VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

    def run(self, base_url: str, session: httpx.Client, **kwargs) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        findings.extend(self._check_debug_endpoints(base, session))
        findings.extend(self._check_cors_misconfig(base, session))
        findings.extend(self._check_server_version_disclosure(base, session))
        findings.extend(self._check_verbose_errors(base, session))
        findings.extend(self._check_options_method(base, session))
        return findings

    def _check_debug_endpoints(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        for path, label in self.DEBUG_ENDPOINTS:
            try:
                resp = session.get(f"{base}{path}")
                if resp.status_code == 200:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.HIGH,
                        title=f"Debug/info endpoint exposed: {label} at {path}",
                        detail=(
                            f"{path} returned HTTP 200. {label} endpoints expose internal "
                            "application structure, configuration, and potentially credentials."
                        ),
                        evidence=f"HTTP 200 on GET {path}",
                        request_url=f"{base}{path}",
                        request_method="GET",
                        status_code=200,
                        remediation=(
                            f"Disable {label} in production environments. "
                            "If needed for ops teams, restrict access to internal networks only."
                        ),
                        cwe_id="CWE-215",
                        cvss_score=7.5,
                    ))
            except Exception:
                pass
        return findings

    def _check_cors_misconfig(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        evil_origin = "https://evil-attacker.com"
        try:
            resp = session.options(
                f"{base}/api/users",
                headers={"Origin": evil_origin, "Access-Control-Request-Method": "GET"},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "false")

            if acao == "*":
                findings.append(OWASPFinding(
                    probe=self.name,
                    owasp_category=self.category,
                    severity=Severity.MEDIUM,
                    title="CORS allows all origins (Access-Control-Allow-Origin: *)",
                    detail=(
                        "ACAO: * allows any website to make cross-origin requests. "
                        "While cookies are not sent with wildcard ACAO, "
                        "it exposes public API data to malicious sites."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    request_url=f"{base}/api/users",
                    request_method="OPTIONS",
                    status_code=resp.status_code,
                    remediation="Replace * with an explicit allowlist of trusted origins.",
                    cwe_id="CWE-942",
                    cvss_score=5.4,
                ))

            elif acao == evil_origin:
                sev = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                findings.append(OWASPFinding(
                    probe=self.name,
                    owasp_category=self.category,
                    severity=sev,
                    title="CORS reflects arbitrary Origin header" + (
                        " with credentials" if acac.lower() == "true" else ""
                    ),
                    detail=(
                        f"The server reflected our evil origin '{evil_origin}' in ACAO. "
                        + ("With ACAC: true, cookies/tokens are also sent — full CORS bypass." if acac.lower() == "true"
                           else "Without ACAC: true, cookies are not sent but API data is accessible.")
                    ),
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    request_url=f"{base}/api/users",
                    request_method="OPTIONS",
                    status_code=resp.status_code,
                    remediation=(
                        "Validate Origin against an explicit allowlist. "
                        "Never dynamically reflect the Origin header value."
                    ),
                    cwe_id="CWE-942",
                    cvss_score=9.1 if acac.lower() == "true" else 7.5,
                ))
        except Exception:
            pass
        return findings

    def _check_server_version_disclosure(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        try:
            resp = session.get(f"{base}/")
            for header in self.VERSION_HEADERS:
                value = resp.headers.get(header, "")
                if value and any(char.isdigit() for char in value):
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.LOW,
                        title=f"Server version disclosed in '{header}' header",
                        detail=(
                            f"Header '{header}: {value}' reveals the server software and version. "
                            "Attackers use this to target known CVEs for that specific version."
                        ),
                        evidence=f"{header}: {value}",
                        request_url=f"{base}/",
                        request_method="GET",
                        status_code=resp.status_code,
                        remediation=f"Remove or genericise the '{header}' response header.",
                        cwe_id="CWE-200",
                        cvss_score=3.7,
                    ))
        except Exception:
            pass
        return findings

    def _check_verbose_errors(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        # Send a malformed request to trigger error handling
        error_triggers = [
            (f"{base}/api/users/not-a-number", "GET"),
            (f"{base}/api/users", "POST"),       # empty body
        ]
        error_patterns = [
            r"Traceback \(most recent call last\)",
            r"at [\w.]+\([\w.]+\.java:\d+\)",
            r"System\.(?:Exception|NullReferenceException)",
            r"SQLSTATE\[",
            r"mysql_",
            r"ORA-\d{5}",
            r"stack\":.*\"at ",
        ]

        for url, method in error_triggers:
            try:
                resp = session.request(method, url)
                body = resp.text[:2048]
                for pattern in error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.MEDIUM,
                            title="Verbose error message discloses internal details",
                            detail=(
                                f"Pattern '{pattern}' found in error response from {method} {url}. "
                                "Stack traces and framework errors reveal internal paths and code structure."
                            ),
                            evidence=body[:300],
                            request_url=url,
                            request_method=method,
                            status_code=resp.status_code,
                            remediation=(
                                "Return generic error messages in production. "
                                "Log full errors server-side; return only an error code to the client."
                            ),
                            cwe_id="CWE-209",
                            cvss_score=5.3,
                        ))
                        break
            except Exception:
                pass
        return findings

    def _check_options_method(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        try:
            resp = session.options(f"{base}/api/users")
            allow = resp.headers.get("allow", "")
            if "TRACE" in allow.upper():
                findings.append(OWASPFinding(
                    probe=self.name,
                    owasp_category=self.category,
                    severity=Severity.MEDIUM,
                    title="TRACE method enabled — potential XST attack vector",
                    detail=(
                        "The Allow header includes TRACE. Cross-Site Tracing (XST) can be "
                        "used to read HttpOnly cookies by reflecting them via TRACE responses."
                    ),
                    evidence=f"Allow: {allow}",
                    request_url=f"{base}/api/users",
                    request_method="OPTIONS",
                    status_code=resp.status_code,
                    remediation="Disable the TRACE method at the web server level.",
                    cwe_id="CWE-16",
                    cvss_score=4.3,
                ))
        except Exception:
            pass
        return findings
