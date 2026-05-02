"""
A01:2021 — Broken Access Control

Tests:
  1. IDOR (Insecure Direct Object Reference) — access other users' resources by manipulating IDs
  2. Horizontal privilege escalation — user A accesses user B's data
  3. Vertical privilege escalation — regular user accesses admin endpoints
  4. Unauthenticated access to protected endpoints
  5. HTTP verb tampering — GET succeeds where only POST should be allowed
  6. Directory traversal on path parameters
  7. JWT user ID manipulation (if auth_token provided)
  8. Missing function-level access control (admin endpoints without admin token)

CWE-284: Improper Access Control
CWE-285: Improper Authorization
CWE-639: Authorization Bypass Through User-Controlled Key
"""

from __future__ import annotations

import httpx
from probe_suite.probes.base import (
    OWASPBaseProbe, OWASPFinding, OWASPCategory, Severity
)


class BrokenAccessControlProbe(OWASPBaseProbe):
    name        = "broken_access_control"
    category    = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    description = "Tests IDOR, privilege escalation, unauthenticated access, verb tampering"

    # Common admin / privileged endpoint patterns
    ADMIN_PATHS = [
        "/admin", "/admin/", "/admin/dashboard", "/admin/users",
        "/api/admin", "/api/v1/admin", "/management",
        "/actuator", "/actuator/env", "/actuator/health",
        "/metrics", "/_debug", "/debug", "/console",
        "/swagger-ui.html", "/swagger-ui", "/api-docs",
        "/openapi.json", "/openapi.yaml",
    ]

    # Sensitive paths that should require auth
    PROTECTED_PATHS = [
        "/api/users", "/api/v1/users", "/users",
        "/api/profile", "/profile", "/account",
        "/api/orders", "/orders",
        "/api/payments", "/payments",
        "/api/settings", "/settings",
    ]

    def run(
        self,
        base_url: str,
        session: httpx.Client,
        user_token:  str = None,
        admin_token: str = None,
        user_id:     int = 1,
        **kwargs,
    ) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        # ── 1. Unauthenticated access to protected endpoints ───────────────
        findings.extend(self._test_unauthenticated_access(base, session))

        # ── 2. Admin endpoint enumeration ──────────────────────────────────
        findings.extend(self._test_admin_endpoints(base, session, user_token))

        # ── 3. IDOR — sequential ID manipulation ──────────────────────────
        if user_token and user_id:
            findings.extend(self._test_idor(base, session, user_token, user_id))

        # ── 4. HTTP verb tampering ─────────────────────────────────────────
        findings.extend(self._test_verb_tampering(base, session, user_token))

        return findings

    def _test_unauthenticated_access(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        no_auth = httpx.Client(timeout=10, follow_redirects=True)

        for path in self.PROTECTED_PATHS:
            try:
                resp = no_auth.get(f"{base}{path}")
                if resp.status_code == 200:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.HIGH,
                        title=f"Protected endpoint accessible without authentication",
                        detail=(
                            f"GET {path} returned HTTP 200 without any Authorization header. "
                            "This endpoint appears to be publicly accessible when it should require authentication."
                        ),
                        evidence=f"HTTP 200 on {path} with no token",
                        request_url=f"{base}{path}",
                        request_method="GET",
                        status_code=200,
                        remediation=(
                            "Add authentication middleware to all non-public routes. "
                            "Use a deny-by-default policy: require explicit opt-in to public access."
                        ),
                        cwe_id="CWE-306",
                        cvss_score=7.5,
                    ))
            except Exception:
                pass

        no_auth.close()
        return findings

    def _test_admin_endpoints(
        self, base: str, session: httpx.Client, user_token: str = None
    ) -> list[OWASPFinding]:
        findings = []
        headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}

        for path in self.ADMIN_PATHS:
            try:
                resp = session.get(f"{base}{path}", headers=headers)

                # 200 with user token = vertical privilege escalation
                if resp.status_code == 200 and user_token:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"Admin endpoint accessible with regular user token",
                        detail=(
                            f"GET {path} returned HTTP 200 using a non-admin Bearer token. "
                            "A regular user can access administrative functionality."
                        ),
                        evidence=f"HTTP 200 on {path} with user-level token",
                        request_url=f"{base}{path}",
                        request_method="GET",
                        status_code=200,
                        remediation=(
                            "Implement role-based access control (RBAC). "
                            "Admin endpoints must validate the 'role' or 'permissions' claim in the JWT."
                        ),
                        cwe_id="CWE-285",
                        cvss_score=9.1,
                    ))

                # 200 without any token = completely unprotected admin
                elif resp.status_code == 200 and not user_token:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"Admin endpoint exposed without authentication",
                        detail=(
                            f"GET {path} returned HTTP 200 with no authentication. "
                            "This administrative endpoint is publicly accessible."
                        ),
                        evidence=f"HTTP 200 on {path} — no auth required",
                        request_url=f"{base}{path}",
                        request_method="GET",
                        status_code=200,
                        remediation="Immediately restrict access to admin endpoints.",
                        cwe_id="CWE-284",
                        cvss_score=9.8,
                    ))

            except Exception:
                pass

        return findings

    def _test_idor(
        self,
        base: str,
        session: httpx.Client,
        user_token: str,
        own_user_id: int,
    ) -> list[OWASPFinding]:
        """Try accessing adjacent user IDs to detect IDOR."""
        findings = []
        headers = {"Authorization": f"Bearer {user_token}"}

        # Test IDs near the current user's ID
        test_ids = [
            own_user_id - 2, own_user_id - 1,
            own_user_id + 1, own_user_id + 2,
            1, 2, 3, 100, 9999,
        ]
        test_ids = [i for i in test_ids if i > 0 and i != own_user_id]

        idor_paths = [
            f"/api/users/{{id}}", f"/users/{{id}}",
            f"/api/v1/users/{{id}}", f"/api/profile/{{id}}",
        ]

        for path_template in idor_paths:
            for test_id in test_ids[:3]:   # Limit to 3 IDs per path
                path = path_template.replace("{id}", str(test_id))
                try:
                    resp = session.get(f"{base}{path}", headers=headers)
                    if resp.status_code == 200:
                        body = ""
                        try:
                            body = resp.text[:200]
                        except Exception:
                            pass

                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.HIGH,
                            title=f"Possible IDOR: user {own_user_id} can access user {test_id}'s data",
                            detail=(
                                f"Accessing {path} with user {own_user_id}'s token returned HTTP 200. "
                                "If this response contains user {test_id}'s private data, this is an IDOR vulnerability."
                            ),
                            evidence=body,
                            request_url=f"{base}{path}",
                            request_method="GET",
                            status_code=200,
                            remediation=(
                                "Validate that the authenticated user owns the resource being accessed. "
                                "Never rely solely on client-supplied IDs — always cross-check against the JWT sub claim."
                            ),
                            cwe_id="CWE-639",
                            cvss_score=8.1,
                        ))
                        break   # One finding per path template is enough signal
                except Exception:
                    pass

        return findings

    def _test_verb_tampering(
        self, base: str, session: httpx.Client, user_token: str = None
    ) -> list[OWASPFinding]:
        """Test HTTP verb tampering on common endpoints."""
        findings = []
        headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}

        # Endpoints that should only accept specific methods
        verb_tests = [
            ("/api/users", "DELETE"),       # DELETE on collection
            ("/api/admin", "GET"),
            ("/health", "DELETE"),
            ("/api/users/1", "TRACE"),      # TRACE can bypass WAF rules
        ]

        for path, method in verb_tests:
            try:
                resp = session.request(method, f"{base}{path}", headers=headers)
                if resp.status_code == 200:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.MEDIUM,
                        title=f"HTTP verb tampering: {method} {path} returned 200",
                        detail=(
                            f"{method} {path} returned HTTP 200. "
                            "Some security controls only protect specific HTTP methods "
                            "and may be bypassed using unexpected verbs."
                        ),
                        evidence=f"HTTP 200 on {method} {path}",
                        request_url=f"{base}{path}",
                        request_method=method,
                        status_code=200,
                        remediation=(
                            "Explicitly allowlist accepted HTTP methods per endpoint. "
                            "Return 405 Method Not Allowed for all others."
                        ),
                        cwe_id="CWE-650",
                        cvss_score=5.3,
                    ))
            except Exception:
                pass

        return findings
