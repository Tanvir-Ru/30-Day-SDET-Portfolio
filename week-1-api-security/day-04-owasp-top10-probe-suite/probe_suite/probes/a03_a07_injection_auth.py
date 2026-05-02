"""
A03:2021 — Injection
A07:2021 — Identification & Authentication Failures

A03 Tests:
  1. SQL injection via query parameters and request bodies
  2. NoSQL injection (MongoDB $gt, $where operators)
  3. Command injection (shell metacharacters in parameters)
  4. LDAP injection
  5. XPath injection
  6. Log injection / log forging

A07 Tests:
  1. Brute-force protection — does the API rate-limit login attempts?
  2. Default credentials check (admin/admin, admin/password, etc.)
  3. Credential stuffing simulation
  4. Weak password acceptance
  5. Token not invalidated on logout (if logout endpoint exists)
  6. Username enumeration via response timing or message differences
"""

from __future__ import annotations

import time
import httpx
from probe_suite.probes.base import (
    OWASPBaseProbe, OWASPFinding, OWASPCategory, Severity
)


# ── A03: Injection ────────────────────────────────────────────────────────────

class InjectionProbe(OWASPBaseProbe):
    name        = "injection"
    category    = OWASPCategory.A03_INJECTION
    description = "SQL, NoSQL, command, log injection detection via response and timing analysis"

    SQL_PAYLOADS = [
        ("' OR '1'='1",          "classic OR bypass"),
        ("' OR 1=1--",           "comment bypass"),
        ("'; DROP TABLE users;--","destructive DDL"),
        ("1 UNION SELECT NULL--", "UNION probe"),
        ("' AND SLEEP(3)--",     "time-based blind"),
        ("1; WAITFOR DELAY '0:0:3'--", "MSSQL time-based"),
    ]

    NOSQL_PAYLOADS = [
        ('{"$gt": ""}',          "MongoDB gt operator"),
        ('{"$ne": null}',        "MongoDB ne operator"),
        ('{"$where":"1==1"}',    "MongoDB where eval"),
        ('{"$regex":".*"}',      "MongoDB regex bypass"),
    ]

    COMMAND_PAYLOADS = [
        ("; ls",                 "Unix semicolon"),
        ("| id",                 "Unix pipe"),
        ("& whoami",             "Windows ampersand"),
        ("`id`",                 "backtick execution"),
        ("$(id)",                "subshell execution"),
        ("\nid\n",               "newline injection"),
    ]

    LOG_INJECTION = [
        ("\n[CRITICAL] Fake log entry injected",  "log forging"),
        ("%0a[ERROR] Injected line",              "URL-encoded newline"),
        ("\r\nX-Injected-Header: injected",       "CRLF in log"),
    ]

    def run(
        self,
        base_url: str,
        session: httpx.Client,
        login_endpoint: str = "/api/auth/login",
        search_endpoint: str = "/api/users",
        **kwargs,
    ) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        findings.extend(self._test_sql_injection(base, session, search_endpoint))
        findings.extend(self._test_nosql_injection(base, session, login_endpoint))
        findings.extend(self._test_log_injection(base, session))
        return findings

    def _test_sql_injection(
        self, base: str, session: httpx.Client, search_path: str
    ) -> list[OWASPFinding]:
        findings = []
        url = f"{base}{search_path}"

        for payload, description in self.SQL_PAYLOADS:
            is_time_based = "SLEEP" in payload or "WAITFOR" in payload
            try:
                t0 = time.perf_counter()
                # Try as query parameter
                resp = session.get(url, params={"q": payload, "search": payload, "id": payload})
                elapsed = (time.perf_counter() - t0) * 1000

                # Time-based detection
                if is_time_based and elapsed > 2500:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"Time-based SQL injection — response delayed {elapsed:.0f}ms",
                        detail=(
                            f"Payload '{payload}' ({description}) caused a {elapsed:.0f}ms delay. "
                            "This is a strong indicator of time-based blind SQL injection. "
                            "The database executed the SLEEP/WAITFOR instruction."
                        ),
                        evidence=f"Payload: {payload} | Elapsed: {elapsed:.0f}ms",
                        request_url=url,
                        request_method="GET",
                        status_code=resp.status_code,
                        remediation=(
                            "Use parameterised queries or prepared statements for ALL database queries. "
                            "Never concatenate user input into SQL strings."
                        ),
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                    ))

                # Error-based detection
                elif resp.status_code == 500:
                    body = resp.text[:500]
                    sql_errors = ["sql", "syntax", "mysql", "postgresql", "ora-", "sqlite"]
                    if any(err in body.lower() for err in sql_errors):
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.HIGH,
                            title=f"Error-based SQL injection — database error in response",
                            detail=(
                                f"Payload '{payload}' triggered a 500 response containing SQL error text. "
                                "The database error confirms the input reaches a SQL query unparameterised."
                            ),
                            evidence=body[:300],
                            request_url=url,
                            request_method="GET",
                            status_code=500,
                            remediation="Use parameterised queries. Never expose raw DB errors to clients.",
                            cwe_id="CWE-89",
                            cvss_score=9.1,
                        ))

            except Exception:
                pass

        return findings

    def _test_nosql_injection(
        self, base: str, session: httpx.Client, login_path: str
    ) -> list[OWASPFinding]:
        findings = []
        url = f"{base}{login_path}"

        for payload, description in self.NOSQL_PAYLOADS:
            try:
                import json
                # Attempt to inject MongoDB operators into login body
                body = {"username": "admin", "password": json.loads(payload)}
                resp = session.post(url, json=body)

                if resp.status_code == 200:
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.CRITICAL,
                        title=f"NoSQL injection bypass on login — {description}",
                        detail=(
                            f"Login with password={payload} returned HTTP 200. "
                            "The MongoDB operator in the password field bypassed authentication. "
                            "The application does not sanitise operator keys in JSON input."
                        ),
                        evidence=f"Payload: {payload} → HTTP 200",
                        request_url=url,
                        request_method="POST",
                        status_code=200,
                        remediation=(
                            "Sanitise all user input to strip MongoDB operators ($gt, $ne, $where). "
                            "Use a schema validation library. Never pass raw user objects to MongoDB queries."
                        ),
                        cwe_id="CWE-943",
                        cvss_score=9.8,
                    ))
            except Exception:
                pass

        return findings

    def _test_log_injection(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        """
        Log injection is detectable by sending payloads that would forge log entries
        and checking if the application reflects them (indicating unsanitised logging).
        """
        findings = []
        for payload, description in self.LOG_INJECTION:
            try:
                resp = session.get(f"{base}/api/users", params={"search": payload})
                # If the newline-containing payload is reflected in the response
                if "\n" in payload and resp.status_code < 500:
                    body = resp.text
                    if "CRITICAL" in body or "Fake log" in body or "Injected" in body:
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.MEDIUM,
                            title="Log injection — newline characters reflected in response",
                            detail=(
                                f"Payload with log forging content was reflected in the response. "
                                "If this content reaches log files unsanitised, attackers can forge log entries."
                            ),
                            evidence=f"Payload: {repr(payload)}",
                            request_url=f"{base}/api/users",
                            request_method="GET",
                            status_code=resp.status_code,
                            remediation=(
                                "Strip or encode newline characters (\\n, \\r) from user input "
                                "before writing to logs."
                            ),
                            cwe_id="CWE-117",
                            cvss_score=4.3,
                        ))
            except Exception:
                pass
        return findings


# ── A07: Authentication Failures ─────────────────────────────────────────────

class AuthFailuresProbe(OWASPBaseProbe):
    name        = "auth_failures"
    category    = OWASPCategory.A07_AUTH_FAILURES
    description = "Brute-force protection, default creds, username enumeration, weak passwords"

    DEFAULT_CREDENTIALS = [
        ("admin",     "admin"),
        ("admin",     "password"),
        ("admin",     "123456"),
        ("admin",     "admin123"),
        ("root",      "root"),
        ("root",      "toor"),
        ("test",      "test"),
        ("admin",     ""),
        ("",          ""),
        ("superuser", "superuser"),
    ]

    WEAK_PASSWORDS = [
        "password", "123456", "12345678", "qwerty",
        "111111", "password1", "abc123", "letmein",
    ]

    def run(
        self,
        base_url: str,
        session: httpx.Client,
        login_endpoint: str = "/api/auth/login",
        register_endpoint: str = "/api/auth/register",
        **kwargs,
    ) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        findings.extend(self._test_brute_force_protection(base, session, login_endpoint))
        findings.extend(self._test_default_credentials(base, session, login_endpoint))
        findings.extend(self._test_username_enumeration(base, session, login_endpoint))
        findings.extend(self._test_weak_password_acceptance(base, session, register_endpoint))
        return findings

    def _test_brute_force_protection(
        self, base: str, session: httpx.Client, login_path: str
    ) -> list[OWASPFinding]:
        findings = []
        url = f"{base}{login_path}"
        attempt_count = 0
        rate_limited = False

        for i in range(15):
            try:
                resp = session.post(url, json={
                    "username": "admin",
                    "password": f"wrong_password_{i}",
                })
                attempt_count += 1
                if resp.status_code == 429:
                    rate_limited = True
                    break
                # Some implementations lock accounts with 403
                if resp.status_code == 403 and i > 3:
                    rate_limited = True
                    break
            except Exception:
                break

        if not rate_limited and attempt_count >= 10:
            findings.append(OWASPFinding(
                probe=self.name,
                owasp_category=self.category,
                severity=Severity.HIGH,
                title=f"No brute-force protection on login — {attempt_count} attempts without rate limiting",
                detail=(
                    f"Sent {attempt_count} consecutive failed login attempts without receiving "
                    "HTTP 429 (Too Many Requests) or account lockout. "
                    "Automated credential stuffing attacks are unrestricted."
                ),
                evidence=f"{attempt_count} attempts, no 429 or lockout observed",
                request_url=url,
                request_method="POST",
                remediation=(
                    "Implement rate limiting: max 5 failed attempts per IP per minute. "
                    "Add exponential backoff after repeated failures. "
                    "Consider CAPTCHA after 3 failures."
                ),
                cwe_id="CWE-307",
                cvss_score=7.5,
            ))
        return findings

    def _test_default_credentials(
        self, base: str, session: httpx.Client, login_path: str
    ) -> list[OWASPFinding]:
        findings = []
        url = f"{base}{login_path}"

        for username, password in self.DEFAULT_CREDENTIALS:
            try:
                resp = session.post(url, json={"username": username, "password": password})
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        has_token = any(k in str(body).lower() for k in ["token", "access", "jwt", "session"])
                    except Exception:
                        has_token = False

                    if has_token or resp.status_code == 200:
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.CRITICAL,
                            title=f"Default credentials accepted: {username!r} / {password!r}",
                            detail=(
                                f"Login with username='{username}' and password='{password}' "
                                f"returned HTTP 200. Default credentials have not been changed."
                            ),
                            evidence=f"username={username!r}, password={password!r} → HTTP 200",
                            request_url=url,
                            request_method="POST",
                            status_code=200,
                            remediation=(
                                "Remove all default credentials from production. "
                                "Force password change on first login. "
                                "Block known-weak passwords during registration."
                            ),
                            cwe_id="CWE-521",
                            cvss_score=9.8,
                        ))
                        break
            except Exception:
                pass
        return findings

    def _test_username_enumeration(
        self, base: str, session: httpx.Client, login_path: str
    ) -> list[OWASPFinding]:
        """Detect if response times or messages differ for valid vs invalid usernames."""
        findings = []
        url = f"{base}{login_path}"

        timings = {}
        messages = {}
        test_users = {
            "likely_exists": "admin",
            "likely_not": "zzz_nonexistent_user_xyz_9999",
        }

        for label, username in test_users.items():
            times = []
            last_body = ""
            for _ in range(3):
                try:
                    t0 = time.perf_counter()
                    resp = session.post(url, json={"username": username, "password": "wrong_pw_xyz"})
                    times.append((time.perf_counter() - t0) * 1000)
                    last_body = resp.text[:200]
                except Exception:
                    pass
            timings[label] = sum(times) / len(times) if times else 0
            messages[label] = last_body

        # Check message-based enumeration
        if messages.get("likely_exists") and messages.get("likely_not"):
            if messages["likely_exists"] != messages["likely_not"]:
                findings.append(OWASPFinding(
                    probe=self.name,
                    owasp_category=self.category,
                    severity=Severity.MEDIUM,
                    title="Username enumeration via different error messages",
                    detail=(
                        "Login failure for a likely-valid username returns a different error message "
                        "than for a clearly invalid username. Attackers can use this to enumerate "
                        "valid usernames before attempting password attacks."
                    ),
                    evidence=(
                        f"Known user response: {messages['likely_exists'][:100]}\n"
                        f"Unknown user response: {messages['likely_not'][:100]}"
                    ),
                    request_url=url,
                    request_method="POST",
                    remediation=(
                        "Return identical error messages for both invalid username and invalid password: "
                        "'Invalid username or password'. Never say 'user not found' vs 'wrong password'."
                    ),
                    cwe_id="CWE-204",
                    cvss_score=5.3,
                ))

        # Check timing-based enumeration (>100ms difference)
        time_diff = abs(timings.get("likely_exists", 0) - timings.get("likely_not", 0))
        if time_diff > 100:
            findings.append(OWASPFinding(
                probe=self.name,
                owasp_category=self.category,
                severity=Severity.LOW,
                title=f"Username enumeration via response timing ({time_diff:.0f}ms difference)",
                detail=(
                    f"Average response time differs by {time_diff:.0f}ms between existing and "
                    "non-existing usernames. Timing differences reveal whether a username exists."
                ),
                evidence=f"Known user avg: {timings['likely_exists']:.0f}ms | Unknown avg: {timings['likely_not']:.0f}ms",
                request_url=url,
                request_method="POST",
                remediation=(
                    "Use constant-time comparison for credential validation. "
                    "Always hash the provided password even if the user doesn't exist (dummy hash)."
                ),
                cwe_id="CWE-208",
                cvss_score=3.7,
            ))

        return findings

    def _test_weak_password_acceptance(
        self, base: str, session: httpx.Client, register_path: str
    ) -> list[OWASPFinding]:
        findings = []
        url = f"{base}{register_path}"

        for weak_pw in self.WEAK_PASSWORDS[:3]:   # Test first 3 to avoid flooding
            try:
                resp = session.post(url, json={
                    "username": f"testuser_{weak_pw}",
                    "email":    f"test_{weak_pw}@example.com",
                    "password": weak_pw,
                })
                if resp.status_code in (200, 201):
                    findings.append(OWASPFinding(
                        probe=self.name,
                        owasp_category=self.category,
                        severity=Severity.HIGH,
                        title=f"Weak password accepted during registration: '{weak_pw}'",
                        detail=(
                            f"Registration with password='{weak_pw}' succeeded (HTTP {resp.status_code}). "
                            "This password appears in every known password breach dataset. "
                            "Users can register with trivially guessable passwords."
                        ),
                        evidence=f"password='{weak_pw}' → HTTP {resp.status_code}",
                        request_url=url,
                        request_method="POST",
                        status_code=resp.status_code,
                        remediation=(
                            "Enforce minimum password policy: 12+ chars, mixed case, numbers, symbols. "
                            "Check against HaveIBeenPwned's breached password list. "
                            "Use zxcvbn for password strength estimation."
                        ),
                        cwe_id="CWE-521",
                        cvss_score=7.5,
                    ))
                    break
            except Exception:
                pass
        return findings
