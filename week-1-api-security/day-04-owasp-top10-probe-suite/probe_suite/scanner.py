"""
OWASP Top-10 Scanner — main orchestrator + HTML report generator.

Runs all probes sequentially, aggregates findings, produces
a structured JSON + rich HTML report with OWASP category breakdown.

Usage (CLI):
    python -m probe_suite.scanner --url http://localhost:8000
    python -m probe_suite.scanner --url https://api.example.com --token Bearer_xyz --output html

Usage (library):
    from probe_suite.scanner import OWASPScanner
    scanner = OWASPScanner(base_url="http://localhost:8000")
    report  = scanner.run()
    report.save_html("owasp-report.html")
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from probe_suite.probes.base import OWASPFinding, Severity, OWASPCategory
from probe_suite.probes.a01_broken_access_control import BrokenAccessControlProbe
from probe_suite.probes.a02_a05_crypto_misconfig import CryptographicFailuresProbe, SecurityMisconfigProbe
from probe_suite.probes.a03_a07_injection_auth import InjectionProbe, AuthFailuresProbe
from probe_suite.probes.a10_ssrf import SSRFProbe


SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


@dataclass
class OWASPScanReport:
    base_url:          str
    findings:          list[OWASPFinding]
    probes_run:        list[str]
    scan_duration_s:   float
    timestamp:         float = field(default_factory=time.time)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def risk_score(self) -> float:
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1}
        return min(100.0, sum(weights.get(f.severity, 0) for f in self.findings))

    def by_category(self) -> dict[str, list[OWASPFinding]]:
        result: dict[str, list[OWASPFinding]] = {}
        for f in self.findings:
            cat = f.owasp_category.value
            result.setdefault(cat, []).append(f)
        return result

    def summary(self) -> str:
        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
        lines = [
            "=" * 70,
            "OWASP TOP-10 SECURITY SCAN REPORT",
            "=" * 70,
            f"Target           : {self.base_url}",
            f"Probes run       : {', '.join(self.probes_run)}",
            f"Duration         : {self.scan_duration_s:.1f}s",
            f"Risk Score       : {self.risk_score:.0f}/100",
            f"Total findings   : {len(self.findings)} "
            f"({self.critical_count} CRITICAL, {self.high_count} HIGH, "
            f"{sum(1 for f in self.findings if f.severity==Severity.MEDIUM)} MEDIUM, "
            f"{sum(1 for f in self.findings if f.severity==Severity.LOW)} LOW)",
            "",
        ]
        for f in sorted_findings:
            cat = f.owasp_category.value.split(" - ")[0]
            lines.append(f"  [{f.severity.value:8s}] [{cat}] {f.title}")
            if f.cwe_id:
                lines.append(f"               {f.cwe_id} | CVSS {f.cvss_score}")
            if f.remediation:
                lines.append(f"               Fix: {f.remediation[:80]}")
            lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "timestamp": self.timestamp,
            "scan_duration_s": round(self.scan_duration_s, 2),
            "risk_score": self.risk_score,
            "summary": {
                "critical": self.critical_count, "high": self.high_count,
                "total": len(self.findings),
            },
            "findings": [
                f.to_dict() for f in sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])
            ],
        }

    def save_html(self, path: str = "owasp-report.html") -> None:
        """Generate a professional HTML report."""
        by_cat = self.by_category()
        severity_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#65a30d", "INFO": "#6b7280",
        }
        severity_bg = {
            "CRITICAL": "#fef2f2", "HIGH": "#fff7ed",
            "MEDIUM": "#fffbeb", "LOW": "#f7fee7", "INFO": "#f9fafb",
        }

        findings_html = ""
        for cat, cat_findings in sorted(by_cat.items()):
            findings_html += f'<div class="category"><h2>{cat}</h2>'
            for f in sorted(cat_findings, key=lambda x: SEVERITY_ORDER[x.severity]):
                color  = severity_colors.get(f.severity.value, "#6b7280")
                bg     = severity_bg.get(f.severity.value, "#f9fafb")
                findings_html += f"""
                <div class="finding" style="border-left: 4px solid {color}; background: {bg}; padding: 12px 16px; margin: 8px 0; border-radius: 4px;">
                    <div style="display:flex; justify-content:space-between; align-items:start;">
                        <strong style="color:{color};">[{f.severity.value}] {f.title}</strong>
                        <span style="font-size:11px; color:#6b7280;">{f.cwe_id or ''}</span>
                    </div>
                    <p style="margin:6px 0; color:#374151; font-size:13px;">{f.detail}</p>
                    {'<pre style="background:#f3f4f6; padding:8px; font-size:11px; overflow-x:auto; border-radius:3px;">' + (f.evidence[:300] if f.evidence else '') + '</pre>' if f.evidence else ''}
                    {'<p style="margin:4px 0; font-size:12px; color:#059669;"><strong>Fix:</strong> ' + (f.remediation or '') + '</p>' if f.remediation else ''}
                </div>"""
            findings_html += "</div>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OWASP Top-10 Scan — {self.base_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #111827; }}
        h1 {{ border-bottom: 2px solid #1d4ed8; padding-bottom: 12px; }}
        h2 {{ color: #1d4ed8; margin-top: 32px; font-size: 15px; text-transform: uppercase; letter-spacing: .04em; }}
        .meta {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 6px; margin: 20px 0; }}
        .score {{ font-size: 48px; font-weight: 700; color: {'#dc2626' if self.risk_score >= 50 else '#d97706' if self.risk_score >= 25 else '#65a30d'}; }}
        .counts {{ display: flex; gap: 16px; margin: 12px 0; flex-wrap: wrap; }}
        .count-badge {{ padding: 4px 12px; border-radius: 999px; font-weight: 600; font-size: 13px; }}
        .category {{ margin-bottom: 32px; }}
    </style>
</head>
<body>
    <h1>🔐 OWASP Top-10 Security Scan</h1>
    <div class="meta">
        <p><strong>Target:</strong> {self.base_url}</p>
        <p><strong>Scan Duration:</strong> {self.scan_duration_s:.1f}s</p>
        <p><strong>Probes:</strong> {', '.join(self.probes_run)}</p>
        <div class="score">{self.risk_score:.0f}<span style="font-size:18px; color:#6b7280;">/100</span></div>
        <div class="counts">
            <span class="count-badge" style="background:#fef2f2; color:#dc2626;">{self.critical_count} CRITICAL</span>
            <span class="count-badge" style="background:#fff7ed; color:#ea580c;">{self.high_count} HIGH</span>
            <span class="count-badge" style="background:#fffbeb; color:#d97706;">{sum(1 for f in self.findings if f.severity==Severity.MEDIUM)} MEDIUM</span>
            <span class="count-badge" style="background:#f7fee7; color:#65a30d;">{sum(1 for f in self.findings if f.severity==Severity.LOW)} LOW</span>
        </div>
    </div>
    {findings_html if self.findings else '<p style="color:#65a30d; font-size:16px;">✅ No findings — target passed all probes.</p>'}
</body>
</html>"""
        Path(path).write_text(html, encoding="utf-8")
        print(f"HTML report saved: {path}")


class OWASPScanner:
    """Orchestrates all OWASP probes against a target API."""

    def __init__(
        self,
        base_url:          str,
        auth_token:        str = None,
        user_token:        str = None,
        admin_token:       str = None,
        login_endpoint:    str = "/api/auth/login",
        register_endpoint: str = "/api/auth/register",
        timeout:           float = 15.0,
    ):
        self.base_url          = base_url.rstrip("/")
        self.auth_token        = auth_token
        self.user_token        = user_token or auth_token
        self.admin_token       = admin_token
        self.login_endpoint    = login_endpoint
        self.register_endpoint = register_endpoint
        self.timeout           = timeout

        self._probes = [
            BrokenAccessControlProbe(),
            CryptographicFailuresProbe(),
            SecurityMisconfigProbe(),
            InjectionProbe(),
            AuthFailuresProbe(),
            SSRFProbe(),
        ]

    def run(self) -> OWASPScanReport:
        start    = time.perf_counter()
        session  = httpx.Client(timeout=self.timeout, follow_redirects=True)
        all_findings: list[OWASPFinding] = []
        probes_run = []

        for probe in self._probes:
            print(f"  → Running probe: {probe.name}", flush=True)
            probes_run.append(probe.name)
            try:
                findings = probe.run(
                    base_url=self.base_url,
                    session=session,
                    user_token=self.user_token,
                    admin_token=self.admin_token,
                    login_endpoint=self.login_endpoint,
                    register_endpoint=self.register_endpoint,
                )
                all_findings.extend(findings)
                print(f"     {len(findings)} finding(s)", flush=True)
            except Exception as e:
                print(f"     WARNING: probe failed: {e}", flush=True)

        session.close()
        return OWASPScanReport(
            base_url=self.base_url,
            findings=all_findings,
            probes_run=probes_run,
            scan_duration_s=time.perf_counter() - start,
        )


def main():
    parser = argparse.ArgumentParser(description="OWASP Top-10 Security Scanner")
    parser.add_argument("--url",      required=True, help="Target base URL")
    parser.add_argument("--token",    help="Bearer token (user level)")
    parser.add_argument("--admin",    help="Admin-level Bearer token")
    parser.add_argument("--output",   choices=["text", "json", "html"], default="text")
    parser.add_argument("--out-file", default="owasp-report", help="Output file basename")
    args = parser.parse_args()

    print(f"OWASP Top-10 Scanner → {args.url}\n")
    scanner = OWASPScanner(base_url=args.url, auth_token=args.token, admin_token=args.admin)
    report  = scanner.run()
    print()

    if args.output == "json":
        out = f"{args.out_file}.json"
        Path(out).write_text(json.dumps(report.to_dict(), indent=2))
        print(f"JSON report saved: {out}")
    elif args.output == "html":
        report.save_html(f"{args.out_file}.html")
    else:
        print(report.summary())

    sys.exit(1 if report.critical_count > 0 or report.high_count > 0 else 0)


if __name__ == "__main__":
    main()
