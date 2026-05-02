# Day 04 — OWASP Top-10 Automated Probe Suite

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A systematic, probe-based security scanner that covers all 10 OWASP Top-10 2021 risk
categories against a running API. Each probe is self-contained, independently testable,
and produces structured findings with CWE IDs, CVSS scores, and remediation guidance.
Generates a rich HTML report for stakeholders and a JSON report for CI gates.

---

## The Problem This Solves

Security audits happen once a quarter. This suite runs on every PR.

Most development teams don't have a dedicated security engineer reviewing every
API change. This probe suite gives QA engineers the ability to catch the most
common and highest-impact security vulnerabilities automatically — before code
reaches staging, not after a pentest finds them in production.

---

## OWASP Top-10 2021 Coverage

| # | Category | Probe | Checks |
|---|---|---|---|
| A01 | Broken Access Control | `BrokenAccessControlProbe` | IDOR, admin endpoints, unauthenticated access, verb tampering |
| A02 | Cryptographic Failures | `CryptographicFailuresProbe` | Missing HSTS/CSP/X-Frame headers, cleartext HTTP, sensitive data in responses |
| A03 | Injection | `InjectionProbe` | SQL (error-based + time-based), NoSQL operators, log injection |
| A04 | Insecure Design | *(via A05/A07 probes)* | Debug endpoints, no rate limiting |
| A05 | Security Misconfiguration | `SecurityMisconfigProbe` | Swagger/metrics exposed, CORS *, verbose errors, TRACE method, server version |
| A06 | Vulnerable Components | *(via header analysis)* | Framework version disclosure |
| A07 | Auth Failures | `AuthFailuresProbe` | Brute-force, default creds, username enumeration (message + timing), weak passwords |
| A08 | Data Integrity | *(via A02 crypto probe)* | Sensitive fields in responses |
| A09 | Logging Failures | *(via injection probe)* | Log injection / log forging |
| A10 | SSRF | `SSRFProbe` | Internal network, AWS metadata, protocol smuggling, IP encoding bypasses |

---

## Architecture

```
probe_suite/
│
├── probes/
│   ├── base.py                    ← OWASPBaseProbe + OWASPFinding model
│   ├── a01_broken_access_control  ← IDOR, admin enum, verb tampering
│   ├── a02_a05_crypto_misconfig   ← Headers, cleartext, CORS, debug endpoints
│   ├── a03_a07_injection_auth     ← SQL/NoSQL injection, brute-force, enumeration
│   └── a10_ssrf                   ← SSRF, metadata, protocol smuggling, bypasses
│
├── scanner.py                     ← Orchestrator + HTML/JSON reporter
│
└── targets/
    └── vulnerable_app.py          ← FastAPI target with intentional vulnerabilities
```

### Design decision: probe isolation

Each probe is independently runnable and testable. You can run just the SSRF probe
against a target, or just the auth probe, without running the full suite. This matters
for targeted retesting after a fix and for running specific probes in time-constrained CI.

### Design decision: finding severity tied to CVSS

Every finding has a CVSS v3.1 score. Severity buckets follow the standard thresholds:
- CRITICAL: CVSS ≥ 9.0
- HIGH: CVSS 7.0–8.9
- MEDIUM: CVSS 4.0–6.9
- LOW: CVSS < 4.0

This makes findings directly comparable to CVEs in your dependency scanner output.

### Design decision: HTML report for stakeholders

The HTML report is designed for non-technical audiences — a colour-coded risk score,
findings grouped by OWASP category, and plain-English remediation. QA engineers can
share this directly with product managers and security teams without translation.

---

## File Structure

```
day-04-owasp-top10-probe-suite/
├── probe_suite/
│   ├── __init__.py
│   ├── scanner.py                  # Orchestrator, HTML/JSON reporter, CLI
│   ├── probes/
│   │   ├── base.py                 # OWASPBaseProbe + OWASPFinding data model
│   │   ├── a01_broken_access_control.py
│   │   ├── a02_a05_crypto_misconfig.py
│   │   ├── a03_a07_injection_auth.py
│   │   └── a10_ssrf.py
│   ├── tests/
│   │   └── test_owasp_probes.py    # Full integration test suite
│   └── targets/
│       └── vulnerable_app.py       # Intentionally vulnerable FastAPI target
├── .github/workflows/
│   └── owasp-scan.yml              # CI + nightly staging scan
└── pyproject.toml
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Start the vulnerable test target
poetry run uvicorn probe_suite.targets.vulnerable_app:app --port 8000

# Run full OWASP scan (text report)
poetry run python -m probe_suite.scanner --url http://localhost:8000

# HTML report (open in browser)
poetry run python -m probe_suite.scanner \
  --url http://localhost:8000 \
  --output html \
  --out-file report
open report.html

# JSON report (pipe to jq or CI)
poetry run python -m probe_suite.scanner \
  --url http://localhost:8000 \
  --output json | jq '.summary'

# Authenticated scan
poetry run python -m probe_suite.scanner \
  --url https://api.example.com \
  --token "your-user-token" \
  --admin "your-admin-token"

# Run just the unit tests
poetry run pytest probe_suite/tests/ -v
```

**Exit codes:**
- `0` — No CRITICAL or HIGH findings
- `1` — One or more CRITICAL/HIGH findings (CI gate)

---

## Sample HTML Report

The generated HTML report shows:
- Risk score (0–100, colour-coded red/amber/green)
- Findings grouped by OWASP category
- Severity badge + CWE ID per finding
- Evidence snippet (truncated response body or header value)
- Remediation guidance in plain English

---

## Adding a New Probe

```python
# probe_suite/probes/a08_data_integrity.py
from probe_suite.probes.base import OWASPBaseProbe, OWASPFinding, OWASPCategory, Severity

class DataIntegrityProbe(OWASPBaseProbe):
    name     = "data_integrity"
    category = OWASPCategory.A08_DATA_INTEGRITY

    def run(self, base_url, session, **kwargs) -> list[OWASPFinding]:
        findings = []
        # ... your checks
        return findings

# Register in scanner.py:
from probe_suite.probes.a08_data_integrity import DataIntegrityProbe
self._probes.append(DataIntegrityProbe())
```

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `httpx` | HTTP client (sync, timeout, redirect handling) |
| `fastapi` | Vulnerable test target |
| `pytest` | Test runner |

No heavy security frameworks required — this is intentionally lightweight to demonstrate
that security testing doesn't require specialised tools, just methodical coverage.

---

## Recruiter Talking Points

- **Why 6 probes instead of 10?** Several OWASP categories (A04, A06, A08, A09) are
  effectively checked as side effects of other probes. A04 (Insecure Design) manifests
  as missing rate limiting (A07 probe). A06 (Vulnerable Components) shows up as version
  headers (A02/A05 probes). Real security coverage isn't one-probe-per-category.

- **What's the most impactful finding type?** Default credentials (A07) and SSRF to cloud
  metadata (A10) are both CVSS 9.8–9.9. Either one gives an attacker full account takeover
  or cloud environment compromise respectively.

- **What's username enumeration timing bypass?** Even when a server returns identical
  error messages, it may take longer to respond for a valid username (because it does a
  DB lookup and password hash comparison) than for an invalid one (which fails fast). This
  probe detects that 100ms+ timing difference.

- **Why build a vulnerable target?** Testing security probes against a target you control
  lets you verify the probe works before pointing it at production. It also provides
  repeatable CI validation — the probe suite tests itself.
