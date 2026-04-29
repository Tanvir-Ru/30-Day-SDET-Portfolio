# Day 02 — JWT / OAuth 2.0 Security Scanner

> **30-Day Senior SDET Portfolio** | Week 1: API Foundations & Security

A modular security scanner that probes JWT tokens for vulnerabilities
across four attack categories: token expiry, algorithm confusion,
scope overflow, and replay attack surface. Produces structured JSON
reports with CWE IDs, CVSS scores, and remediation guidance.

---

## Attack Categories Covered

| Probe | Attack | Severity Range | CWE |
|---|---|---|---|
| `expiry_probe` | Missing `exp`, expired token, excessive lifetime | HIGH–MEDIUM | CWE-613 |
| `algorithm_probe` | `alg=none`, RS256→HS256 confusion, `kid` injection | CRITICAL–MEDIUM | CWE-327, CWE-89 |
| `scope_probe` | Wildcard scopes, privilege escalation, scope creep | HIGH–LOW | CWE-285, CWE-269 |
| `replay_probe` | Missing `jti`, `aud`, `iss`, DPoP binding | HIGH–LOW | CWE-294, CWE-295 |

---

## Architecture

```
scanner/
├── jwt_decoder.py          ← Decodes JWT without verification (structural analysis)
├── scanner.py              ← Orchestrator: runs all probes, produces ScanReport
└── probes/
    ├── base.py             ← BaseProbe interface + SecurityFinding data model
    ├── expiry_probe.py     ← Token lifetime analysis
    ├── algorithm_probe.py  ← Algorithm confusion attacks
    ├── scope_probe.py      ← Scope overflow / privilege escalation
    └── replay_probe.py     ← Replay attack surface analysis
```

### Design decisions

**Probe isolation**: Each attack category is a separate class inheriting from
`BaseProbe`. Adding a new probe requires zero changes to the orchestrator —
instantiate it and append it to `JWTSecurityScanner.probes`.

**No signature verification by design**: The decoder intentionally skips
signature verification. Security scanners analyze token structure and claims,
not authenticity — that's the server's job. This allows scanning tokens from
any issuer without needing the signing key.

**Structured findings with CWE + CVSS**: Every `SecurityFinding` includes a
CWE ID and CVSS score, making the output actionable for security teams and
directly importable into vulnerability trackers.

**Risk score**: The report computes a weighted score (CRITICAL=25pts, HIGH=10pts,
MEDIUM=4pts, LOW=1pts, capped at 100) useful for trend tracking across releases.

---

## File Structure

```
day-02-jwt-oauth-security-scanner/
├── scanner/
│   ├── __init__.py
│   ├── jwt_decoder.py
│   ├── scanner.py
│   ├── probes/
│   │   ├── base.py
│   │   ├── expiry_probe.py
│   │   ├── algorithm_probe.py
│   │   ├── scope_probe.py
│   │   └── replay_probe.py
│   └── tests/
│       └── test_scanner.py
├── scripts/
├── .github/workflows/
│   └── security-scanner.yml
├── pyproject.toml
└── README.md
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Run all tests
poetry run pytest scanner/tests/ -v

# Scan a token from command line
poetry run python -m scanner.scanner --token "eyJhbGci..." --type access

# JSON output (pipe to jq, save to file, post to Slack)
poetry run python -m scanner.scanner --token "eyJhbGci..." --output json | jq .

# Check against expected issuer + audience
poetry run python -m scanner.scanner \
  --token "eyJhbGci..." \
  --issuer "https://auth.example.com" \
  --audience "api.example.com"
```

**Exit codes:**
- `0` — No CRITICAL or HIGH findings
- `1` — One or more CRITICAL/HIGH findings (suitable for CI gate)

---

## Sample Output

```
============================================================
JWT SECURITY SCAN REPORT
============================================================
Algorithm    : none
Subject      : admin
Issuer       : N/A
Scopes       : admin:*
Expired      : False
Scan time    : 0.8ms

Risk Score   : 57/100
Findings     : 5 total (1 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW)

  [CRITICAL ] algorithm_confusion: JWT uses alg=none — signature verification bypassed
               The token header specifies alg=none, meaning no cryptographic signature...
               CWE-347

  [HIGH     ] scope_overflow: Wildcard scope detected: 'admin:*'
               Scope 'admin:*' grants access to all resources matching the wildcard...
               CWE-285
...
============================================================
```

---

## Extending the Scanner

Add a new probe in 3 steps:

```python
# 1. Create scanner/probes/my_probe.py
from scanner.probes.base import BaseProbe, SecurityFinding, Severity, FindingCategory

class MyProbe(BaseProbe):
    name = "my_probe"

    def run(self, analysis, **kwargs) -> list[SecurityFinding]:
        findings = []
        # ... your logic
        return findings

# 2. Register it in scanner/scanner.py
from scanner.probes.my_probe import MyProbe
self.probes.append(MyProbe())

# 3. Write tests in scanner/tests/test_scanner.py
```

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `pyjwt[crypto]` | JWT encoding for test fixtures |
| `cryptography` | RSA/EC key generation |
| `httpx` | HTTP client for live endpoint scanning |
| `pytest` | Test runner |

---

## Recruiter Talking Points

- **Why decode without verification?** Security testing needs to inspect the token
  structure regardless of key availability. The *server's* responsibility is
  verification; the *scanner's* responsibility is finding structural vulnerabilities.

- **What's the alg=none attack?** Libraries that don't explicitly whitelist allowed
  algorithms will accept a token with `alg=none` — meaning any attacker can forge
  arbitrary claims by simply omitting the signature. This was a critical vulnerability
  in many JWT libraries (2015).

- **What's RS256→HS256 confusion?** If a server supports both RS256 (asymmetric) and
  HS256 (symmetric), an attacker can craft an HS256 token using the *public* RSA key
  as the HMAC secret — and the server will verify it successfully using its own
  public key. Fixed by pinning one algorithm per key.

- **What's `kid` injection?** The `kid` (key ID) header value is often used to look
  up the signing key in a database. Without sanitization, SQL injection or path
  traversal in `kid` can expose private keys or allow algorithm bypass.
