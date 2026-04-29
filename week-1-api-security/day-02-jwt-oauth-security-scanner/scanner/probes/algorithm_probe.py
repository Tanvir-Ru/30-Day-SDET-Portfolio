"""
Probe: Algorithm confusion attacks.

Checks for:
- alg=none (signature bypass) — CVE class, trivially exploitable
- RS256→HS256 confusion attack (public key used as HMAC secret)
- Weak algorithm usage (MD5, SHA1-based, deprecated algorithms)
- Algorithm not in server's allowed list
- kid header injection potential (SQL/path traversal in kid)

References:
  - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
"""

import re
from scanner.jwt_decoder import JWTAnalysis
from scanner.probes.base import BaseProbe, SecurityFinding, Severity, FindingCategory

# Algorithms considered secure for production use
SECURE_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
ACCEPTABLE_SYMMETRIC = {"HS256", "HS384", "HS512"}
DEPRECATED_ALGORITHMS = {"RS1", "HS1", "RS256WithMD5", "none", "NONE", "None"}

# Patterns that suggest kid injection
KID_INJECTION_PATTERNS = [
    r"['\";]",           # SQL injection chars
    r"\.\./",            # Path traversal
    r"[\x00-\x1f]",     # Control characters
    r"(union|select|insert|drop|--)",  # SQL keywords
]


class AlgorithmConfusionProbe(BaseProbe):
    name = "algorithm_confusion"
    description = "Detects algorithm confusion attacks, alg=none, and weak crypto"

    def run(
        self,
        analysis: JWTAnalysis,
        allowed_algorithms: list[str] = None,
    ) -> list[SecurityFinding]:
        findings = []
        alg = analysis.algorithm

        # ── alg=none ──────────────────────────────────────────────────────
        if alg.lower() == "none":
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.NONE_ALGORITHM,
                severity=Severity.CRITICAL,
                title="JWT uses alg=none — signature verification bypassed",
                detail=(
                    "The token header specifies alg=none, meaning no cryptographic "
                    "signature is present or required. Any server that accepts this "
                    "token without enforcing a specific algorithm list allows any "
                    "attacker to forge arbitrary claims without a key."
                ),
                evidence={"header": analysis.header},
                remediation=(
                    "Explicitly whitelist accepted algorithms server-side. "
                    "Never allow 'none'. Use RS256 or ES256 for stateless tokens."
                ),
                cwe_id="CWE-347",
                cvss_score=9.8,
            ))
            return findings  # No point continuing if alg is none

        # ── Deprecated / broken algorithm ──────────────────────────────────
        if alg in DEPRECATED_ALGORITHMS:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.ALGORITHM_CONFUSION,
                severity=Severity.HIGH,
                title=f"Deprecated algorithm in use: {alg}",
                detail=f"Algorithm '{alg}' is deprecated or cryptographically weak.",
                evidence={"alg": alg},
                remediation="Migrate to RS256, ES256, or PS256.",
                cwe_id="CWE-327",
                cvss_score=7.4,
            ))

        # ── Symmetric algorithm (HS256/384/512) in a multi-party context ──
        if analysis.is_symmetric:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.ALGORITHM_CONFUSION,
                severity=Severity.MEDIUM,
                title=f"Symmetric algorithm {alg} — watch for RS256→HS256 confusion",
                detail=(
                    f"Token uses HMAC ({alg}). If the server also supports RS256, "
                    "an attacker may craft an HS256 token using the server's PUBLIC "
                    "RSA key as the HMAC secret, bypassing asymmetric verification. "
                    "Confirm the server enforces a single algorithm per key."
                ),
                evidence={"alg": alg, "header": analysis.header},
                remediation=(
                    "Pin the allowed algorithm per key ID in your JWT library config. "
                    "Never allow the client to choose the algorithm."
                ),
                cwe_id="CWE-327",
                cvss_score=8.1,
            ))

        # ── Algorithm not in server's allowed list ─────────────────────────
        if allowed_algorithms and alg not in allowed_algorithms:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.ALGORITHM_CONFUSION,
                severity=Severity.HIGH,
                title=f"Algorithm '{alg}' not in server allowlist",
                detail=(
                    f"Token algorithm '{alg}' is not in the configured allowed "
                    f"algorithms: {allowed_algorithms}. Server may be accepting "
                    "unexpected algorithm families."
                ),
                evidence={"alg": alg, "allowed": allowed_algorithms},
                remediation="Configure your JWT library to explicitly reject unlisted algorithms.",
                cwe_id="CWE-327",
                cvss_score=8.0,
            ))

        # ── kid header injection ───────────────────────────────────────────
        kid = analysis.header.get("kid", "")
        if kid:
            for pattern in KID_INJECTION_PATTERNS:
                if re.search(pattern, str(kid), re.IGNORECASE):
                    findings.append(SecurityFinding(
                        probe=self.name,
                        category=FindingCategory.KID_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Potential injection in JWT 'kid' header",
                        detail=(
                            f"The 'kid' header value '{kid}' contains characters "
                            "that suggest SQL injection or path traversal. If the "
                            "server uses 'kid' to look up a key in a database or "
                            "filesystem without sanitization, this is exploitable."
                        ),
                        evidence={"kid": kid, "matched_pattern": pattern},
                        remediation=(
                            "Validate 'kid' against a strict allowlist (e.g. UUID format). "
                            "Never use 'kid' directly in database queries or file paths."
                        ),
                        cwe_id="CWE-89",
                        cvss_score=9.1,
                    ))
                    break

        return findings
