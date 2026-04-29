"""
Probe: Scope overflow and privilege escalation.

Checks for:
- Tokens with wildcard scopes (admin:*, *:write)
- Scope creep: token has more scopes than the minimum required
- Dangerous scope combinations (write + delete on sensitive resources)
- Missing scope claim entirely
- Overly broad audience (aud: *)
"""

from scanner.jwt_decoder import JWTAnalysis
from scanner.probes.base import BaseProbe, SecurityFinding, Severity, FindingCategory

# Scopes that individually indicate elevated privilege
DANGEROUS_SCOPES = {
    "admin", "root", "superuser", "sudo",
    "write:*", "read:*", "*",
    "admin:*", "manage:*", "delete:*",
    "openid profile email address phone",  # Overly broad OIDC
}

# Patterns indicating wildcard/catch-all
WILDCARD_PATTERNS = ["*", ".*", "/*", ":*"]

# Dangerous scope combinations (any pair triggers a finding)
DANGEROUS_COMBINATIONS = [
    ({"delete", "write"}, "write + delete on same resource"),
    ({"admin", "write"}, "admin + write — likely full access"),
    ({"read:all", "write:all"}, "full read + write access"),
]


class ScopeOverflowProbe(BaseProbe):
    name = "scope_overflow"
    description = "Detects excessive, wildcard, or dangerous scope combinations"

    def run(
        self,
        analysis: JWTAnalysis,
        expected_scopes: list[str] = None,
    ) -> list[SecurityFinding]:
        findings = []
        scopes = set(s.lower() for s in analysis.scopes)

        # ── Missing scope claim ────────────────────────────────────────────
        if not scopes:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.MISSING_CLAIM,
                severity=Severity.LOW,
                title="Token has no scope claim",
                detail=(
                    "No 'scope', 'scp', or 'scopes' claim found. "
                    "Without scopes, the server may be using role-based or "
                    "implicit authorization, which is harder to audit."
                ),
                evidence={"payload_keys": list(analysis.payload.keys())},
                remediation="Include explicit scopes in all issued tokens.",
                cwe_id="CWE-285",
                cvss_score=3.1,
            ))
            return findings

        # ── Wildcard scopes ────────────────────────────────────────────────
        for scope in analysis.scopes:
            if any(scope.endswith(p) or scope == p for p in WILDCARD_PATTERNS):
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.SCOPE_OVERFLOW,
                    severity=Severity.HIGH,
                    title=f"Wildcard scope detected: '{scope}'",
                    detail=(
                        f"Scope '{scope}' grants access to all resources matching "
                        "the wildcard pattern. This violates the principle of least "
                        "privilege and should never appear in production tokens."
                    ),
                    evidence={"scope": scope, "all_scopes": analysis.scopes},
                    remediation=(
                        "Replace wildcard scopes with explicit, resource-specific scopes. "
                        "e.g., 'write:orders' instead of 'write:*'"
                    ),
                    cwe_id="CWE-285",
                    cvss_score=7.6,
                ))

        # ── Individually dangerous scopes ──────────────────────────────────
        for dangerous in DANGEROUS_SCOPES:
            if dangerous.lower() in scopes:
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.SCOPE_OVERFLOW,
                    severity=Severity.HIGH,
                    title=f"Dangerous privileged scope: '{dangerous}'",
                    detail=(
                        f"Scope '{dangerous}' grants elevated privileges. "
                        "Tokens with this scope should be tightly controlled, "
                        "short-lived, and issued only to trusted machine clients."
                    ),
                    evidence={"dangerous_scope": dangerous, "all_scopes": analysis.scopes},
                    remediation="Issue least-privilege tokens. Admin scopes should require MFA.",
                    cwe_id="CWE-269",
                    cvss_score=8.0,
                ))

        # ── Dangerous scope combinations ───────────────────────────────────
        for combo, reason in DANGEROUS_COMBINATIONS:
            if combo.issubset(scopes):
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.SCOPE_OVERFLOW,
                    severity=Severity.MEDIUM,
                    title=f"Dangerous scope combination: {reason}",
                    detail=(
                        f"Scopes {sorted(combo)} were found together. "
                        f"Reason: {reason}. This combination effectively grants "
                        "full control over the relevant resources."
                    ),
                    evidence={"matched_scopes": sorted(combo), "all_scopes": analysis.scopes},
                    remediation="Separate read and write tokens. Never combine delete + write.",
                    cwe_id="CWE-269",
                    cvss_score=6.5,
                ))

        # ── More scopes than expected (scope creep) ────────────────────────
        if expected_scopes is not None:
            expected = set(s.lower() for s in expected_scopes)
            extra = scopes - expected
            if extra:
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.SCOPE_OVERFLOW,
                    severity=Severity.MEDIUM,
                    title="Token contains unexpected scopes",
                    detail=(
                        f"Token has {len(extra)} scope(s) beyond what this endpoint requires: "
                        f"{sorted(extra)}. This indicates scope creep — the token was issued "
                        "with broader access than needed."
                    ),
                    evidence={
                        "expected_scopes": sorted(expected),
                        "actual_scopes": sorted(scopes),
                        "extra_scopes": sorted(extra),
                    },
                    remediation=(
                        "Issue tokens with only the scopes required for the specific operation. "
                        "Use the 'scope' parameter in the OAuth token request."
                    ),
                    cwe_id="CWE-285",
                    cvss_score=5.4,
                ))

        # ── Overly broad audience ──────────────────────────────────────────
        aud = analysis.audience
        if aud in ("*", ["*"], "any", "all"):
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.SCOPE_OVERFLOW,
                severity=Severity.HIGH,
                title="Token audience (aud) is a wildcard",
                detail=(
                    f"Token aud='{aud}' means it is accepted by any service. "
                    "A token stolen from service A can be replayed against service B."
                ),
                evidence={"aud": aud},
                remediation="Set aud to the specific service identifier(s) that should accept the token.",
                cwe_id="CWE-295",
                cvss_score=7.2,
            ))

        return findings
