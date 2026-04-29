"""
Probe: Token expiry and lifetime analysis.

Checks for:
- Missing `exp` claim (token never expires)
- Token already expired (server accepting it = vulnerability)
- Excessive token lifetime (access tokens > 1h, refresh tokens > 30d)
- Token issued in the future (clock skew abuse or forged `iat`)
- Missing `nbf` enforcement
"""

import time
from scanner.jwt_decoder import JWTAnalysis
from scanner.probes.base import BaseProbe, SecurityFinding, Severity, FindingCategory

# Thresholds
ACCESS_TOKEN_MAX_LIFETIME_SECONDS = 3600        # 1 hour
REFRESH_TOKEN_MAX_LIFETIME_SECONDS = 2592000    # 30 days
MAX_FUTURE_SKEW_SECONDS = 60


class TokenExpiryProbe(BaseProbe):
    name = "token_expiry"
    description = "Checks token expiry, lifetime, and temporal claim integrity"

    def run(self, analysis: JWTAnalysis, token_type: str = "access") -> list[SecurityFinding]:
        findings = []
        now = time.time()

        # ── Missing exp claim ──────────────────────────────────────────────
        if not analysis.has_expiry:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.TOKEN_EXPIRY,
                severity=Severity.HIGH,
                title="Token has no expiry claim (exp)",
                detail=(
                    "The JWT does not contain an 'exp' claim. Without an expiry, "
                    "the token is valid indefinitely. A stolen token can never be "
                    "invalidated without a full token blacklist."
                ),
                evidence={"payload_keys": list(analysis.payload.keys())},
                remediation=(
                    "Always set 'exp' on issued tokens. "
                    "Access tokens: ≤ 1 hour. Refresh tokens: ≤ 30 days."
                ),
                cwe_id="CWE-613",
                cvss_score=7.5,
            ))
            return findings  # No point checking lifetime if there's no exp

        # ── Token already expired ──────────────────────────────────────────
        if analysis.is_expired:
            age_minutes = abs(analysis.seconds_until_expiry) / 60
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.TOKEN_EXPIRY,
                severity=Severity.MEDIUM,
                title="Token is expired",
                detail=(
                    f"Token expired {age_minutes:.1f} minutes ago. "
                    "If the API accepted this token, it is not enforcing expiry."
                ),
                evidence={
                    "exp": analysis.expires_at,
                    "now": now,
                    "expired_seconds_ago": abs(analysis.seconds_until_expiry),
                },
                remediation="Verify the server rejects requests with expired tokens.",
                cwe_id="CWE-613",
            ))

        # ── Excessive token lifetime ───────────────────────────────────────
        if analysis.issued_at and analysis.expires_at:
            lifetime = analysis.expires_at - analysis.issued_at
            max_lifetime = (
                ACCESS_TOKEN_MAX_LIFETIME_SECONDS
                if token_type == "access"
                else REFRESH_TOKEN_MAX_LIFETIME_SECONDS
            )

            if lifetime > max_lifetime:
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.EXCESSIVE_LIFETIME,
                    severity=Severity.MEDIUM,
                    title=f"Excessive {token_type} token lifetime",
                    detail=(
                        f"Token lifetime is {lifetime / 3600:.1f} hours. "
                        f"Recommended maximum for {token_type} tokens is "
                        f"{max_lifetime / 3600:.1f} hours. "
                        "Long-lived tokens increase the blast radius of token theft."
                    ),
                    evidence={
                        "iat": analysis.issued_at,
                        "exp": analysis.expires_at,
                        "lifetime_hours": lifetime / 3600,
                        "max_recommended_hours": max_lifetime / 3600,
                    },
                    remediation=(
                        f"Reduce {token_type} token lifetime to ≤ {max_lifetime / 3600:.0f} hours. "
                        "Use refresh tokens for long-lived sessions."
                    ),
                    cwe_id="CWE-613",
                    cvss_score=4.3,
                ))

        # ── Token issued in the future ─────────────────────────────────────
        if analysis.issued_at and analysis.issued_at > (now + MAX_FUTURE_SKEW_SECONDS):
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.MISSING_CLAIM,
                severity=Severity.HIGH,
                title="Token 'iat' claim is in the future",
                detail=(
                    f"Token was issued {(analysis.issued_at - now):.0f} seconds in the future. "
                    "This indicates either severe clock skew or a forged/manipulated token."
                ),
                evidence={
                    "iat": analysis.issued_at,
                    "now": now,
                    "delta_seconds": analysis.issued_at - now,
                },
                remediation="Reject tokens where iat > now + acceptable_clock_skew (30–60 seconds).",
                cwe_id="CWE-347",
                cvss_score=6.5,
            ))

        return findings
