"""
Probe: Token replay attack surface analysis.

Checks for:
- Missing `jti` (JWT ID) claim — server cannot detect replayed tokens
- Missing audience binding — token can be replayed cross-service
- Missing issuer claim — token origin unverifiable
- Token not bound to client (no `cnf` claim for DPoP/mTLS binding)
- Suspicious use pattern: same token used from multiple IPs (requires log data)

Note: Replay attacks are architectural — this probe identifies the absence
of mitigations rather than directly exploiting a replay. The actual test
(sending an expired/revoked token and checking if the server accepts it)
is in test_replay_attacks.py.
"""

from scanner.jwt_decoder import JWTAnalysis
from scanner.probes.base import BaseProbe, SecurityFinding, Severity, FindingCategory


class ReplayAttackProbe(BaseProbe):
    name = "replay_attack"
    description = "Identifies missing replay attack mitigations"

    def run(
        self,
        analysis: JWTAnalysis,
        expected_issuer: str = None,
        expected_audience: str = None,
    ) -> list[SecurityFinding]:
        findings = []

        # ── Missing jti (JWT ID) ───────────────────────────────────────────
        if "jti" not in analysis.claims:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.REPLAY_ATTACK,
                severity=Severity.MEDIUM,
                title="Token missing 'jti' claim — replay detection not possible",
                detail=(
                    "Without a unique 'jti' (JWT ID) claim, the server cannot maintain "
                    "a token revocation list or detect if a stolen token is being replayed. "
                    "Any intercepted token can be reused until expiry."
                ),
                evidence={"payload_keys": list(analysis.claims.keys())},
                remediation=(
                    "Include a unique 'jti' (UUID or ULID) in all issued tokens. "
                    "Maintain a short-lived cache of seen jti values to detect replays "
                    "within the token's validity window."
                ),
                cwe_id="CWE-294",
                cvss_score=5.9,
            ))

        # ── Missing issuer ─────────────────────────────────────────────────
        if not analysis.issuer:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.MISSING_CLAIM,
                severity=Severity.MEDIUM,
                title="Token missing 'iss' (issuer) claim",
                detail=(
                    "Without an issuer claim, the server cannot verify that the token "
                    "came from the expected authorization server. Tokens from rogue "
                    "issuers could be accepted."
                ),
                evidence={"payload_keys": list(analysis.claims.keys())},
                remediation="Always include and validate the 'iss' claim against a known allowlist.",
                cwe_id="CWE-347",
                cvss_score=5.3,
            ))
        elif expected_issuer and analysis.issuer != expected_issuer:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.MISSING_CLAIM,
                severity=Severity.HIGH,
                title="Token issuer does not match expected issuer",
                detail=(
                    f"Token iss='{analysis.issuer}' but expected '{expected_issuer}'. "
                    "This token may have been issued by a different authorization server "
                    "or the token has been tampered with."
                ),
                evidence={"actual_iss": analysis.issuer, "expected_iss": expected_issuer},
                remediation="Reject tokens whose 'iss' does not exactly match the expected issuer URI.",
                cwe_id="CWE-347",
                cvss_score=8.2,
            ))

        # ── Missing audience ───────────────────────────────────────────────
        if not analysis.audience:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.REPLAY_ATTACK,
                severity=Severity.MEDIUM,
                title="Token missing 'aud' (audience) claim",
                detail=(
                    "Without an audience claim, the token is not bound to a specific "
                    "service. A token stolen from service A can be replayed against "
                    "service B if both accept the same issuer."
                ),
                evidence={"payload_keys": list(analysis.claims.keys())},
                remediation=(
                    "Set 'aud' to the service identifier. Each service should reject "
                    "tokens not addressed to it."
                ),
                cwe_id="CWE-295",
                cvss_score=5.4,
            ))
        elif expected_audience:
            aud = analysis.audience
            if isinstance(aud, list):
                aud_list = aud
            else:
                aud_list = [aud]
            if expected_audience not in aud_list:
                findings.append(SecurityFinding(
                    probe=self.name,
                    category=FindingCategory.REPLAY_ATTACK,
                    severity=Severity.HIGH,
                    title="Token not addressed to this service",
                    detail=(
                        f"Token aud={aud!r} does not include '{expected_audience}'. "
                        "This token was issued for a different service. Accepting it "
                        "here would allow cross-service token replay."
                    ),
                    evidence={"actual_aud": aud, "expected_aud": expected_audience},
                    remediation="Strictly validate 'aud' matches your service identifier.",
                    cwe_id="CWE-295",
                    cvss_score=7.7,
                ))

        # ── Missing DPoP / mTLS binding (cnf claim) ────────────────────────
        if "cnf" not in analysis.claims:
            findings.append(SecurityFinding(
                probe=self.name,
                category=FindingCategory.REPLAY_ATTACK,
                severity=Severity.LOW,
                title="Token not sender-constrained (no 'cnf' claim)",
                detail=(
                    "Token lacks a 'cnf' (confirmation) claim, meaning it is a bearer "
                    "token — possession = authorization. For high-value APIs, consider "
                    "DPoP (RFC 9449) or mTLS token binding to tie the token to a "
                    "specific client key pair."
                ),
                evidence={"payload_keys": list(analysis.claims.keys())},
                remediation=(
                    "For high-security flows, implement DPoP (RFC 9449) to bind tokens "
                    "to a client key pair. This prevents replay from different clients."
                ),
                cwe_id="CWE-294",
                cvss_score=3.7,
            ))

        return findings
