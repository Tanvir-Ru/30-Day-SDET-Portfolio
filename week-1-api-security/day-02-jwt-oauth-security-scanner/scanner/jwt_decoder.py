"""
JWT token decoder and structural analyzer.

Decodes JWTs without verification (for attack surface analysis), then
extracts claims, algorithm, and metadata needed by the probe suite.
"""

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class JWTAnalysis:
    raw_token: str
    header: dict
    payload: dict
    signature: str
    algorithm: str
    issued_at: Optional[int]
    expires_at: Optional[int]
    is_expired: bool
    seconds_until_expiry: Optional[float]
    subject: Optional[str]
    issuer: Optional[str]
    audience: Optional[Any]
    scopes: list[str]
    claims: dict
    warnings: list[str] = field(default_factory=list)

    @property
    def is_none_algorithm(self) -> bool:
        return self.algorithm.lower() == "none"

    @property
    def is_symmetric(self) -> bool:
        return self.algorithm.startswith("HS")

    @property
    def is_asymmetric(self) -> bool:
        return self.algorithm.startswith(("RS", "ES", "PS"))

    @property
    def has_expiry(self) -> bool:
        return self.expires_at is not None


def _b64_decode(segment: str) -> bytes:
    """Base64url decode with padding fix."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def decode_jwt(token: str) -> JWTAnalysis:
    """
    Decode a JWT without signature verification.

    This is intentional for security testing — we want to inspect
    the token structure regardless of whether the signature is valid.
    """
    token = token.strip()
    if token.startswith("Bearer "):
        token = token[7:]

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    try:
        header = json.loads(_b64_decode(parts[0]))
    except Exception as e:
        raise ValueError(f"Failed to decode JWT header: {e}")

    try:
        payload = json.loads(_b64_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Failed to decode JWT payload: {e}")

    signature = parts[2]
    algorithm = header.get("alg", "unknown")
    now = time.time()

    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    is_expired = expires_at is not None and expires_at < now
    seconds_until_expiry = (expires_at - now) if expires_at is not None else None

    # Extract scopes from common claim names
    raw_scope = payload.get("scope") or payload.get("scp") or payload.get("scopes") or []
    if isinstance(raw_scope, str):
        scopes = raw_scope.split()
    elif isinstance(raw_scope, list):
        scopes = raw_scope
    else:
        scopes = []

    warnings = []
    if algorithm.lower() == "none":
        warnings.append("CRITICAL: alg=none — signature is not verified by server")
    if algorithm.startswith("HS") and len(signature) < 43:
        warnings.append("WARNING: HMAC signature appears short — possible weak secret")

    return JWTAnalysis(
        raw_token=token,
        header=header,
        payload=payload,
        signature=signature,
        algorithm=algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
        is_expired=is_expired,
        seconds_until_expiry=seconds_until_expiry,
        subject=payload.get("sub"),
        issuer=payload.get("iss"),
        audience=payload.get("aud"),
        scopes=scopes,
        claims=payload,
        warnings=warnings,
    )
