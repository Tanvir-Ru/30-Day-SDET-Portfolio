"""
GraphQL HTTP client helper.

Wraps httpx to send GraphQL queries/mutations, handle GQL-specific
response semantics (errors returned as HTTP 200 with errors[] field),
and provide timing information.

Key difference from REST: GraphQL always returns HTTP 200 even for
errors. Success/failure is determined by the presence of the `errors`
field in the response body — not by HTTP status code.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


@dataclass
class GQLResponse:
    status_code:  int
    elapsed_ms:   float
    data:         Optional[dict]
    errors:       Optional[list]
    raw:          str
    headers:      dict

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def has_data(self) -> bool:
        return self.data is not None and bool(self.data)

    @property
    def error_messages(self) -> list[str]:
        if not self.errors:
            return []
        return [e.get("message", "") for e in self.errors]

    @property
    def first_error(self) -> str:
        msgs = self.error_messages
        return msgs[0] if msgs else ""

    def field_data(self, *keys: str) -> Any:
        """Drill into data using dot-path keys."""
        result = self.data or {}
        for key in keys:
            if isinstance(result, dict):
                result = result.get(key)
            else:
                return None
        return result


class GQLClient:
    """
    Thin GraphQL client over httpx.

    Handles:
      - POST application/json (standard)
      - GET with query string (for CSRF probe)
      - Multipart form (file upload attack surface)
      - Batch queries (array of operations)
      - Response parsing with error extraction
    """

    def __init__(
        self,
        endpoint:    str,
        session:     httpx.Client,
        headers:     dict = None,
        auth_token:  str = None,
    ):
        self.endpoint   = endpoint
        self.session    = session
        self.headers    = headers or {}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    def query(
        self,
        query:      str,
        variables:  dict = None,
        operation:  str = None,
    ) -> GQLResponse:
        """Send a single GraphQL query/mutation via POST."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation:
            payload["operationName"] = operation

        return self._post(payload)

    def batch(self, operations: list[dict]) -> GQLResponse:
        """Send a batch of GraphQL operations in a single POST."""
        return self._post(operations)

    def query_via_get(self, query: str, variables: dict = None) -> GQLResponse:
        """Send a GraphQL query via GET (CSRF attack surface)."""
        params = {"query": query}
        if variables:
            params["variables"] = json.dumps(variables)

        t0 = time.perf_counter()
        try:
            resp = self.session.get(
                self.endpoint,
                params=params,
                headers={**self.headers, "Accept": "application/json"},
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return self._parse(resp, elapsed)
        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - t0) * 1000
            return GQLResponse(
                status_code=0, elapsed_ms=elapsed,
                data=None, errors=[{"message": "Request timed out"}],
                raw="", headers={},
            )

    def _post(self, payload: Any) -> GQLResponse:
        t0 = time.perf_counter()
        try:
            resp = self.session.post(
                self.endpoint,
                json=payload,
                headers={**self.headers, "Content-Type": "application/json"},
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return self._parse(resp, elapsed)
        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - t0) * 1000
            return GQLResponse(
                status_code=0, elapsed_ms=elapsed,
                data=None, errors=[{"message": "Request timed out"}],
                raw="", headers={},
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return GQLResponse(
                status_code=0, elapsed_ms=elapsed,
                data=None, errors=[{"message": str(e)}],
                raw="", headers={},
            )

    @staticmethod
    def _parse(resp: httpx.Response, elapsed_ms: float) -> GQLResponse:
        raw = resp.text
        data = errors = None
        try:
            body = resp.json()
            if isinstance(body, dict):
                data   = body.get("data")
                errors = body.get("errors")
            elif isinstance(body, list):
                # Batch response
                data = {"batch_results": body}
        except Exception:
            pass

        return GQLResponse(
            status_code=resp.status_code,
            elapsed_ms=elapsed_ms,
            data=data,
            errors=errors,
            raw=raw,
            headers=dict(resp.headers),
        )
