"""
Request builder.

Takes an EndpointSpec + a set of parameter overrides and assembles
a complete httpx.Request ready to send.

Handles:
  - Path parameter substitution (/users/{id} → /users/123)
  - Query parameter encoding
  - JSON request body construction
  - Authentication header injection
  - Baseline request generation (valid values from schema examples)
"""

from __future__ import annotations

import json
import random
import string
import uuid
from typing import Any, Optional

import httpx

from fuzzer.spec_parser import EndpointSpec, ParameterSpec, APISpec


# ── Baseline value generator ──────────────────────────────────────────────────

def generate_valid_value(schema: dict) -> Any:
    """
    Generate a single valid value from a JSON schema.
    Used to build baseline requests and fill in fields not being fuzzed.
    """
    if not schema:
        return "test"

    # Use example if available
    if "example" in schema:
        return schema["example"]
    if "examples" in schema:
        examples = schema["examples"]
        if isinstance(examples, list) and examples:
            return examples[0]
        if isinstance(examples, dict):
            return next(iter(examples.values()), {}).get("value", "test")

    # Use enum first value
    if "enum" in schema:
        return schema["enum"][0]

    # Use const
    if "const" in schema:
        return schema["const"]

    t = schema.get("type", "string")
    fmt = schema.get("format", "")

    if t == "string":
        if fmt == "uuid":
            return str(uuid.uuid4())
        if fmt in ("date-time",):
            return "2024-06-15T10:30:00Z"
        if fmt == "date":
            return "2024-06-15"
        if fmt == "email":
            return "test@example.com"
        if fmt in ("uri", "url"):
            return "https://example.com"
        min_len = schema.get("minLength", 1)
        max_len = min(schema.get("maxLength", 20), 20)
        return "".join(random.choices(string.ascii_lowercase, k=max(min_len, 5)))

    elif t in ("integer", "number"):
        minimum = schema.get("minimum", 1)
        maximum = schema.get("maximum", 100)
        val = (minimum + maximum) // 2
        return int(val) if t == "integer" else float(val)

    elif t == "boolean":
        return True

    elif t == "array":
        items_schema = schema.get("items", {"type": "string"})
        min_items = schema.get("minItems", 1)
        return [generate_valid_value(items_schema) for _ in range(min_items or 1)]

    elif t == "object":
        props = schema.get("properties", {})
        required = schema.get("required", list(props.keys())[:3])
        return {k: generate_valid_value(v) for k, v in props.items() if k in required}

    return "test_value"


def generate_valid_body(schema: dict) -> dict:
    """Generate a complete valid JSON body from an object schema."""
    if not schema:
        return {}

    t = schema.get("type", "object")
    if t == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])

        # Build all required fields + a sample of optional ones
        body = {}
        for field_name, field_schema in props.items():
            if field_name in required or random.random() > 0.5:
                body[field_name] = generate_valid_value(field_schema)
        return body

    return generate_valid_value(schema)


# ── Request builder ───────────────────────────────────────────────────────────

class FuzzRequestBuilder:
    """
    Builds httpx requests for a given endpoint + parameter override map.

    Usage:
        builder = FuzzRequestBuilder(api_spec)
        request = builder.build(endpoint, path_params={"id": "' OR 1=1"})
        response = httpx.Client().send(request)
    """

    def __init__(self, api_spec: APISpec, auth_token: str = None):
        self.api_spec = api_spec
        self.auth_token = auth_token

    def build_baseline(self, endpoint: EndpointSpec) -> httpx.Request:
        """Build a valid baseline request — used to confirm the endpoint works before fuzzing."""
        path_params = {
            p.name: generate_valid_value(p.schema)
            for p in endpoint.path_parameters
        }
        query_params = {
            p.name: generate_valid_value(p.schema)
            for p in endpoint.required_parameters
            if p.location == "query"
        }
        body = None
        if endpoint.request_body:
            body = generate_valid_body(endpoint.request_body.schema)

        return self._build(endpoint, path_params, query_params, body)

    def build_fuzzed(
        self,
        endpoint: EndpointSpec,
        param_name: str,
        param_location: str,
        fuzz_value: Any,
    ) -> httpx.Request:
        """
        Build a request with one parameter replaced by a fuzz value.
        All other parameters use valid baseline values.
        """
        # Build baseline values for all parameters
        path_params = {
            p.name: generate_valid_value(p.schema)
            for p in endpoint.path_parameters
        }
        query_params = {
            p.name: generate_valid_value(p.schema)
            for p in endpoint.query_parameters
        }
        body = None
        if endpoint.request_body:
            body = generate_valid_body(endpoint.request_body.schema)

        # Inject the fuzz value at the target location
        if param_location == "path":
            path_params[param_name] = fuzz_value
        elif param_location == "query":
            query_params[param_name] = fuzz_value
        elif param_location == "body":
            if isinstance(body, dict):
                body[param_name] = fuzz_value
            else:
                body = fuzz_value

        return self._build(endpoint, path_params, query_params, body)

    def _build(
        self,
        endpoint: EndpointSpec,
        path_params: dict,
        query_params: dict,
        body: Any = None,
    ) -> httpx.Request:
        # Substitute path parameters
        path = endpoint.path
        for name, value in path_params.items():
            path = path.replace(f"{{{name}}}", str(value) if value is not None else "")

        url = f"{self.api_spec.base_url}{path}"

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        # Safely encode query params (skip None)
        safe_query = {k: str(v) for k, v in query_params.items() if v is not None}

        content = None
        if body is not None:
            try:
                content = json.dumps(body, default=str).encode()
            except (TypeError, ValueError):
                content = str(body).encode()

        return httpx.Request(
            method=endpoint.method,
            url=url,
            params=safe_query,
            content=content,
            headers=headers,
        )
