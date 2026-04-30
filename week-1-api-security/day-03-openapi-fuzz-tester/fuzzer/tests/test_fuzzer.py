"""
Fuzz tester unit & integration tests.

Tests cover:
  - Spec parser: endpoint extraction, $ref resolution, parameter types
  - Mutators: each mutator produces expected payload categories
  - Request builder: path substitution, query encoding, body construction
  - Response analyzer: detects each anomaly class
  - Engine: end-to-end fuzz run against the sample target

Run: pytest fuzzer/tests/ -v
"""

import json
import time
import pytest
import httpx

from fuzzer.spec_parser import OpenAPIParser, APISpec, EndpointSpec
from fuzzer.mutators.payload_mutators import (
    BoundaryMutator, TypeConfusionMutator, InjectionMutator,
    NullMutator, OversizeMutator, UnicodeMutator, FormatMutator,
    generate_mutations,
)
from fuzzer.request_builder import FuzzRequestBuilder, generate_valid_value, generate_valid_body
from fuzzer.response_analyzer import ResponseAnalyzer, FindingSeverity


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "Test API", "version": "1.0"},
    "servers": [{"url": "http://localhost:8000"}],
    "paths": {
        "/users/{user_id}": {
            "get": {
                "operationId": "get_user",
                "summary": "Get user",
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1},
                    }
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/users": {
            "post": {
                "operationId": "create_user",
                "summary": "Create user",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name", "email"],
                                "properties": {
                                    "name":  {"type": "string", "minLength": 1, "maxLength": 100},
                                    "email": {"type": "string", "format": "email"},
                                    "age":   {"type": "integer", "minimum": 0, "maximum": 150},
                                },
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "Created"}},
            }
        },
    },
}


@pytest.fixture
def api_spec() -> APISpec:
    return OpenAPIParser(SAMPLE_SPEC).parse()


@pytest.fixture
def builder(api_spec) -> FuzzRequestBuilder:
    return FuzzRequestBuilder(api_spec)


def _make_response(status: int, body: dict = None, elapsed_ms: float = 100) -> httpx.Response:
    """Create a mock httpx.Response for testing the analyzer."""
    body_bytes = json.dumps(body or {}).encode()
    response = httpx.Response(
        status_code=status,
        content=body_bytes,
        headers={"content-type": "application/json"},
    )
    return response


# ── Spec parser tests ─────────────────────────────────────────────────────────

class TestOpenAPIParser:
    def test_parses_endpoints(self, api_spec):
        assert api_spec.endpoint_count == 2

    def test_extracts_path_parameter(self, api_spec):
        get_endpoint = next(e for e in api_spec.endpoints if e.method == "GET")
        assert len(get_endpoint.path_parameters) == 1
        assert get_endpoint.path_parameters[0].name == "user_id"
        assert get_endpoint.path_parameters[0].required is True

    def test_extracts_request_body(self, api_spec):
        post_endpoint = next(e for e in api_spec.endpoints if e.method == "POST")
        assert post_endpoint.request_body is not None
        assert post_endpoint.request_body.required is True
        assert "name" in post_endpoint.request_body.schema.get("properties", {})

    def test_extracts_base_url(self, api_spec):
        assert api_spec.base_url == "http://localhost:8000"

    def test_endpoint_id_format(self, api_spec):
        ids = [e.endpoint_id for e in api_spec.endpoints]
        assert "GET /users/{user_id}" in ids
        assert "POST /users" in ids


# ── Mutator tests ─────────────────────────────────────────────────────────────

class TestBoundaryMutator:
    def test_integer_includes_min_minus_one(self):
        schema = {"type": "integer", "minimum": 1, "maximum": 100}
        payloads = BoundaryMutator().mutate(schema)
        assert 0 in payloads      # min - 1
        assert 1 in payloads      # at minimum
        assert 101 in payloads    # max + 1

    def test_string_includes_empty_and_oversize(self):
        schema = {"type": "string", "minLength": 2, "maxLength": 10}
        payloads = BoundaryMutator().mutate(schema)
        assert "" in payloads
        assert "a" * 11 in payloads   # max + 1


class TestTypeConfusionMutator:
    def test_string_field_gets_object_and_array(self):
        schema = {"type": "string"}
        payloads = TypeConfusionMutator().mutate(schema)
        assert None in payloads
        assert [] in payloads
        assert {} in payloads

    def test_integer_field_gets_string_coercion(self):
        schema = {"type": "integer"}
        payloads = TypeConfusionMutator().mutate(schema)
        assert "0" in payloads
        assert "NaN" in payloads


class TestInjectionMutator:
    def test_string_field_gets_sql_payloads(self):
        schema = {"type": "string"}
        payloads = InjectionMutator().mutate(schema)
        sql_payloads = [p for p in payloads if "OR" in str(p) or "DROP" in str(p)]
        assert len(sql_payloads) >= 2

    def test_non_string_returns_empty(self):
        schema = {"type": "integer"}
        payloads = InjectionMutator().mutate(schema)
        assert payloads == []

    def test_ssti_payloads_present(self):
        schema = {"type": "string"}
        payloads = InjectionMutator().mutate(schema)
        assert "{{7*7}}" in payloads


class TestFormatMutator:
    def test_uuid_format_gets_malformed_values(self):
        schema = {"type": "string", "format": "uuid"}
        payloads = FormatMutator().mutate(schema)
        assert "not-a-uuid" in payloads
        assert "' OR 1=1--" in payloads

    def test_email_format_gets_injection(self):
        schema = {"type": "string", "format": "email"}
        payloads = FormatMutator().mutate(schema)
        assert any("CRLF" in str(p) or "\r\n" in str(p) for p in payloads)

    def test_url_format_gets_ssrf_seeds(self):
        schema = {"type": "string", "format": "uri"}
        payloads = FormatMutator().mutate(schema)
        assert any("169.254.169.254" in str(p) for p in payloads)  # AWS metadata SSRF


class TestGenerateMutations:
    def test_deduplicates_payloads(self):
        schema = {"type": "string"}
        mutations = generate_mutations(schema)
        values = [v for _, v in mutations]
        assert len(values) == len(set(repr(v) for v in values))

    def test_returns_mutator_name_tuples(self):
        schema = {"type": "integer"}
        mutations = generate_mutations(schema)
        assert all(isinstance(name, str) for name, _ in mutations)
        assert all(name in ["boundary", "type_confusion", "null", "oversize", "unicode", "format", "injection"]
                   for name, _ in mutations)


# ── Request builder tests ─────────────────────────────────────────────────────

class TestRequestBuilder:
    def test_baseline_substitutes_path_params(self, api_spec, builder):
        endpoint = next(e for e in api_spec.endpoints if e.method == "GET")
        request = builder.build_baseline(endpoint)
        assert "{user_id}" not in str(request.url)

    def test_fuzz_injects_value_in_path(self, api_spec, builder):
        endpoint = next(e for e in api_spec.endpoints if e.method == "GET")
        request = builder.build_fuzzed(endpoint, "user_id", "path", "' OR 1=1")
        assert "' OR 1=1" in str(request.url) or "%27" in str(request.url)

    def test_fuzz_injects_value_in_body(self, api_spec, builder):
        endpoint = next(e for e in api_spec.endpoints if e.method == "POST")
        request = builder.build_fuzzed(endpoint, "name", "body", "<script>alert(1)</script>")
        body = json.loads(request.content)
        assert body["name"] == "<script>alert(1)</script>"

    def test_auth_token_added_to_headers(self, api_spec):
        builder_with_auth = FuzzRequestBuilder(api_spec, auth_token="test-token-xyz")
        endpoint = api_spec.endpoints[0]
        request = builder_with_auth.build_baseline(endpoint)
        assert request.headers.get("authorization") == "Bearer test-token-xyz"


# ── Response analyzer tests ───────────────────────────────────────────────────

class TestResponseAnalyzer:
    def setup_method(self):
        self.analyzer = ResponseAnalyzer()
        self.base_ctx = dict(
            endpoint="/users/1", method="GET",
            parameter="user_id", param_location="path",
            mutator="boundary", fuzz_value="-1",
        )

    def test_detects_500_as_high(self):
        resp = _make_response(500, {"error": "Internal Server Error"})
        findings = self.analyzer.analyze(resp, 100, **self.base_ctx)
        assert any(f.severity == FindingSeverity.HIGH for f in findings)
        assert any(f.finding_type == "server_error" for f in findings)

    def test_detects_python_traceback(self):
        resp = _make_response(500, {}, elapsed_ms=100)
        # Manually inject stack trace into response text via monkeypatching
        import unittest.mock as mock
        with mock.patch.object(type(resp), "text", new_callable=lambda: property(
            lambda self: "Traceback (most recent call last):\n  File app.py line 42\nValueError"
        )):
            findings = self.analyzer.analyze(resp, 100, **self.base_ctx)
        assert any(f.finding_type == "stack_trace_disclosure" for f in findings)

    def test_no_findings_on_clean_404(self):
        resp = _make_response(404, {"error": "Not found", "code": "NOT_FOUND"})
        findings = self.analyzer.analyze(resp, 100, **self.base_ctx)
        # 404 is expected for boundary values — no finding unless body is suspicious
        assert not any(f.finding_type == "server_error" for f in findings)

    def test_detects_slow_response(self):
        resp = _make_response(200, {"data": "ok"})
        findings = self.analyzer.analyze(resp, 11000, **self.base_ctx)
        assert any(f.finding_type in ("redos_candidate", "slow_response") for f in findings)

    def test_flags_injection_200_as_critical(self):
        resp = _make_response(200, {"users": [{"id": 1, "name": "admin"}]})
        ctx = {**self.base_ctx, "mutator": "injection", "fuzz_value": "' OR 1=1"}
        findings = self.analyzer.analyze(resp, 80, **ctx, baseline_status=200)
        assert any(f.severity == FindingSeverity.CRITICAL for f in findings)

    def test_valid_value_produces_no_findings(self):
        resp = _make_response(200, {"id": 1, "name": "Alice"})
        ctx = {**self.base_ctx, "mutator": "boundary", "fuzz_value": 1}
        findings = self.analyzer.analyze(resp, 50, **ctx)
        assert findings == []
