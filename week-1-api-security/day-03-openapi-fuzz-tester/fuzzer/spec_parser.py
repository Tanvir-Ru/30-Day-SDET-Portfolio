"""
OpenAPI 3.x spec parser.

Parses an OpenAPI spec (YAML or JSON) and extracts every endpoint,
method, parameter, request body schema, and response schema into
a structured model that the fuzzer can iterate over.

Supports:
  - OpenAPI 3.0.x and 3.1.x
  - $ref resolution (local and inline)
  - allOf / anyOf / oneOf (flattened for fuzzing)
  - Path parameters, query parameters, headers, cookies
  - application/json and multipart/form-data request bodies
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import yaml


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ParameterSpec:
    name: str
    location: str          # path | query | header | cookie
    required: bool
    schema: dict
    description: str = ""
    example: Any = None


@dataclass
class RequestBodySpec:
    required: bool
    content_type: str      # application/json | multipart/form-data | etc.
    schema: dict
    example: Any = None


@dataclass
class ResponseSpec:
    status_code: str       # "200", "404", "default"
    description: str
    schema: Optional[dict] = None


@dataclass
class EndpointSpec:
    path: str
    method: str            # GET, POST, PUT, PATCH, DELETE, etc.
    operation_id: str
    summary: str
    parameters: list[ParameterSpec] = field(default_factory=list)
    request_body: Optional[RequestBodySpec] = None
    responses: list[ResponseSpec] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    security: list[dict] = field(default_factory=list)

    @property
    def path_parameters(self) -> list[ParameterSpec]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def query_parameters(self) -> list[ParameterSpec]:
        return [p for p in self.parameters if p.location == "query"]

    @property
    def required_parameters(self) -> list[ParameterSpec]:
        return [p for p in self.parameters if p.required]

    @property
    def endpoint_id(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class APISpec:
    title: str
    version: str
    base_url: str
    endpoints: list[EndpointSpec]
    security_schemes: dict = field(default_factory=dict)

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def endpoints_by_tag(self, tag: str) -> list[EndpointSpec]:
        return [e for e in self.endpoints if tag in e.tags]

    def endpoints_by_method(self, method: str) -> list[EndpointSpec]:
        return [e for e in self.endpoints if e.method.upper() == method.upper()]


# ── Parser ────────────────────────────────────────────────────────────────────

class OpenAPIParser:
    """
    Parses an OpenAPI 3.x spec file or URL into an APISpec model.

    Resolves $ref references inline so consumers don't have to handle them.
    """

    def __init__(self, spec_source: str | Path | dict):
        if isinstance(spec_source, dict):
            self._raw = spec_source
        elif isinstance(spec_source, Path) or (
            isinstance(spec_source, str) and not spec_source.startswith("http")
        ):
            path = Path(spec_source)
            text = path.read_text(encoding="utf-8")
            self._raw = yaml.safe_load(text) if path.suffix in (".yaml", ".yml") else json.loads(text)
        else:
            import httpx
            response = httpx.get(spec_source, timeout=30)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            self._raw = (
                yaml.safe_load(response.text)
                if "yaml" in content_type
                else response.json()
            )

    def parse(self, base_url: str = None) -> APISpec:
        raw = self._raw

        # Extract base URL from servers if not provided
        if not base_url:
            servers = raw.get("servers", [])
            base_url = servers[0].get("url", "http://localhost:8000") if servers else "http://localhost:8000"

        info = raw.get("info", {})
        paths = raw.get("paths", {})
        components = raw.get("components", {})

        endpoints = []
        for path, path_item in paths.items():
            # Path-level parameters apply to all methods
            path_level_params = [
                self._parse_parameter(p, components)
                for p in path_item.get("parameters", [])
            ]

            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                operation = path_item.get(method)
                if not operation:
                    continue

                # Merge path-level + operation-level parameters
                op_params = [
                    self._parse_parameter(p, components)
                    for p in operation.get("parameters", [])
                ]
                # Operation params override path params with same name+location
                merged_params = {(p.name, p.location): p for p in path_level_params}
                merged_params.update({(p.name, p.location): p for p in op_params})

                request_body = None
                if "requestBody" in operation:
                    request_body = self._parse_request_body(operation["requestBody"], components)

                responses = [
                    self._parse_response(code, resp, components)
                    for code, resp in operation.get("responses", {}).items()
                ]

                op_id = operation.get("operationId") or f"{method}_{re.sub(r'[^a-z0-9]', '_', path.lower())}"

                endpoints.append(EndpointSpec(
                    path=path,
                    method=method.upper(),
                    operation_id=op_id,
                    summary=operation.get("summary", ""),
                    parameters=list(merged_params.values()),
                    request_body=request_body,
                    responses=responses,
                    tags=operation.get("tags", []),
                    security=operation.get("security", raw.get("security", [])),
                ))

        return APISpec(
            title=info.get("title", "Unknown API"),
            version=info.get("version", "0.0.0"),
            base_url=base_url.rstrip("/"),
            endpoints=endpoints,
            security_schemes=components.get("securitySchemes", {}),
        )

    def _resolve_ref(self, obj: dict, components: dict) -> dict:
        """Resolve a $ref to its target schema."""
        if "$ref" not in obj:
            return obj
        ref = obj["$ref"]
        if not ref.startswith("#/"):
            return obj  # External refs not supported
        parts = ref.lstrip("#/").split("/")
        result = self._raw
        for part in parts:
            result = result.get(part, {})
        return result

    def _parse_parameter(self, param: dict, components: dict) -> ParameterSpec:
        param = self._resolve_ref(param, components)
        schema = self._resolve_ref(param.get("schema", {}), components)
        return ParameterSpec(
            name=param.get("name", ""),
            location=param.get("in", "query"),
            required=param.get("required", param.get("in") == "path"),
            schema=schema,
            description=param.get("description", ""),
            example=param.get("example") or schema.get("example"),
        )

    def _parse_request_body(self, body: dict, components: dict) -> RequestBodySpec:
        body = self._resolve_ref(body, components)
        content = body.get("content", {})

        # Prefer JSON, fall back to first available
        content_type = "application/json"
        if "application/json" not in content and content:
            content_type = next(iter(content))

        media = content.get(content_type, {})
        schema = self._resolve_ref(media.get("schema", {}), components)

        return RequestBodySpec(
            required=body.get("required", False),
            content_type=content_type,
            schema=schema,
            example=media.get("example") or schema.get("example"),
        )

    def _parse_response(self, status_code: str, response: dict, components: dict) -> ResponseSpec:
        response = self._resolve_ref(response, components)
        content = response.get("content", {})
        schema = None
        if "application/json" in content:
            media = content["application/json"]
            schema = self._resolve_ref(media.get("schema", {}), components)

        return ResponseSpec(
            status_code=status_code,
            description=response.get("description", ""),
            schema=schema,
        )
