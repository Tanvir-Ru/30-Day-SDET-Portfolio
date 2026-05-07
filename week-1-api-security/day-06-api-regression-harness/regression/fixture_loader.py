"""
Fixture loader — reads test cases from YAML/CSV/JSON files.

Architecture decision: separating test data from test logic means:
  - QA engineers can add test cases without touching Python
  - Product managers can review/approve test coverage in YAML
  - Different environments use different fixture files (no code change)
  - Test cases can be generated from OpenAPI specs or Postman collections

Fixture schema (YAML):
  - id:          unique test case identifier
  - name:        human-readable description
  - method:      HTTP method (GET, POST, PUT, PATCH, DELETE)
  - path:        URL path (may contain {param} placeholders)
  - path_params: dict of path parameter substitutions
  - query:       dict of query parameters
  - headers:     dict of request headers
  - body:        request body (dict → JSON)
  - expected:
      status:    expected HTTP status code
      schema:    JSON Schema to validate response body against
      fields:    dict of expected field values (dot-path supported)
      contains:  list of strings that must appear in response body
      not_contains: list of strings that must NOT appear
      max_ms:    maximum acceptable response time in milliseconds
  - tags:        list of tags for filtering (smoke, regression, auth, etc.)
  - skip:        bool — skip this test case
  - skip_reason: reason for skip
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class ExpectedSpec:
    status:       int               = 200
    schema:       Optional[dict]    = None    # JSON Schema
    fields:       dict              = field(default_factory=dict)
    contains:     list[str]         = field(default_factory=list)
    not_contains: list[str]         = field(default_factory=list)
    max_ms:       Optional[float]   = None


@dataclass
class TestCase:
    id:           str
    name:         str
    method:       str
    path:         str
    path_params:  dict              = field(default_factory=dict)
    query:        dict              = field(default_factory=dict)
    headers:      dict              = field(default_factory=dict)
    body:         Any               = None
    expected:     ExpectedSpec      = field(default_factory=ExpectedSpec)
    tags:         list[str]         = field(default_factory=list)
    skip:         bool              = False
    skip_reason:  str               = ""

    @property
    def resolved_path(self) -> str:
        """Substitute {param} placeholders with path_params values."""
        path = self.path
        for key, value in self.path_params.items():
            path = path.replace(f"{{{key}}}", str(value))
        return path

    @property
    def tag_set(self) -> set[str]:
        return set(self.tags)


class FixtureLoader:
    """
    Loads test cases from YAML, JSON, or CSV fixture files.

    Multiple fixture files can be loaded and merged — useful for splitting
    fixtures by domain (users.yaml, orders.yaml, payments.yaml).
    """

    @classmethod
    def from_yaml(cls, path: str | Path) -> list[TestCase]:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return [cls._parse_case(c) for c in (data.get("tests") or data)]

    @classmethod
    def from_json(cls, path: str | Path) -> list[TestCase]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cases = data.get("tests") or data
        return [cls._parse_case(c) for c in cases]

    @classmethod
    def from_csv(cls, path: str | Path) -> list[TestCase]:
        """
        CSV format: id, name, method, path, status, tags
        Minimal format — body/schema validation not supported in CSV.
        Use YAML for complex assertions.
        """
        cases = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                cases.append(TestCase(
                    id=row.get("id", f"csv_{i}"),
                    name=row.get("name", f"Test {i}"),
                    method=row.get("method", "GET").upper(),
                    path=row.get("path", "/"),
                    expected=ExpectedSpec(status=int(row.get("status", 200))),
                    tags=row.get("tags", "").split(",") if row.get("tags") else [],
                ))
        return cases

    @classmethod
    def from_directory(cls, directory: str | Path) -> list[TestCase]:
        """Load all .yaml, .json fixture files from a directory."""
        all_cases: list[TestCase] = []
        dir_path = Path(directory)
        for yaml_file in sorted(dir_path.glob("**/*.yaml")):
            all_cases.extend(cls.from_yaml(yaml_file))
        for json_file in sorted(dir_path.glob("**/*.json")):
            if "schema" not in json_file.name:   # Skip JSON schema files
                all_cases.extend(cls.from_json(json_file))
        return all_cases

    @classmethod
    def filter_by_tag(cls, cases: list[TestCase], tag: str) -> list[TestCase]:
        return [c for c in cases if tag in c.tag_set]

    @classmethod
    def _parse_case(cls, raw: dict) -> TestCase:
        expected_raw = raw.get("expected", {})
        expected = ExpectedSpec(
            status=expected_raw.get("status", 200),
            schema=expected_raw.get("schema"),
            fields=expected_raw.get("fields", {}),
            contains=expected_raw.get("contains", []),
            not_contains=expected_raw.get("not_contains", []),
            max_ms=expected_raw.get("max_ms"),
        )
        return TestCase(
            id=str(raw.get("id", "unknown")),
            name=raw.get("name", ""),
            method=raw.get("method", "GET").upper(),
            path=raw.get("path", "/"),
            path_params=raw.get("path_params", {}),
            query=raw.get("query", {}),
            headers=raw.get("headers", {}),
            body=raw.get("body"),
            expected=expected,
            tags=raw.get("tags", []),
            skip=raw.get("skip", False),
            skip_reason=raw.get("skip_reason", ""),
        )
