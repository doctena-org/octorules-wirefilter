"""Type stub for octorules_wirefilter — PyO3 FFI bindings for Cloudflare wirefilter."""

from typing import Any

def parse_expression(expr: str, scheme: str | None = None) -> dict[str, Any]:
    """Parse a wirefilter expression and return extracted components.

    The `scheme` parameter selects the field scheme: `"magic_firewall"` uses
    the packet-level Layer-4 scheme; any other value (or `None`) uses the
    default HTTP scheme.

    Returns a dict with the following keys:
      - `fields`: list of field names (strings) referenced in the expression.
      - `functions`: list of function names (strings) called in the expression.
      - `operators`: list of operators (strings, e.g. "eq", "ne", "matches").
      - `string_literals`: list of string literal values.
      - `regex_literals`: list of regex patterns (strings).
      - `regex_field_pairs`: list of [field_name, regex_pattern] pairs (two-element
        lists) showing which field each regex is matched against. Only populated
        for `matches` operators with a plain field on the left-hand side.
      - `ip_literals`: list of IP address/range literals (strings).
      - `int_literals`: list of integer literals (ints).
      - `error` (optional): error message (string) if parsing failed. Present
        with all list keys as empty lists.
      - `depth_exceeded` (optional): boolean `true` if AST nesting exceeded the
        extraction walk limit (100 levels). Expressions nested deeper than 128
        levels do not reach extraction: the engine rejects them at parse time
        and `error` is set instead.

    On success: all list keys are populated with extracted values.
    On failure: `error` key is present with all list keys as empty lists.
    Empty or whitespace-only expressions are valid and return empty lists.
    Expressions exceeding 1 MiB are rejected with an error dict.
    """
    ...

def get_schema_info(scheme: str | None = None) -> dict[str, Any]:
    """Return schema metadata for a wirefilter scheme.

    The `scheme` parameter selects the field set: `"magic_firewall"` returns
    the Layer-4 (Magic Transit) fields; any other value (or `None`) returns
    the default HTTP fields.

    Returns a dict with:
      - `fields`: list of dicts, each with `name` (str) and `type` (str,
        e.g. "STRING", "INT", "BOOL", "IP").
      - `functions`: list of function names (strings).
    """
    ...
