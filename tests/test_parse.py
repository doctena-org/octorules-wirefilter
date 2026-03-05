"""Tests for the wirefilter FFI bindings.

These tests require the octorules-wirefilter package to be installed.
Skip gracefully if not available.
"""

from __future__ import annotations

import pytest

try:
    from octorules_wirefilter import parse_expression

    HAS_WIREFILTER = True
except ImportError:
    HAS_WIREFILTER = False

pytestmark = pytest.mark.skipif(not HAS_WIREFILTER, reason="octorules-wirefilter not installed")


class TestParseExpression:
    """Basic return-type and key contract tests."""

    def test_returns_dict(self):
        result = parse_expression('http.host eq "example.com"')
        assert isinstance(result, dict)

    def test_success_has_all_keys(self):
        result = parse_expression('http.host eq "example.com"')
        for key in (
            "fields", "functions", "operators",
            "string_literals", "regex_literals",
            "ip_literals", "int_literals",
        ):
            assert key in result, f"missing key: {key}"

    def test_success_values_are_lists(self):
        result = parse_expression('http.host eq "example.com"')
        for key in (
            "fields", "functions", "operators",
            "string_literals", "regex_literals",
            "ip_literals", "int_literals",
        ):
            assert isinstance(result[key], list), f"{key} is not a list"

    def test_error_on_unknown_field(self):
        result = parse_expression('nonexistent_field eq "x"')
        assert "error" in result
        assert "unknown" in result["error"].lower()

    def test_error_on_syntax_error(self):
        result = parse_expression('http.host eq eq')
        assert "error" in result


class TestFieldExtraction:
    """Field extraction from various expression types."""

    def test_single_field(self):
        result = parse_expression('http.host eq "example.com"')
        assert result["fields"] == ["http.host"]

    def test_multiple_fields(self):
        result = parse_expression('http.host eq "a" and ip.src in {1.2.3.4}')
        assert "http.host" in result["fields"]
        assert "ip.src" in result["fields"]

    def test_deduplicated_fields(self):
        result = parse_expression(
            'http.host eq "a" or http.host eq "b" or http.host eq "c"'
        )
        assert result["fields"].count("http.host") == 1

    def test_field_in_function(self):
        result = parse_expression('lower(http.host) eq "example.com"')
        assert "http.host" in result["fields"]

    def test_boolean_field(self):
        result = parse_expression("ssl")
        assert result["fields"] == ["ssl"]

    def test_ip_field(self):
        result = parse_expression("ip.src == 1.2.3.4")
        assert result["fields"] == ["ip.src"]


class TestFunctionExtraction:
    """Function call extraction."""

    def test_lower(self):
        result = parse_expression('lower(http.host) eq "example.com"')
        assert "lower" in result["functions"]

    def test_starts_with(self):
        result = parse_expression('starts_with(http.request.uri.path, "/api/")')
        assert "starts_with" in result["functions"]

    def test_nested_function_and_field(self):
        result = parse_expression('lower(http.host) eq "a"')
        assert "lower" in result["functions"]
        assert "http.host" in result["fields"]

    def test_no_functions(self):
        result = parse_expression('http.host eq "example.com"')
        assert result["functions"] == []

    def test_encode_base64(self):
        result = parse_expression('encode_base64(http.request.uri.path) eq "L2Fw"')
        assert "encode_base64" in result["functions"]

    def test_decode_base64(self):
        result = parse_expression('decode_base64(http.request.uri.path) eq "/api"')
        assert "decode_base64" in result["functions"]

    def test_cidr(self):
        result = parse_expression("cidr(ip.src, 24, 0) == 10.0.0.0")
        assert "cidr" in result["functions"]

    def test_cidr6(self):
        result = parse_expression("cidr6(ip.src, 48) == 2001:db8::")
        assert "cidr6" in result["functions"]

    def test_join(self):
        result = parse_expression('join(http.request.headers.names, ",") eq "a,b"')
        assert "join" in result["functions"]

    def test_split(self):
        result = parse_expression('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "split" in result["functions"]

    def test_has_key(self):
        result = parse_expression('has_key(http.request.headers, "x-api-key")')
        assert "has_key" in result["functions"]

    def test_wildcard_replace(self):
        result = parse_expression('wildcard_replace(http.host, "*.example.com", "${1}.cdn.com") eq "a.cdn.com"')
        assert "wildcard_replace" in result["functions"]


class TestOperatorExtraction:
    """Operator extraction from expressions."""

    def test_eq(self):
        result = parse_expression('http.host eq "example.com"')
        assert "eq" in result["operators"]

    def test_and_or(self):
        result = parse_expression(
            'http.host eq "a" and http.host eq "b" or http.host eq "c"'
        )
        assert "and" in result["operators"]
        assert "or" in result["operators"]

    def test_not(self):
        result = parse_expression('not http.host eq "bad.com"')
        assert "not" in result["operators"]

    def test_in(self):
        result = parse_expression('http.host in {"a" "b"}')
        assert "in" in result["operators"]

    def test_contains(self):
        result = parse_expression('http.host contains "api"')
        assert "contains" in result["operators"]

    def test_matches(self):
        result = parse_expression('http.request.uri.path matches "^/api/.*"')
        assert "matches" in result["operators"]

    def test_gt(self):
        result = parse_expression("cf.threat_score gt 50")
        assert "gt" in result["operators"]

    def test_ne(self):
        result = parse_expression('http.host ne "bad.com"')
        assert "ne" in result["operators"]

    def test_ge(self):
        result = parse_expression("cf.threat_score ge 50")
        assert "ge" in result["operators"]

    def test_le(self):
        result = parse_expression("cf.threat_score le 50")
        assert "le" in result["operators"]

    def test_lt(self):
        result = parse_expression("cf.threat_score lt 50")
        assert "lt" in result["operators"]

    def test_wildcard(self):
        result = parse_expression('http.host wildcard "*.example.com"')
        assert "wildcard" in result["operators"]
        assert "*.example.com" in result["string_literals"]

    def test_strict_wildcard(self):
        result = parse_expression('http.host strict wildcard "*.example.com"')
        assert "strict_wildcard" in result["operators"]
        assert "*.example.com" in result["string_literals"]

    def test_bitwise_and(self):
        result = parse_expression("cf.waf.score bitwise_and 2")
        assert "bitwise_and" in result["operators"]
        assert 2 in result["int_literals"]

    def test_xor(self):
        result = parse_expression(
            'http.host eq "a" xor http.host eq "b"'
        )
        assert "xor" in result["operators"]


class TestLiteralExtraction:
    """String, regex, IP, and integer literal extraction."""

    def test_string_literal(self):
        result = parse_expression('http.host eq "example.com"')
        assert "example.com" in result["string_literals"]

    def test_string_set(self):
        result = parse_expression('http.host in {"alpha" "beta" "gamma"}')
        assert "alpha" in result["string_literals"]
        assert "beta" in result["string_literals"]
        assert "gamma" in result["string_literals"]

    def test_regex_literal(self):
        result = parse_expression('http.request.uri.path matches "^/api/.*"')
        assert "^/api/.*" in result["regex_literals"]

    def test_ip_literal(self):
        result = parse_expression("ip.src == 1.2.3.4")
        assert "1.2.3.4" in result["ip_literals"]

    def test_ip_cidr(self):
        result = parse_expression("ip.src in {10.0.0.0/8}")
        assert "10.0.0.0/8" in result["ip_literals"]

    def test_int_literal(self):
        result = parse_expression("cf.threat_score gt 50")
        assert 50 in result["int_literals"]

    def test_function_string_arg(self):
        result = parse_expression('starts_with(http.request.uri.path, "/blog/")')
        assert "/blog/" in result["string_literals"]


class TestEmptyExpression:
    """Empty and whitespace expressions."""

    def test_empty_string(self):
        result = parse_expression("")
        assert result.get("error") is None
        assert result["fields"] == []
        assert result["functions"] == []
        assert result["operators"] == []

    def test_whitespace_only(self):
        result = parse_expression("   ")
        assert result.get("error") is None
        assert result["fields"] == []


class TestPhaseContextParsing:
    """Tests for phase-dependent scheme selection."""

    def test_no_phase_uses_default_scheme(self):
        """Without phase, http.request.uri.path is a field."""
        result = parse_expression('http.request.uri.path eq "/test"')
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_none_phase_uses_default_scheme(self):
        """Explicit None behaves the same as omitting phase."""
        result = parse_expression('http.request.uri.path eq "/test"', phase=None)
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_unknown_phase_uses_default_scheme(self):
        """Non-transform phase falls back to default scheme."""
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="http_request_firewall_custom",
        )
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_url_rewrite_rules_uses_transform_scheme(self):
        """In url_rewrite_rules, http.request.uri.path is a function."""
        # This expression uses uri.path as a function call — should parse OK
        # in transform scheme but fail in default scheme.
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="url_rewrite_rules",
        )
        # uri.path is NOT a field in transform scheme, so this should error
        assert "error" in result

    def test_request_header_rules_uses_transform_scheme(self):
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="request_header_rules",
        )
        assert "error" in result

    def test_response_header_rules_uses_transform_scheme(self):
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="response_header_rules",
        )
        assert "error" in result

    def test_transform_phase_parses_uri_path_as_function(self):
        """In transform phase, uri.path can be used as a function."""
        # Use uri.path as a function wrapping another field
        result = parse_expression(
            'http.request.uri.path(http.request.uri) eq "/rewritten"',
            phase="url_rewrite_rules",
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "http.request.uri.path" in result["functions"]


class TestComplexExpressions:
    """Multi-clause expressions with many component types."""

    def test_full_expression(self):
        expr = (
            '(http.request.method eq "POST" and '
            'starts_with(http.request.uri.path, "/api/")) or '
            'http.request.uri.path matches "^/static/.*"'
        )
        result = parse_expression(expr)
        assert "http.request.method" in result["fields"]
        assert "http.request.uri.path" in result["fields"]
        assert "starts_with" in result["functions"]
        assert "or" in result["operators"]
        assert "and" in result["operators"]
        assert "eq" in result["operators"]
        assert "matches" in result["operators"]
        assert "POST" in result["string_literals"]
        assert "/api/" in result["string_literals"]
        assert "^/static/.*" in result["regex_literals"]

    def test_mixed_types(self):
        expr = (
            'cf.threat_score gt 10 and '
            'ip.src in {192.168.0.0/16} and '
            'http.host eq "example.com"'
        )
        result = parse_expression(expr)
        assert "cf.threat_score" in result["fields"]
        assert "ip.src" in result["fields"]
        assert "http.host" in result["fields"]
        assert 10 in result["int_literals"]
        assert "192.168.0.0/16" in result["ip_literals"]
        assert "example.com" in result["string_literals"]

    def test_boolean_field_with_not(self):
        result = parse_expression("not ssl")
        assert "ssl" in result["fields"]
        assert "not" in result["operators"]
