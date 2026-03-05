"""Tests for the wirefilter FFI bindings.

These tests require the octorules-wirefilter package to be installed.
Skip gracefully if not available.
"""

from __future__ import annotations

import pytest

try:
    from octorules_wirefilter import get_schema_info, parse_expression

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
            "fields",
            "functions",
            "operators",
            "string_literals",
            "regex_literals",
            "ip_literals",
            "int_literals",
        ):
            assert key in result, f"missing key: {key}"

    def test_success_values_are_lists(self):
        result = parse_expression('http.host eq "example.com"')
        for key in (
            "fields",
            "functions",
            "operators",
            "string_literals",
            "regex_literals",
            "ip_literals",
            "int_literals",
        ):
            assert isinstance(result[key], list), f"{key} is not a list"

    def test_error_on_unknown_field(self):
        result = parse_expression('nonexistent_field eq "x"')
        assert "error" in result
        assert "unknown" in result["error"].lower()

    def test_error_on_syntax_error(self):
        result = parse_expression("http.host eq eq")
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
        result = parse_expression('http.host eq "a" or http.host eq "b" or http.host eq "c"')
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
        expr = 'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com") eq "a.cdn.com"'
        result = parse_expression(expr)
        assert "wildcard_replace" in result["functions"]


class TestOperatorExtraction:
    """Operator extraction from expressions."""

    def test_eq(self):
        result = parse_expression('http.host eq "example.com"')
        assert "eq" in result["operators"]

    def test_and_or(self):
        result = parse_expression('http.host eq "a" and http.host eq "b" or http.host eq "c"')
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
        result = parse_expression('http.host eq "a" xor http.host eq "b"')
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


class TestIsTimedHmacValidV0:
    """is_timed_hmac_valid_v0 with required and optional parameters."""

    def test_three_args(self):
        """3 required args: (Bytes, Bytes, Int) → Bool."""
        result = parse_expression('is_timed_hmac_valid_v0(http.request.full_uri, "secret", 300)')
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "is_timed_hmac_valid_v0" in result["functions"]
        assert "http.request.full_uri" in result["fields"]
        assert "secret" in result["string_literals"]
        assert 300 in result["int_literals"]

    def test_four_args(self):
        """4th optional arg (Bytes?): separator override."""
        result = parse_expression(
            'is_timed_hmac_valid_v0(http.request.full_uri, "secret", 300, "/")'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "is_timed_hmac_valid_v0" in result["functions"]
        assert "/" in result["string_literals"]

    def test_five_args(self):
        """5th optional arg (Int?): message start index."""
        result = parse_expression(
            'is_timed_hmac_valid_v0(http.request.full_uri, "secret", 300, "/", -1)'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "is_timed_hmac_valid_v0" in result["functions"]
        assert -1 in result["int_literals"]


class TestRemoveQueryArgs:
    """remove_query_args with required and variadic parameters."""

    def test_two_args(self):
        """Minimum: (Bytes, Bytes) → Bytes."""
        result = parse_expression(
            'remove_query_args(http.request.full_uri, "utm_source") eq "/path"'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "remove_query_args" in result["functions"]
        assert "utm_source" in result["string_literals"]

    def test_three_args(self):
        """3 args: 1 required + 1 variadic."""
        result = parse_expression(
            'remove_query_args(http.request.full_uri, "utm_source", "utm_medium") eq "/path"'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "remove_query_args" in result["functions"]
        assert "utm_source" in result["string_literals"]
        assert "utm_medium" in result["string_literals"]

    def test_five_args(self):
        """5 args: 1 required + 4 variadic."""
        result = parse_expression(
            'remove_query_args(http.request.full_uri, "a", "b", "c", "d") eq "/path"'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "remove_query_args" in result["functions"]
        for lit in ("a", "b", "c", "d"):
            assert lit in result["string_literals"]

    def test_eight_args(self):
        """8 args: 1 required + 7 variadic (maximum supported)."""
        args = ", ".join(f'"{chr(97 + i)}"' for i in range(7))
        result = parse_expression(f'remove_query_args(http.request.full_uri, {args}) eq "/path"')
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "remove_query_args" in result["functions"]


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
        expr = 'cf.threat_score gt 10 and ip.src in {192.168.0.0/16} and http.host eq "example.com"'
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


class TestEdgeCases:
    """Edge case coverage for literal types, nesting, and combinations."""

    def test_ipv6_literal(self):
        result = parse_expression("ip.src == 2001:db8::1")
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "2001:db8::1" in result["ip_literals"]

    def test_ipv6_cidr(self):
        result = parse_expression("ip.src in {2001:db8::/32}")
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "2001:db8::/32" in result["ip_literals"]

    def test_negative_integer(self):
        result = parse_expression("cf.threat_score eq -5")
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert -5 in result["int_literals"]

    def test_large_integer(self):
        result = parse_expression("cf.threat_score gt 2147483647")
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert 2147483647 in result["int_literals"]

    def test_unicode_string_literal(self):
        result = parse_expression('http.host eq "café.example.com"')
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "café.example.com" in result["string_literals"]

    def test_deeply_nested_parentheses(self):
        result = parse_expression('((((http.host eq "a"))))')
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "http.host" in result["fields"]
        assert "a" in result["string_literals"]

    def test_multiple_regex_patterns(self):
        result = parse_expression(
            'http.request.uri.path matches "^/api/.*" and http.user_agent matches "bot.*"'
        )
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "^/api/.*" in result["regex_literals"]
        assert "bot.*" in result["regex_literals"]


class TestInputLimits:
    """Boundary and stress tests for input validation."""

    def test_rejects_oversized_expression(self):
        """Expression > 1 MiB is rejected with an error dict."""
        huge = 'http.host eq "' + "x" * (2 * 1024 * 1024) + '"'
        result = parse_expression(huge)
        assert "error" in result
        assert "maximum length" in result["error"]

    def test_accepts_expression_near_limit(self):
        """500 KiB expression is accepted (not a size limit error)."""
        # Build a valid-ish expression under the limit.
        expr = 'http.host eq "' + "a" * (500 * 1024) + '"'
        result = parse_expression(expr)
        # Should either parse OK or hit a wirefilter error, but NOT the size limit.
        if "error" in result:
            assert "maximum length" not in result["error"]

    def test_deeply_nested_parens_handled_gracefully(self):
        """200+ levels of parentheses doesn't crash and signals depth exceeded."""
        depth = 200
        expr = "(" * depth + "ssl" + ")" * depth
        result = parse_expression(expr)
        # Should not crash — either parses or returns an error.
        assert isinstance(result, dict)
        # If it parsed successfully, the depth_exceeded flag should be set.
        if "error" not in result:
            assert result.get("depth_exceeded") is True

    def test_many_unique_fields_works(self):
        """Expression with 50+ fields extracts all of them."""
        # All Bytes-typed fields use eq "x"; all Int-typed fields use gt 0.
        string_fields = [
            "http.host",
            "http.referer",
            "http.cookie",
            "http.user_agent",
            "http.request.method",
            "http.request.uri",
            "http.request.full_uri",
            "http.request.version",
            "http.request.body.mime",
            "http.request.uri.query",
            "http.request.uri.path.extension",
            "cf.ray_id",
            "cf.tls_version",
            "cf.tls_cipher",
            "cf.tls_ciphers_sha1",
            "cf.tls_client_random",
            "cf.tls_client_extensions_sha1",
            "cf.tls_client_extensions_sha1_le",
            "cf.response.error_type",
            "cf.hostname.metadata",
            "cf.random_seed",
            "cf.verified_bot_category",
            "cf.worker.upstream_zone",
            "cf.waf.score.class",
            "cf.bot_management.ja3_hash",
            "cf.bot_management.ja4",
            "ip.src.city",
            "ip.src.continent",
            "ip.src.country",
            "ip.src.lat",
            "ip.src.lon",
            "ip.src.region",
            "ip.src.region_code",
            "ip.src.postal_code",
            "ip.src.metro_code",
            "ip.src.timezone.name",
        ]
        int_fields = [
            "cf.threat_score",
            "cf.tls_client_hello_length",
            "cf.edge.server_port",
            "cf.bot_management.score",
            "cf.waf.score",
            "cf.waf.score.sqli",
            "cf.waf.score.xss",
            "cf.waf.score.rce",
            "cf.response.1xxx_code",
            "cf.timings.edge_msec",
            "cf.timings.origin_ttfb_msec",
            "cf.timings.client_tcp_rtt_msec",
            "ip.src.asnum",
            "http.request.timestamp.sec",
        ]
        clauses = [f'{f} eq "x"' for f in string_fields]
        clauses += [f"{f} gt 0" for f in int_fields]
        expr = " or ".join(clauses)
        result = parse_expression(expr)
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert len(result["fields"]) >= 50

    def test_i64_max_value(self):
        result = parse_expression("cf.threat_score gt 9223372036854775807")
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert 9223372036854775807 in result["int_literals"]

    def test_null_byte_in_expression(self):
        result = parse_expression('http.host eq "\x00"')
        assert isinstance(result, dict)

    def test_empty_string_literal(self):
        result = parse_expression('http.host eq ""')
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "" in result["string_literals"]


class TestPhaseEdgeCases:
    """Edge case tests for the phase parameter."""

    def test_misspelled_phase_falls_back_to_default(self):
        """Misspelled phase name uses default scheme."""
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="url_rewrite_rule",  # missing trailing 's'
        )
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_empty_phase_string_falls_back(self):
        """Empty string phase uses default scheme."""
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="",
        )
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_none_phase_is_default(self):
        """Explicit None uses default scheme."""
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase=None,
        )
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_uppercase_phase_falls_back(self):
        """Uppercase phase name uses default scheme (case-sensitive)."""
        result = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="URL_REWRITE_RULES",
        )
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]


class TestGetSchemaInfo:
    """Tests for the get_schema_info() FFI function."""

    def test_returns_dict(self):
        info = get_schema_info()
        assert isinstance(info, dict)

    def test_has_required_keys(self):
        info = get_schema_info()
        for key in ("fields", "functions", "transform_phases", "transform_field_as_function"):
            assert key in info, f"missing key: {key}"

    def test_fields_are_list_of_dicts(self):
        info = get_schema_info()
        assert isinstance(info["fields"], list)
        assert len(info["fields"]) > 100
        for entry in info["fields"]:
            assert "name" in entry
            assert "type" in entry

    def test_field_types_are_valid(self):
        valid_types = {
            "STRING",
            "INT",
            "BOOL",
            "IP",
            "ARRAY_STRING",
            "ARRAY_INT",
            "ARRAY_ARRAY_STRING",
            "MAP_ARRAY_STRING",
            "MAP_ARRAY_INT",
        }
        info = get_schema_info()
        for entry in info["fields"]:
            assert entry["type"] in valid_types, (
                f"field {entry['name']} has unexpected type {entry['type']}"
            )

    def test_functions_are_list_of_strings(self):
        info = get_schema_info()
        assert isinstance(info["functions"], list)
        assert len(info["functions"]) > 30
        for name in info["functions"]:
            assert isinstance(name, str)

    def test_transform_phases(self):
        info = get_schema_info()
        assert set(info["transform_phases"]) == {
            "url_rewrite_rules",
            "request_header_rules",
            "response_header_rules",
        }

    def test_transform_field_as_function(self):
        info = get_schema_info()
        assert info["transform_field_as_function"] == "http.request.uri.path"

    def test_known_field_present(self):
        info = get_schema_info()
        names = [f["name"] for f in info["fields"]]
        assert "http.host" in names
        assert "ip.src" in names

    def test_known_function_present(self):
        info = get_schema_info()
        assert "lower" in info["functions"]
        assert "starts_with" in info["functions"]
