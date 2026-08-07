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
            "regex_field_pairs",
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
            "regex_field_pairs",
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

    def test_error_response_has_all_keys(self):
        """Parse error responses should include all standard keys for API consistency."""
        result = parse_expression("http.host eq eq")
        assert "error" in result
        for key in (
            "fields",
            "functions",
            "operators",
            "string_literals",
            "regex_literals",
            "regex_field_pairs",
            "ip_literals",
            "int_literals",
        ):
            assert key in result, f"Missing key {key!r} in error response"
            assert result[key] == []


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

    @pytest.mark.parametrize(
        "expr,fn",
        [
            ('lower(http.host) eq "example.com"', "lower"),
            ('starts_with(http.request.uri.path, "/api/")', "starts_with"),
            ('encode_base64(http.request.uri.path) eq "L2Fw"', "encode_base64"),
            ('decode_base64(http.request.uri.path) eq "/api"', "decode_base64"),
            ("cidr(ip.src, 24, 0) == 10.0.0.0", "cidr"),
            ("cidr6(ip.src, 48) == 2001:db8::", "cidr6"),
            ('join(http.request.headers.names, ",") eq "a,b"', "join"),
            ('any(split(http.request.uri.path, "/", 3)[*] eq "api")', "split"),
            ('has_key(http.request.headers, "x-api-key")', "has_key"),
            ('upper(http.host) eq "EXAMPLE.COM"', "upper"),
            ('url_decode(http.request.uri.path) eq "/hello world"', "url_decode"),
            ('uuidv4(http.request.uri.path) eq "test"', "uuidv4"),
            ('contains(http.host, "example")', "contains"),
            ("len(http.host) gt 10", "len"),
            ('substring(http.host, 0, 5) eq "examp"', "substring"),
            (
                'regex_replace(http.request.uri.path, "/old", "/new") eq "/new"',
                "regex_replace",
            ),
            ('remove_bytes(http.host, "www.") eq "example.com"', "remove_bytes"),
            ('to_string(cf.threat_score) eq "50"', "to_string"),
            (
                'lookup_json_string(http.request.body.raw, "key") eq "value"',
                "lookup_json_string",
            ),
            (
                'lookup_json_integer(http.request.body.raw, "count") gt 0',
                "lookup_json_integer",
            ),
            ('sha256(http.request.body.raw) eq "abc"', "sha256"),
            ('sha512(http.request.body.raw) eq "abc"', "sha512"),
            ('hmac(http.request.uri.path, "secret", "sha256") eq "abc"', "hmac"),
            ('ip_in_range(ip.src, "10.0.0.0/8")', "ip_in_range"),
            ('has_value(http.request.headers.names, "x-api-key")', "has_value"),
            ("bit_slice(http.request.body.raw, 0, 8) gt 0", "bit_slice"),
            (
                'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com") eq "a.cdn.com"',
                "wildcard_replace",
            ),
        ],
    )
    def test_function_name_extracted(self, expr, fn):
        """Each documented Cloudflare function name is surfaced in ``functions``."""
        result = parse_expression(expr)
        assert fn in result["functions"]

    def test_nested_function_and_field(self):
        """Functions and fields are extracted from the same expression."""
        result = parse_expression('lower(http.host) eq "a"')
        assert "lower" in result["functions"]
        assert "http.host" in result["fields"]

    def test_no_functions(self):
        """Expressions with no function calls return an empty list."""
        result = parse_expression('http.host eq "example.com"')
        assert result["functions"] == []


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

    @pytest.mark.parametrize(
        "expr,bucket,expected",
        [
            ('http.host eq "example.com"', "string_literals", "example.com"),
            ('http.request.uri.path matches "^/api/.*"', "regex_literals", "^/api/.*"),
            ("ip.src == 1.2.3.4", "ip_literals", "1.2.3.4"),
            ("ip.src in {10.0.0.0/8}", "ip_literals", "10.0.0.0/8"),
            ("cf.threat_score gt 50", "int_literals", 50),
            (
                'starts_with(http.request.uri.path, "/blog/")',
                "string_literals",
                "/blog/",
            ),
        ],
    )
    def test_literal_extracted(self, expr, bucket, expected):
        """Each literal type lands in its dedicated bucket."""
        result = parse_expression(expr)
        assert expected in result[bucket]

    def test_string_set_extracts_all(self):
        """A set literal yields every member into ``string_literals``."""
        result = parse_expression('http.host in {"alpha" "beta" "gamma"}')
        for s in ("alpha", "beta", "gamma"):
            assert s in result["string_literals"]


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


class TestSchemeParameter:
    """Tests for the scheme parameter (selects HTTP vs Magic Transit L4)."""

    def test_no_scheme(self):
        """Without scheme, http.request.uri.path is a field (default HTTP)."""
        result = parse_expression('http.request.uri.path eq "/test"')
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_none_scheme(self):
        """Explicit None behaves the same as omitting scheme (default HTTP)."""
        result = parse_expression('http.request.uri.path eq "/test"', scheme=None)
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]

    def test_unknown_scheme_uses_http(self):
        """Any scheme other than "magic_firewall" falls back to the HTTP scheme."""
        for scheme in (
            "http_request_firewall_custom",
            "url_rewrite_rules",
            "request_header_rules",
            "response_header_rules",
        ):
            result = parse_expression(
                'http.request.uri.path eq "/test"',
                scheme=scheme,
            )
            assert "error" not in result, f"scheme={scheme}: {result.get('error')}"
            assert "http.request.uri.path" in result["fields"]

    def test_magic_firewall_scheme(self):
        """scheme="magic_firewall" parses Layer-4 packet fields."""
        result = parse_expression(
            'ip.proto eq "tcp" and tcp.dstport in {23 3389}',
            scheme="magic_firewall",
        )
        assert "error" not in result, result.get("error")
        assert "ip.proto" in result["fields"]
        assert "tcp.dstport" in result["fields"]

    def test_magic_firewall_rejects_http_fields(self):
        """HTTP-only fields are unknown in the Layer-4 scheme."""
        result = parse_expression('http.request.uri.path eq "/test"', scheme="magic_firewall")
        assert "error" in result


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
        """Expression > 1 MiB is rejected with an error dict with all keys."""
        huge = 'http.host eq "' + "x" * (2 * 1024 * 1024) + '"'
        result = parse_expression(huge)
        assert "error" in result
        assert "maximum length" in result["error"]
        # Error responses should include all standard keys for API consistency
        for key in (
            "fields",
            "functions",
            "operators",
            "string_literals",
            "regex_literals",
            "regex_field_pairs",
            "ip_literals",
            "int_literals",
        ):
            assert key in result, f"Missing key {key!r} in oversized error response"
            assert result[key] == []

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

    def test_exact_size_limit_accepted(self):
        """Expression at exactly 1 MiB is accepted (not rejected by size check)."""
        limit = 1_048_576
        prefix = 'http.host eq "'
        suffix = '"'
        padding = limit - len(prefix) - len(suffix)
        expr = prefix + "a" * padding + suffix
        assert len(expr) == limit
        result = parse_expression(expr)
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert "fields" in result

    def test_one_byte_over_limit_rejected(self):
        """Expression at 1 MiB + 1 is rejected."""
        limit = 1_048_576
        expr = "a" * (limit + 1)
        result = parse_expression(expr)
        assert "error" in result
        assert "maximum length" in result["error"]
        assert str(limit + 1) in result["error"]
        # Error responses still include standard keys with empty lists
        assert result["fields"] == []
        assert result["int_literals"] == []

    def test_depth_exceeded_flag_on_deep_logical_nesting(self):
        """Between our visitor's walk limit (100) and the engine's parse
        limit (128), the expression parses and the flag reports the
        truncated walk."""
        depth = 110
        expr = "(" * depth + "ssl" + ")" * depth
        result = parse_expression(expr)
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert result.get("depth_exceeded") is True

    def test_nesting_boundary_is_exactly_128(self):
        """128 parses, 129 fails — the boundary itself is the regression
        tripwire for an upstream default change."""
        ok = "(" * 128 + "ssl" + ")" * 128
        bad = "(" * 129 + "ssl" + ")" * 129
        assert "error" not in parse_expression(ok)
        assert "maximum nesting depth exceeded" in parse_expression(bad).get("error", "")

    def test_engine_rejects_nesting_beyond_128(self):
        """The engine enforces its own nesting limit at parse time
        (upstream 02741bcb) — the same rejection Cloudflare's edge gives,
        so lint now matches it instead of parsing pathological input."""
        depth = 150
        expr = "(" * depth + "ssl" + ")" * depth
        result = parse_expression(expr)
        assert "maximum nesting depth exceeded" in result.get("error", "")

    def test_depth_not_exceeded_at_shallow_nesting(self):
        """Shallow nesting (10 levels) does NOT set depth_exceeded."""
        depth = 10
        expr = "(" * depth + "ssl" + ")" * depth
        result = parse_expression(expr)
        assert "error" not in result, f"unexpected error: {result.get('error')}"
        assert result.get("depth_exceeded") is not True


class TestSchemeEdgeCases:
    """Edge cases for the scheme parameter — any value other than
    "magic_firewall" falls back to the default HTTP scheme."""

    @pytest.mark.parametrize(
        "scheme",
        [
            None,  # explicit None
            "",  # empty string
            "url_rewrite_rule",  # not a recognized scheme name
            "URL_REWRITE_RULES",  # wrong case
        ],
    )
    def test_unknown_scheme_falls_back_to_http(self, scheme):
        result = parse_expression('http.request.uri.path eq "/test"', scheme=scheme)
        assert "error" not in result
        assert "http.request.uri.path" in result["fields"]


class TestGetSchemaInfo:
    """Tests for the get_schema_info() FFI function."""

    def test_returns_dict(self):
        info = get_schema_info()
        assert isinstance(info, dict)

    def test_schema_shape(self):
        """Single shape check: fields/functions present, fields are typed
        dicts, every field type is one of the documented enum values, and
        functions is a non-trivial list of strings."""
        valid_types = {
            "STRING",
            "INT",
            "BOOL",
            "IP",
            "ARRAY_STRING",
            "ARRAY_INT",
            "ARRAY_ARRAY_STRING",
            "MAP_STRING_STRING",
            "MAP_STRING_INT",
            "MAP_ARRAY_STRING",
            "MAP_ARRAY_INT",
        }
        info = get_schema_info()
        for key in ("fields", "functions"):
            assert key in info, f"missing key: {key}"
        assert isinstance(info["fields"], list) and len(info["fields"]) > 100
        for entry in info["fields"]:
            assert "name" in entry and "type" in entry
            assert entry["type"] in valid_types, (
                f"field {entry['name']} has unexpected type {entry['type']}"
            )
        assert isinstance(info["functions"], list) and len(info["functions"]) > 30
        assert all(isinstance(name, str) for name in info["functions"])

    def test_known_field_present(self):
        info = get_schema_info()
        names = [f["name"] for f in info["fields"]]
        assert "http.host" in names
        assert "ip.src" in names

    def test_known_function_present(self):
        info = get_schema_info()
        assert "lower" in info["functions"]
        assert "starts_with" in info["functions"]


# ---------------------------------------------------------------------------
# 2026 CF additions: RFC 9440 mTLS, L4/timings, LLM, JWT functions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_WIREFILTER, reason="wirefilter not installed")
class TestRecentCFAdditions:
    """Each recently-added Cloudflare field/function has a parse-level
    test that fails fast if the registration is dropped from the scheme."""

    def test_rfc9440_mtls_fields_parse(self):
        """All four RFC 9440 mTLS Client-Cert fields parse cleanly.

        Bytes fields use ``ne ""`` to test; bool fields are bare-truth
        (the wirefilter idiom — ``bool_field eq true`` is not valid
        syntax for bare bool fields).
        """
        for expr, expected in [
            (
                'cf.tls_client_auth.cert_chain_rfc9440 ne ""',
                "cf.tls_client_auth.cert_chain_rfc9440",
            ),
            (
                "cf.tls_client_auth.cert_chain_rfc9440_too_large",
                "cf.tls_client_auth.cert_chain_rfc9440_too_large",
            ),
            ('cf.tls_client_auth.cert_rfc9440 ne ""', "cf.tls_client_auth.cert_rfc9440"),
            (
                "cf.tls_client_auth.cert_rfc9440_too_large",
                "cf.tls_client_auth.cert_rfc9440_too_large",
            ),
        ]:
            r = parse_expression(expr)
            assert r.get("error") is None, f"{expr}: {r.get('error')}"
            assert expected in r["fields"]

    def test_l4_and_timings_fields_parse(self):
        """2026-03 additions for L4 stats and timings."""
        for expr, expected in [
            ("cf.edge.l4.delivery_rate gt 1000", "cf.edge.l4.delivery_rate"),
            ("cf.timings.client_quic_rtt_msec lt 100", "cf.timings.client_quic_rtt_msec"),
            ("cf.timings.worker_msec gt 10", "cf.timings.worker_msec"),
        ]:
            r = parse_expression(expr)
            assert r.get("error") is None, f"{expr}: {r.get('error')}"
            assert expected in r["fields"]

    def test_llm_2026_fields_parse(self):
        """2026-03-11 AI prompt features."""
        r = parse_expression("cf.llm.prompt.token_count gt 4000")
        assert r.get("error") is None, r.get("error")
        assert "cf.llm.prompt.token_count" in r["fields"]
        # Map-typed field — index access is the documented use.
        r = parse_expression('cf.llm.prompt.custom_topic_categories["competitors"] lt 30')
        assert r.get("error") is None, r.get("error")
        assert "cf.llm.prompt.custom_topic_categories" in r["fields"]

    def test_jwt_validation_functions_take_literal_arg(self):
        """``is_jwt_valid`` and ``is_jwt_present`` accept a UUID literal."""
        # Documented usage from CF docs.
        for fn in ["is_jwt_valid", "is_jwt_present"]:
            r = parse_expression(f'{fn}("51231d16-01f1-48e3-93f8-91c99e81288e")')
            assert r.get("error") is None, f"{fn}: {r.get('error')}"
            assert fn in r["functions"]

    def test_jwt_validation_function_rejects_field_arg(self):
        """Passing a field where a literal is expected is a parse error."""
        # Field arg should fail because the param is registered as Literal.
        r = parse_expression('is_jwt_valid(http.request.headers["authorization"])')
        assert r.get("error") is not None


# ---------------------------------------------------------------------------
# Speculative-addition regression guards
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_WIREFILTER, reason="wirefilter not installed")
class TestSpeculativeRemovals:
    """Four fields registered earlier by symmetry-pattern reasoning are
    intentionally absent — Cloudflare doesn't expose them. Re-adding any
    of them must be backed by current CF docs evidence, not symmetry.
    See CHANGELOG for the per-field rationale."""

    def test_jwt_exp_sec_no_longer_parses(self):
        """``http.request.jwt.claims.exp.sec`` is intentionally absent;
        CF doesn't expose ``exp`` as a queryable field (validates via
        ``is_jwt_valid()`` internally)."""
        for field in [
            "http.request.jwt.claims.exp.sec",
            "http.request.jwt.claims.exp.sec.names",
            "http.request.jwt.claims.exp.sec.values",
        ]:
            r = parse_expression(f'{field} != ""')
            assert r.get("error") is not None, f"{field} should be removed but parse succeeded"

    def test_response_headers_truncated_no_longer_parses(self):
        """``http.response.headers.truncated`` is intentionally absent;
        CF docs don't expose a response-side variant of the truncation
        indicator (only ``http.request.headers.truncated`` exists)."""
        r = parse_expression("http.response.headers.truncated eq true")
        assert r.get("error") is not None


# ---------------------------------------------------------------------------
# regex_field_pairs: field-context for regex literals
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_WIREFILTER, reason="wirefilter not installed")
class TestRegexFieldPairs:
    """The result dict carries ``regex_field_pairs`` — (field, regex)
    tuples for `matches` operators against plain field LHS."""

    def test_pair_recorded_for_plain_field_lhs(self):
        r = parse_expression(r'http.host matches "api\.example\.com"')
        pairs = r["regex_field_pairs"]
        assert len(pairs) == 1
        field, regex = pairs[0]
        assert field == "http.host"
        assert "api" in regex

    def test_pair_skipped_for_function_call_lhs(self):
        """``lower(http.host) matches "..."`` — function-call LHS;
        field context is ambiguous after a transformation, so no pair."""
        r = parse_expression(r'lower(http.host) matches "x"')
        assert r["regex_field_pairs"] == []
        # The flat regex_literals list still records the regex.
        assert len(r["regex_literals"]) == 1

    def test_pair_empty_for_non_matches_operator(self):
        r = parse_expression('http.host eq "example.com"')
        assert r["regex_field_pairs"] == []

    def test_multiple_pairs_recorded(self):
        r = parse_expression(r'http.host matches "a" or http.request.uri.path matches "b"')
        fields = {f for f, _ in r["regex_field_pairs"]}
        assert "http.host" in fields
        assert "http.request.uri.path" in fields


# ---------------------------------------------------------------------------
# Named list support ($list_name)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_WIREFILTER, reason="wirefilter not installed")
class TestNamedLists:
    def test_ip_named_list_basic(self):
        """``ip.src in $blocked_ips`` parses, extracts the field, and the operator."""
        r = parse_expression("ip.src in $blocked_ips")
        assert r.get("error") is None
        assert "ip.src" in r["fields"]
        assert "in" in r["operators"]

    def test_string_named_list(self):
        r = parse_expression("http.host in $allowed_hosts")
        assert r.get("error") is None
        assert "http.host" in r["fields"]

    def test_int_named_list(self):
        r = parse_expression("cf.bot_management.score in $suspicious")
        assert r.get("error") is None
        assert "cf.bot_management.score" in r["fields"]

    def test_negated_named_list(self):
        r = parse_expression("not ip.src in $allowlist")
        assert r.get("error") is None
        assert "not" in r["operators"]
        assert "in" in r["operators"]

    def test_named_list_in_compound_expression(self):
        r = parse_expression('ip.src in $blocked and http.host eq "example.com"')
        assert r.get("error") is None
        assert "ip.src" in r["fields"]
        assert "http.host" in r["fields"]
        assert "in" in r["operators"]
        assert "eq" in r["operators"]

    def test_two_named_lists(self):
        r = parse_expression("ip.src in $list_a or ip.src in $list_b")
        assert r.get("error") is None
        assert "ip.src" in r["fields"]
        assert "or" in r["operators"]

    def test_named_list_with_literal_set(self):
        r = parse_expression('ip.src in $blocked or http.host in {"a.com" "b.com"}')
        assert r.get("error") is None
        assert "a.com" in r["string_literals"]


# ---------------------------------------------------------------------------
# Wildcard star limit (ParserSettings)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_WIREFILTER, reason="wirefilter not installed")
class TestWildcardLimit:
    def test_at_limit_accepted(self):
        """Exactly 10 stars (the limit) parses without error."""
        pattern = ".".join(["*"] * 10) + ".com"
        r = parse_expression(f'http.host wildcard "{pattern}"')
        assert r.get("error") is None

    def test_one_over_limit_rejected(self):
        """11 stars (one past the limit) is rejected."""
        pattern = ".".join(["*"] * 11) + ".com"
        r = parse_expression(f'http.host wildcard "{pattern}"')
        assert r.get("error") is not None

    def test_escaped_stars_not_counted(self):
        """Escaped \\* shouldn't count toward the limit."""
        r = parse_expression(r'http.host wildcard "\\*\\*\\*.example.com"')
        # Escaped stars are literal — may or may not count depending on
        # wirefilter's implementation. Just verify it doesn't crash.
        assert isinstance(r, dict)


class TestQuantifiersInParseOutput:
    """any()/all() are native AST quantifiers since the ec8e24e engine bump,
    not registered functions — but to the expression author they are function
    calls, so parse output must keep reporting them under `functions`."""

    def test_any_reported_as_function_with_inner_field(self):
        result = parse_expression('any(http.request.headers.names[*] == "x")')
        assert "error" not in result, result.get("error")
        assert "any" in result["functions"]
        assert "http.request.headers.names" in result["fields"]

    def test_all_reported_as_function(self):
        result = parse_expression('all(http.request.headers.names[*] != "y")')
        assert "error" not in result, result.get("error")
        assert "all" in result["functions"]

    def test_nested_function_inside_quantifier_also_reported(self):
        result = parse_expression('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "error" not in result, result.get("error")
        assert "any" in result["functions"]
        assert "split" in result["functions"]

    def test_quantifier_arg_must_be_boolean_array(self):
        """The quantifier arg is typed: a plain Bool comparison is rejected
        with a precise error, as on the edge."""
        result = parse_expression('any(http.request.uri.path == "/x")')
        assert "expected value of type Array<Bool>, but got Bool" in result.get("error", "")

    def test_quantifier_rejects_combining_operators_inside(self):
        """The engine accepts exactly one mapped comparison inside any()/all();
        combining with || is a parse error. Pinned so an upstream change in
        either direction shows up here instead of in CF lint behaviour."""
        result = parse_expression(
            'any(http.request.headers.names[*] == "x" || http.request.headers.names[*] == "y")'
        )
        assert "error" in result
