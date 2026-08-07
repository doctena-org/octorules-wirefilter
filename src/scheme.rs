//! Wirefilter field scheme builder.
//!
//! Registers Cloudflare fields and functions with their types.
//! A single scheme is built once and cached in a `LazyLock` static:
//!
//! - `SCHEME` — 178 fields (incl. `http.request.uri.path`), 34 registered functions (+ native `any`/`all`).
//!
//! # Panics
//!
//! Field and function registrations use `.unwrap()` throughout. This is
//! intentional: registrations happen once at process startup inside `LazyLock`
//! statics, not at runtime. A registration failure means a programmer error
//! (e.g. duplicate field name, wrong type) and should be caught immediately
//! rather than silently ignored.

use std::sync::LazyLock;

use wirefilter::{
    AlwaysList, ConcatFunction, FunctionArgs, GetType, LhsValue, Scheme, SchemeBuilder,
    SimpleFunctionArgKind, SimpleFunctionDefinition, SimpleFunctionImpl, SimpleFunctionOptParam,
    SimpleFunctionParam, Type,
};

/// Stub function implementation that returns None (field value passthrough).
fn stub_fn<'a>(_args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    None
}

/// Helper: build a `SimpleFunctionDefinition` with given params and return type.
fn simple_fn(params: Vec<SimpleFunctionParam>, return_type: Type) -> SimpleFunctionDefinition {
    SimpleFunctionDefinition {
        params,
        opt_params: vec![],
        return_type,
        implementation: SimpleFunctionImpl::new(stub_fn),
    }
}

/// Helper: build a `SimpleFunctionDefinition` with required and optional params.
fn simple_fn_with_opts(
    params: Vec<SimpleFunctionParam>,
    opt_params: Vec<SimpleFunctionOptParam>,
    return_type: Type,
) -> SimpleFunctionDefinition {
    SimpleFunctionDefinition {
        params,
        opt_params,
        return_type,
        implementation: SimpleFunctionImpl::new(stub_fn),
    }
}

/// An optional literal Bytes parameter (default: empty bytes).
fn opt_literal_bytes() -> SimpleFunctionOptParam {
    SimpleFunctionOptParam {
        arg_kind: SimpleFunctionArgKind::Literal,
        default_value: LhsValue::Bytes(b""[..].into()),
    }
}

/// An optional literal Int parameter (default: 0).
fn opt_literal_int() -> SimpleFunctionOptParam {
    SimpleFunctionOptParam {
        arg_kind: SimpleFunctionArgKind::Literal,
        default_value: LhsValue::Int(0),
    }
}

/// A field-type parameter (variable input from a field or subexpression).
fn field_param(val_type: Type) -> SimpleFunctionParam {
    SimpleFunctionParam {
        arg_kind: SimpleFunctionArgKind::Field,
        val_type,
    }
}

/// A literal parameter (constant value in the expression).
fn literal_param(val_type: Type) -> SimpleFunctionParam {
    SimpleFunctionParam {
        arg_kind: SimpleFunctionArgKind::Literal,
        val_type,
    }
}

/// A parameter that accepts either a field or literal.
fn any_param(val_type: Type) -> SimpleFunctionParam {
    SimpleFunctionParam {
        arg_kind: SimpleFunctionArgKind::Both,
        val_type,
    }
}

/// The wirefilter scheme — 178 fields, 34 registered functions (+ native `any`/`all`).
///
/// `http.request.uri.path` is registered as a regular field. octorules always
/// uses this single scheme for all phases; transform-phase function-call syntax
/// is handled on the Python side.
pub static SCHEME: LazyLock<Scheme> = LazyLock::new(|| {
    let mut b = SchemeBuilder::new();
    register_common_fields(&mut b);
    b.add_field("http.request.uri.path", Type::Bytes).unwrap();
    register_common_functions(&mut b);

    // Register named list support for all value types so expressions
    // like `ip.src in $my_list` parse without error.  AlwaysList accepts
    // any list name — actual list validation is done by the Python linter
    // (CF102 checks existence, CF104 checks type compatibility).
    b.add_list(Type::Int, AlwaysList {}).unwrap();
    b.add_list(Type::Ip, AlwaysList {}).unwrap();
    b.add_list(Type::Bytes, AlwaysList {}).unwrap();

    b.build()
});

/// Scheme for Cloudflare Magic Firewall / Network Firewall (Layer-4) phases.
///
/// Models packet-level fields (`ip.proto`, `tcp.flags`, ports, …) that the
/// HTTP `SCHEME` does not. The FFI selects this scheme for the account-level
/// Magic Transit phases (see `parse_expression`'s `scheme` argument).
/// Source: <https://developers.cloudflare.com/ruleset-engine/rules-language/fields/magic-firewall/>
pub static SCHEME_MAGIC: LazyLock<Scheme> = LazyLock::new(|| {
    let mut b = SchemeBuilder::new();
    register_magic_firewall_fields(&mut b);
    register_common_functions(&mut b);

    // Named-list support so `ip.src in $my_list` parses (existence/type
    // validation is done by the Python linter, as for the HTTP scheme).
    b.add_list(Type::Int, AlwaysList {}).unwrap();
    b.add_list(Type::Ip, AlwaysList {}).unwrap();
    b.add_list(Type::Bytes, AlwaysList {}).unwrap();

    b.build()
});

/// Register common fields (everything except `http.request.uri.path`,
/// which is added separately in the `SCHEME` static).
fn register_common_fields(b: &mut SchemeBuilder) {
    // --- BEGIN GENERATED FIELDS --- //
    b.add_field("cf.api_gateway.auth_id_present", Type::Bool)
        .unwrap();
    b.add_field("cf.api_gateway.fallthrough_detected", Type::Bool)
        .unwrap();
    b.add_field("cf.api_gateway.request_violates_schema", Type::Bool)
        .unwrap();
    b.add_field("cf.bot_management.corporate_proxy", Type::Bool)
        .unwrap();
    b.add_field(
        "cf.bot_management.detection_ids",
        Type::Array(Type::Int.into()),
    )
    .unwrap();
    b.add_field("cf.bot_management.ja3_hash", Type::Bytes)
        .unwrap();
    b.add_field("cf.bot_management.ja4", Type::Bytes).unwrap();
    b.add_field("cf.bot_management.js_detection.passed", Type::Bool)
        .unwrap();
    b.add_field("cf.bot_management.score", Type::Int).unwrap();
    b.add_field("cf.bot_management.static_resource", Type::Bool)
        .unwrap();
    b.add_field("cf.bot_management.verified_bot", Type::Bool)
        .unwrap();
    b.add_field("cf.client.bot", Type::Bool).unwrap();
    b.add_field("cf.edge.client_tcp", Type::Bool).unwrap();
    b.add_field("cf.edge.l4.delivery_rate", Type::Int).unwrap();
    b.add_field("cf.edge.server_ip", Type::Ip).unwrap();
    b.add_field("cf.edge.server_port", Type::Int).unwrap();
    b.add_field("cf.hostname.metadata", Type::Bytes).unwrap();
    b.add_field(
        "cf.llm.prompt.custom_topic_categories",
        Type::Map(Type::Int.into()),
    )
    .unwrap();
    b.add_field("cf.llm.prompt.detected", Type::Bool).unwrap();
    b.add_field("cf.llm.prompt.injection_score", Type::Int)
        .unwrap();
    b.add_field(
        "cf.llm.prompt.pii_categories",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("cf.llm.prompt.pii_detected", Type::Bool)
        .unwrap();
    b.add_field("cf.llm.prompt.token_count", Type::Int).unwrap();
    b.add_field(
        "cf.llm.prompt.unsafe_topic_categories",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("cf.llm.prompt.unsafe_topic_detected", Type::Bool)
        .unwrap();
    b.add_field("cf.random_seed", Type::Bytes).unwrap();
    b.add_field("cf.ray_id", Type::Bytes).unwrap();
    b.add_field("cf.response.1xxx_code", Type::Int).unwrap();
    b.add_field("cf.response.error_type", Type::Bytes).unwrap();
    b.add_field("cf.threat_score", Type::Int).unwrap();
    b.add_field("cf.timings.client_quic_rtt_msec", Type::Int)
        .unwrap();
    b.add_field("cf.timings.client_tcp_rtt_msec", Type::Int)
        .unwrap();
    b.add_field("cf.timings.edge_msec", Type::Int).unwrap();
    b.add_field("cf.timings.origin_ttfb_msec", Type::Int)
        .unwrap();
    b.add_field("cf.timings.worker_msec", Type::Int).unwrap();
    b.add_field("cf.tls_cipher", Type::Bytes).unwrap();
    b.add_field("cf.tls_ciphers_sha1", Type::Bytes).unwrap();
    b.add_field("cf.tls_client_auth.cert_chain_rfc9440", Type::Bytes)
        .unwrap();
    b.add_field(
        "cf.tls_client_auth.cert_chain_rfc9440_too_large",
        Type::Bool,
    )
    .unwrap();
    b.add_field("cf.tls_client_auth.cert_fingerprint_sha1", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_fingerprint_sha256", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_issuer_dn", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_issuer_dn_legacy", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_issuer_dn_rfc2253", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_issuer_serial", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_issuer_ski", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_not_after", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_not_before", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_presented", Type::Bool)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_revoked", Type::Bool)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_rfc9440", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_rfc9440_too_large", Type::Bool)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_serial", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_ski", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_subject_dn", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_subject_dn_legacy", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_subject_dn_rfc2253", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_auth.cert_verified", Type::Bool)
        .unwrap();
    b.add_field("cf.tls_client_extensions_sha1", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_extensions_sha1_le", Type::Bytes)
        .unwrap();
    b.add_field("cf.tls_client_hello_length", Type::Int)
        .unwrap();
    b.add_field("cf.tls_client_random", Type::Bytes).unwrap();
    b.add_field("cf.tls_version", Type::Bytes).unwrap();
    b.add_field("cf.verified_bot_category", Type::Bytes)
        .unwrap();
    b.add_field("cf.waf.auth_detected", Type::Bool).unwrap();
    b.add_field("cf.waf.content_scan.has_failed", Type::Bool)
        .unwrap();
    b.add_field("cf.waf.content_scan.has_malicious_obj", Type::Bool)
        .unwrap();
    b.add_field("cf.waf.content_scan.has_obj", Type::Bool)
        .unwrap();
    b.add_field("cf.waf.content_scan.num_malicious_obj", Type::Int)
        .unwrap();
    b.add_field("cf.waf.content_scan.num_obj", Type::Int)
        .unwrap();
    b.add_field(
        "cf.waf.content_scan.obj_results",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "cf.waf.content_scan.obj_sizes",
        Type::Array(Type::Int.into()),
    )
    .unwrap();
    b.add_field(
        "cf.waf.content_scan.obj_types",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("cf.waf.credential_check.password_leaked", Type::Bool)
        .unwrap();
    b.add_field(
        "cf.waf.credential_check.username_and_password_leaked",
        Type::Bool,
    )
    .unwrap();
    b.add_field("cf.waf.credential_check.username_leaked", Type::Bool)
        .unwrap();
    b.add_field(
        "cf.waf.credential_check.username_password_similar",
        Type::Bool,
    )
    .unwrap();
    b.add_field("cf.waf.score", Type::Int).unwrap();
    b.add_field("cf.waf.score.class", Type::Bytes).unwrap();
    b.add_field("cf.waf.score.rce", Type::Int).unwrap();
    b.add_field("cf.waf.score.sqli", Type::Int).unwrap();
    b.add_field("cf.waf.score.xss", Type::Int).unwrap();
    b.add_field("cf.worker.upstream_zone", Type::Bytes).unwrap();
    b.add_field("http.cookie", Type::Bytes).unwrap();
    b.add_field("http.host", Type::Bytes).unwrap();
    b.add_field("http.referer", Type::Bytes).unwrap();
    b.add_field(
        "http.request.accepted_languages",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.form",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.form.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.form.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.request.body.mime", Type::Bytes).unwrap();
    b.add_field(
        "http.request.body.multipart",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.content_dispositions",
        Type::Array(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.content_transfer_encodings",
        Type::Array(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.content_types",
        Type::Array(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.filenames",
        Type::Array(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.names",
        Type::Array(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.body.multipart.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.request.body.raw", Type::Bytes).unwrap();
    b.add_field("http.request.body.size", Type::Int).unwrap();
    b.add_field("http.request.body.truncated", Type::Bool)
        .unwrap();
    b.add_field(
        "http.request.cookies",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field("http.request.full_uri", Type::Bytes).unwrap();
    b.add_field(
        "http.request.headers",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.headers.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.request.headers.truncated", Type::Bool)
        .unwrap();
    b.add_field(
        "http.request.headers.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.aud",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.aud.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.aud.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iat.sec",
        Type::Map(Type::Array(Type::Int.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iat.sec.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iat.sec.values",
        Type::Array(Type::Int.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iss",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iss.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.iss.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.jti",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.jti.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.jti.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.nbf.sec",
        Type::Map(Type::Array(Type::Int.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.nbf.sec.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.nbf.sec.values",
        Type::Array(Type::Int.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.sub",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.sub.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.jwt.claims.sub.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.request.method", Type::Bytes).unwrap();
    b.add_field("http.request.timestamp.msec", Type::Int)
        .unwrap();
    b.add_field("http.request.timestamp.sec", Type::Int)
        .unwrap();
    b.add_field("http.request.uri", Type::Bytes).unwrap();
    b.add_field(
        "http.request.uri.args",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.request.uri.args.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.request.uri.args.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.request.uri.path.extension", Type::Bytes)
        .unwrap();
    b.add_field("http.request.uri.query", Type::Bytes).unwrap();
    b.add_field("http.request.version", Type::Bytes).unwrap();
    b.add_field("http.response.code", Type::Int).unwrap();
    b.add_field("http.response.content_type.media_type", Type::Bytes)
        .unwrap();
    b.add_field(
        "http.response.headers",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "http.response.headers.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "http.response.headers.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("http.user_agent", Type::Bytes).unwrap();
    b.add_field("http.x_forwarded_for", Type::Bytes).unwrap();
    b.add_field("ip.src", Type::Ip).unwrap();
    b.add_field("ip.src.asnum", Type::Int).unwrap();
    b.add_field("ip.src.city", Type::Bytes).unwrap();
    b.add_field("ip.src.continent", Type::Bytes).unwrap();
    b.add_field("ip.src.country", Type::Bytes).unwrap();
    b.add_field("ip.src.is_in_european_union", Type::Bool)
        .unwrap();
    b.add_field("ip.src.lat", Type::Bytes).unwrap();
    b.add_field("ip.src.lon", Type::Bytes).unwrap();
    b.add_field("ip.src.metro_code", Type::Bytes).unwrap();
    b.add_field("ip.src.postal_code", Type::Bytes).unwrap();
    b.add_field("ip.src.region", Type::Bytes).unwrap();
    b.add_field("ip.src.region_code", Type::Bytes).unwrap();
    b.add_field("ip.src.subdivision_1_iso_code", Type::Bytes)
        .unwrap();
    b.add_field("ip.src.subdivision_2_iso_code", Type::Bytes)
        .unwrap();
    b.add_field("ip.src.timezone.name", Type::Bytes).unwrap();
    b.add_field("raw.http.request.full_uri", Type::Bytes)
        .unwrap();
    b.add_field("raw.http.request.uri", Type::Bytes).unwrap();
    b.add_field(
        "raw.http.request.uri.args",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "raw.http.request.uri.args.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "raw.http.request.uri.args.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("raw.http.request.uri.path", Type::Bytes)
        .unwrap();
    b.add_field("raw.http.request.uri.path.extension", Type::Bytes)
        .unwrap();
    b.add_field("raw.http.request.uri.query", Type::Bytes)
        .unwrap();
    b.add_field(
        "raw.http.response.headers",
        Type::Map(Type::Array(Type::Bytes.into()).into()),
    )
    .unwrap();
    b.add_field(
        "raw.http.response.headers.names",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field(
        "raw.http.response.headers.values",
        Type::Array(Type::Bytes.into()),
    )
    .unwrap();
    b.add_field("ssl", Type::Bool).unwrap();
    // --- END GENERATED FIELDS --- //

    // Deprecated fields — still registered so the parser accepts them and
    // the linter can flag them with G010.
    b.add_field("ip.geoip.asnum", Type::Int).unwrap();
    b.add_field("ip.geoip.continent", Type::Bytes).unwrap();
    b.add_field("ip.geoip.country", Type::Bytes).unwrap();
    b.add_field("ip.geoip.subdivision_1_iso_code", Type::Bytes)
        .unwrap();
    b.add_field("ip.geoip.subdivision_2_iso_code", Type::Bytes)
        .unwrap();
    b.add_field("ip.geoip.is_in_european_union", Type::Bool)
        .unwrap();

    // Account-level zone fields (not in CF docs YAML)
    b.add_field("cf.zone.name", Type::Bytes).unwrap();
    b.add_field("cf.zone.plan", Type::Bytes).unwrap();
}

/// Register the 33 Cloudflare Network Firewall (Magic Transit / Layer-4)
/// fields. Used only by `SCHEME_MAGIC`.
///
/// Source: <https://developers.cloudflare.com/ruleset-engine/rules-language/fields/magic-firewall/>
fn register_magic_firewall_fields(b: &mut SchemeBuilder) {
    // IP addresses
    b.add_field("ip.src", Type::Ip).unwrap();
    b.add_field("ip.dst", Type::Ip).unwrap();
    // Raw packet bytes (for use with bit_slice)
    b.add_field("ip", Type::Bytes).unwrap();
    b.add_field("tcp", Type::Bytes).unwrap();
    b.add_field("udp", Type::Bytes).unwrap();
    b.add_field("icmp", Type::Bytes).unwrap();
    // String-valued (wirefilter Bytes)
    b.add_field("ip.proto", Type::Bytes).unwrap();
    b.add_field("ip.src.country", Type::Bytes).unwrap();
    b.add_field("ip.dst.country", Type::Bytes).unwrap();
    b.add_field("cf.colo.name", Type::Bytes).unwrap();
    b.add_field("cf.colo.region", Type::Bytes).unwrap();
    // Numeric
    b.add_field("ip.len", Type::Int).unwrap();
    b.add_field("ip.hdr_len", Type::Int).unwrap();
    b.add_field("ip.ttl", Type::Int).unwrap();
    b.add_field("ip.opt.type", Type::Int).unwrap();
    b.add_field("ip.src.asnum", Type::Int).unwrap();
    b.add_field("ip.dst.asnum", Type::Int).unwrap();
    b.add_field("icmp.type", Type::Int).unwrap();
    b.add_field("icmp.code", Type::Int).unwrap();
    b.add_field("tcp.flags", Type::Int).unwrap();
    b.add_field("tcp.srcport", Type::Int).unwrap();
    b.add_field("tcp.dstport", Type::Int).unwrap();
    b.add_field("udp.srcport", Type::Int).unwrap();
    b.add_field("udp.dstport", Type::Int).unwrap();
    // Boolean
    b.add_field("sip", Type::Bool).unwrap();
    b.add_field("tcp.flags.ack", Type::Bool).unwrap();
    b.add_field("tcp.flags.cwr", Type::Bool).unwrap();
    b.add_field("tcp.flags.ecn", Type::Bool).unwrap();
    b.add_field("tcp.flags.fin", Type::Bool).unwrap();
    b.add_field("tcp.flags.push", Type::Bool).unwrap();
    b.add_field("tcp.flags.reset", Type::Bool).unwrap();
    b.add_field("tcp.flags.syn", Type::Bool).unwrap();
    b.add_field("tcp.flags.urg", Type::Bool).unwrap();
}

/// Register the 34 functions shared by both schemes (`any`/`all` parse
/// natively as quantifiers and need no registration).
///
/// Source: <https://developers.cloudflare.com/ruleset-engine/rules-language/functions/>
fn register_common_functions(b: &mut SchemeBuilder) {
    // Built-in wirefilter functions.  `any` and `all` are no longer
    // registered: the engine parses them natively as logical quantifiers
    // (upstream af1a1e96).  They stay in COMMON_FUNCTION_NAMES because they
    // remain callable in expressions.
    b.add_function("concat", ConcatFunction::new()).unwrap();

    // String transformation functions — Bytes → Bytes
    for name in ["lower", "upper", "url_decode", "uuidv4"] {
        b.add_function(name, simple_fn(vec![field_param(Type::Bytes)], Type::Bytes))
            .unwrap();
    }

    // String query functions — (Bytes, Bytes) → Bool
    for name in ["starts_with", "ends_with", "contains"] {
        b.add_function(
            name,
            simple_fn(
                vec![field_param(Type::Bytes), any_param(Type::Bytes)],
                Type::Bool,
            ),
        )
        .unwrap();
    }

    // len: Bytes → Int
    b.add_function("len", simple_fn(vec![field_param(Type::Bytes)], Type::Int))
        .unwrap();

    // substring: (Bytes, Int, Int) → Bytes
    b.add_function(
        "substring",
        simple_fn(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Int),
                literal_param(Type::Int),
            ],
            Type::Bytes,
        ),
    )
    .unwrap();

    // regex_replace: (Bytes, Bytes, Bytes) → Bytes
    b.add_function(
        "regex_replace",
        simple_fn(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Bytes),
                literal_param(Type::Bytes),
            ],
            Type::Bytes,
        ),
    )
    .unwrap();

    // remove_bytes: (Bytes, Bytes) → Bytes
    b.add_function(
        "remove_bytes",
        simple_fn(
            vec![field_param(Type::Bytes), literal_param(Type::Bytes)],
            Type::Bytes,
        ),
    )
    .unwrap();

    // to_string: Int → Bytes
    b.add_function(
        "to_string",
        simple_fn(vec![field_param(Type::Int)], Type::Bytes),
    )
    .unwrap();

    // lookup_json_string: (Bytes, Bytes) → Bytes
    b.add_function(
        "lookup_json_string",
        simple_fn(
            vec![field_param(Type::Bytes), literal_param(Type::Bytes)],
            Type::Bytes,
        ),
    )
    .unwrap();

    // lookup_json_integer: (Bytes, Bytes) → Int
    b.add_function(
        "lookup_json_integer",
        simple_fn(
            vec![field_param(Type::Bytes), literal_param(Type::Bytes)],
            Type::Int,
        ),
    )
    .unwrap();

    // sha256, sha512: Bytes → Bytes
    for name in ["sha256", "sha512"] {
        b.add_function(name, simple_fn(vec![field_param(Type::Bytes)], Type::Bytes))
            .unwrap();
    }

    // hmac: (Bytes, Bytes, Bytes) → Bytes
    b.add_function(
        "hmac",
        simple_fn(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Bytes),
                literal_param(Type::Bytes),
            ],
            Type::Bytes,
        ),
    )
    .unwrap();

    // is_timed_hmac_valid_v0: (Bytes, Bytes, Int, Bytes?, Int?) → Bool
    b.add_function(
        "is_timed_hmac_valid_v0",
        simple_fn_with_opts(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Bytes),
                literal_param(Type::Int),
            ],
            vec![opt_literal_bytes(), opt_literal_int()],
            Type::Bool,
        ),
    )
    .unwrap();

    // ip_in_range: (Ip, Bytes) → Bool
    b.add_function(
        "ip_in_range",
        simple_fn(
            vec![field_param(Type::Ip), literal_param(Type::Bytes)],
            Type::Bool,
        ),
    )
    .unwrap();

    // wildcard: (Bytes, Bytes) → Bool
    b.add_function(
        "wildcard",
        simple_fn(
            vec![field_param(Type::Bytes), literal_param(Type::Bytes)],
            Type::Bool,
        ),
    )
    .unwrap();

    // encode_base64: (Bytes, Bytes?) → Bytes
    b.add_function(
        "encode_base64",
        simple_fn_with_opts(
            vec![field_param(Type::Bytes)],
            vec![opt_literal_bytes()],
            Type::Bytes,
        ),
    )
    .unwrap();

    // decode_base64: Bytes → Bytes
    b.add_function(
        "decode_base64",
        simple_fn(vec![field_param(Type::Bytes)], Type::Bytes),
    )
    .unwrap();

    // cidr: (Ip, Int, Int) → Ip
    b.add_function(
        "cidr",
        simple_fn(
            vec![
                field_param(Type::Ip),
                literal_param(Type::Int),
                literal_param(Type::Int),
            ],
            Type::Ip,
        ),
    )
    .unwrap();

    // cidr6: (Ip, Int) → Ip
    b.add_function(
        "cidr6",
        simple_fn(
            vec![field_param(Type::Ip), literal_param(Type::Int)],
            Type::Ip,
        ),
    )
    .unwrap();

    // join: (Array<Bytes>, Bytes) → Bytes
    b.add_function(
        "join",
        simple_fn(
            vec![
                field_param(Type::Array(Type::Bytes.into())),
                literal_param(Type::Bytes),
            ],
            Type::Bytes,
        ),
    )
    .unwrap();

    // split: (Bytes, Bytes, Int) → Array<Bytes>
    b.add_function(
        "split",
        simple_fn(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Bytes),
                literal_param(Type::Int),
            ],
            Type::Array(Type::Bytes.into()),
        ),
    )
    .unwrap();

    // has_key: (Map<Array<Bytes>>, Bytes) → Bool
    b.add_function(
        "has_key",
        simple_fn(
            vec![
                field_param(Type::Map(Type::Array(Type::Bytes.into()).into())),
                literal_param(Type::Bytes),
            ],
            Type::Bool,
        ),
    )
    .unwrap();

    // has_value: (Array<Bytes>, Bytes) → Bool
    b.add_function(
        "has_value",
        simple_fn(
            vec![
                field_param(Type::Array(Type::Bytes.into())),
                literal_param(Type::Bytes),
            ],
            Type::Bool,
        ),
    )
    .unwrap();

    // remove_query_args: (Bytes, Bytes...) → Bytes
    // Variadic: 1 required + up to 7 optional Bytes params covers practical usage.
    b.add_function(
        "remove_query_args",
        simple_fn_with_opts(
            vec![field_param(Type::Bytes), literal_param(Type::Bytes)],
            vec![
                opt_literal_bytes(),
                opt_literal_bytes(),
                opt_literal_bytes(),
                opt_literal_bytes(),
                opt_literal_bytes(),
                opt_literal_bytes(),
                opt_literal_bytes(),
            ],
            Type::Bytes,
        ),
    )
    .unwrap();

    // bit_slice: (Bytes, Int, Int) → Int
    b.add_function(
        "bit_slice",
        simple_fn(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Int),
                literal_param(Type::Int),
            ],
            Type::Int,
        ),
    )
    .unwrap();

    // wildcard_replace: (Bytes, Bytes, Bytes, Bytes?) → Bytes
    b.add_function(
        "wildcard_replace",
        simple_fn_with_opts(
            vec![
                field_param(Type::Bytes),
                literal_param(Type::Bytes),
                literal_param(Type::Bytes),
            ],
            vec![opt_literal_bytes()],
            Type::Bytes,
        ),
    )
    .unwrap();

    // is_jwt_valid / is_jwt_present: (Bytes) → Bool
    //
    // Cloudflare API Shield JWT validation. The argument is a UUID string
    // *literal* identifying a token configuration — NOT a header value /
    // field. See https://developers.cloudflare.com/api-shield/security/
    // jwt-validation/configure/. Use `literal_param`, not `field_param`.
    for name in ["is_jwt_valid", "is_jwt_present"] {
        b.add_function(
            name,
            simple_fn(vec![literal_param(Type::Bytes)], Type::Bool),
        )
        .unwrap();
    }
}

/// Map a wirefilter [`Type`] to the Python `FieldType` enum name.
fn type_to_python(t: &Type) -> &'static str {
    match t {
        Type::Bytes => "STRING",
        Type::Int => "INT",
        Type::Bool => "BOOL",
        Type::Ip => "IP",
        Type::Array(inner) => {
            let inner_ty: Type = (*inner).into();
            match inner_ty {
                Type::Bytes => "ARRAY_STRING",
                Type::Int => "ARRAY_INT",
                Type::Array(inner2) => {
                    let inner2_ty: Type = inner2.into();
                    match inner2_ty {
                        Type::Bytes => "ARRAY_ARRAY_STRING",
                        other => panic!("unmapped Array(Array({other:?})) in type_to_python"),
                    }
                }
                other => panic!("unmapped Array({other:?}) in type_to_python"),
            }
        }
        Type::Map(inner) => {
            let inner_ty: Type = (*inner).into();
            match inner_ty {
                // Wirefilter's Map keys are always strings; the `Map<X>`
                // shorthand maps to `MAP_STRING_<X>` on the Python side.
                Type::Bytes => "MAP_STRING_STRING",
                Type::Int => "MAP_STRING_INT",
                Type::Array(inner2) => {
                    let inner2_ty: Type = inner2.into();
                    match inner2_ty {
                        Type::Bytes => "MAP_ARRAY_STRING",
                        Type::Int => "MAP_ARRAY_INT",
                        other => panic!("unmapped Map(Array({other:?})) in type_to_python"),
                    }
                }
                other => panic!("unmapped Map({other:?}) in type_to_python"),
            }
        }
    }
}

/// Build `(name, python_type)` field defs by iterating a scheme, skipping any
/// excluded names, sorted by name for deterministic output.
///
/// Iterating the scheme means there is no parallel name list to keep in sync —
/// the `register_*_fields` functions are the single source of truth.
fn scheme_field_defs(
    scheme: &'static Scheme,
    excluded: &[&str],
) -> Vec<(&'static str, &'static str)> {
    let mut defs: Vec<(&'static str, &'static str)> = scheme
        .fields()
        .filter(|f| !excluded.contains(&f.name()))
        .map(|f| (f.name(), type_to_python(&f.get_type())))
        .collect();
    defs.sort_unstable();
    defs
}

/// Common (HTTP) field definitions as `(name, python_type)` tuples.
///
/// Derived by iterating `SCHEME` minus [`COMMON_FIELD_EXCLUSIONS`].
/// `register_common_fields` is the single source of truth for HTTP field names
/// and types — there is no parallel inclusion list.
pub fn common_field_defs() -> &'static [(&'static str, &'static str)] {
    static FIELD_DEFS: LazyLock<Vec<(&'static str, &'static str)>> =
        LazyLock::new(|| scheme_field_defs(&SCHEME, COMMON_FIELD_EXCLUSIONS));
    &FIELD_DEFS
}

/// Magic Firewall (Layer-4) field definitions as `(name, python_type)` tuples.
///
/// Derived by iterating `SCHEME_MAGIC` directly. `register_magic_firewall_fields`
/// is the single source of truth for L4 field names and types.
pub fn magic_field_defs() -> &'static [(&'static str, &'static str)] {
    static FIELD_DEFS: LazyLock<Vec<(&'static str, &'static str)>> =
        LazyLock::new(|| scheme_field_defs(&SCHEME_MAGIC, &[]));
    &FIELD_DEFS
}

/// Function names registered in the scheme.
pub fn common_function_names() -> &'static [&'static str] {
    COMMON_FUNCTION_NAMES
}

/// HTTP-scheme fields intentionally NOT exposed via `get_schema_info()`:
/// `http.request.uri.path` (dual field/function, registered separately) plus
/// the geoip/zone alias fields, which the Python field registry supplies with
/// its own metadata. `common_field_defs()` iterates `SCHEME` minus this set, so
/// `register_common_fields` stays the single source of truth (no parallel
/// inclusion list to keep in sync).
const COMMON_FIELD_EXCLUSIONS: &[&str] = &[
    "http.request.uri.path",
    "cf.zone.name",
    "cf.zone.plan",
    "ip.geoip.asnum",
    "ip.geoip.continent",
    "ip.geoip.country",
    "ip.geoip.subdivision_1_iso_code",
    "ip.geoip.subdivision_2_iso_code",
    "ip.geoip.is_in_european_union",
];

/// Function names registered in the scheme.
const COMMON_FUNCTION_NAMES: &[&str] = &[
    "any",
    "all",
    "concat",
    "lower",
    "upper",
    "url_decode",
    "uuidv4",
    "starts_with",
    "ends_with",
    "contains",
    "len",
    "substring",
    "regex_replace",
    "remove_bytes",
    "to_string",
    "lookup_json_string",
    "lookup_json_integer",
    "sha256",
    "sha512",
    "hmac",
    "is_timed_hmac_valid_v0",
    "ip_in_range",
    "wildcard",
    "encode_base64",
    "decode_base64",
    "cidr",
    "cidr6",
    "join",
    "split",
    "has_key",
    "has_value",
    "remove_query_args",
    "bit_slice",
    "wildcard_replace",
    "is_jwt_valid",
    "is_jwt_present",
];

#[cfg(test)]
mod tests {
    use super::*;

    // ── SCHEME tests ─────────────────────────────────────────

    #[test]
    fn scheme_has_all_fields() {
        // 169 common + http.request.uri.path + cf.zone.{name,plan} +
        // 6 ip.geoip.* aliases = 178
        assert_eq!(SCHEME.field_count(), 178);
    }

    #[test]
    fn common_field_defs_count() {
        // get_schema_info() exposes SCHEME minus the 9 excluded dual/alias
        // fields (supplied by the Python field registry instead):
        // 178 - 9 = 169.
        assert_eq!(common_field_defs().len(), 169);
        assert_eq!(
            common_field_defs().len(),
            SCHEME.field_count() - COMMON_FIELD_EXCLUSIONS.len()
        );
    }

    #[test]
    fn common_function_names_array_length() {
        // COMMON_FUNCTION_NAMES lists all functions exposed via get_schema_info().
        assert_eq!(COMMON_FUNCTION_NAMES.len(), 36);
    }

    #[test]
    fn scheme_has_all_functions() {
        // 1 built-in (concat) + 33 custom = 34.  `any`/`all` left the
        // registry when upstream made them native quantifiers; they are
        // still callable (see quantifiers_parse_without_registration) and
        // still listed in COMMON_FUNCTION_NAMES.
        assert_eq!(SCHEME.function_count(), 34);
    }

    // ── 2026 CF additions — verify presence ──

    #[test]
    fn scheme_has_rfc9440_mtls_fields() {
        // RFC 9440 Client-Cert HTTP header — added to CF on 2026-03-25/30.
        for name in [
            "cf.tls_client_auth.cert_chain_rfc9440",
            "cf.tls_client_auth.cert_chain_rfc9440_too_large",
            "cf.tls_client_auth.cert_rfc9440",
            "cf.tls_client_auth.cert_rfc9440_too_large",
        ] {
            assert!(
                SCHEME.get_field(name).is_ok(),
                "RFC 9440 field {name:?} not registered"
            );
        }
    }

    #[test]
    fn scheme_has_2026_l4_and_timing_fields() {
        for name in [
            "cf.edge.l4.delivery_rate",
            "cf.timings.client_quic_rtt_msec",
            "cf.timings.worker_msec",
        ] {
            assert!(
                SCHEME.get_field(name).is_ok(),
                "2026 CF field {name:?} not registered"
            );
        }
    }

    // ── SCHEME_MAGIC (Magic Transit / Layer-4) tests ──────────

    #[test]
    fn magic_scheme_has_l4_fields() {
        for name in [
            "ip.proto",
            "tcp.flags",
            "tcp.flags.syn",
            "tcp.dstport",
            "udp.dstport",
            "icmp.type",
        ] {
            assert!(
                SCHEME_MAGIC.get_field(name).is_ok(),
                "Magic Firewall field {name:?} not registered in SCHEME_MAGIC"
            );
        }
    }

    #[test]
    fn magic_scheme_field_count() {
        assert_eq!(SCHEME_MAGIC.field_count(), 33);
    }

    #[test]
    fn magic_field_defs_derived_from_scheme() {
        // magic_field_defs() iterates SCHEME_MAGIC directly, so it must match
        // the scheme's field count and report correct Python types.
        let defs = magic_field_defs();
        assert_eq!(defs.len(), 33);
        let by_name: std::collections::HashMap<_, _> = defs.iter().copied().collect();
        assert_eq!(by_name.get("ip.proto"), Some(&"STRING"));
        assert_eq!(by_name.get("tcp.dstport"), Some(&"INT"));
        assert_eq!(by_name.get("tcp.flags.syn"), Some(&"BOOL"));
        assert_eq!(by_name.get("ip.src"), Some(&"IP"));
    }

    #[test]
    fn magic_scheme_parses_l4_expression() {
        assert!(
            SCHEME_MAGIC
                .parse(r#"ip.proto eq "tcp" && tcp.dstport in {22 3389}"#)
                .is_ok()
        );
        assert!(
            SCHEME_MAGIC
                .parse("tcp.flags.syn && not tcp.flags.ack")
                .is_ok()
        );
    }

    #[test]
    fn magic_scheme_rejects_http_fields() {
        // The L4 scheme must not accept HTTP fields — per-phase precision.
        assert!(SCHEME_MAGIC.parse(r#"http.host eq "example.com""#).is_err());
    }

    #[test]
    fn http_scheme_rejects_l4_fields() {
        // The HTTP scheme is unchanged — L4 fields remain unknown there.
        assert!(SCHEME.parse(r#"ip.proto eq "tcp""#).is_err());
        assert!(SCHEME.parse("tcp.flags.syn").is_err());
    }

    #[test]
    fn scheme_has_2026_llm_fields() {
        for name in [
            "cf.llm.prompt.custom_topic_categories",
            "cf.llm.prompt.token_count",
        ] {
            assert!(
                SCHEME.get_field(name).is_ok(),
                "2026 CF LLM field {name:?} not registered"
            );
        }
    }

    #[test]
    fn jwt_validation_functions_registered_with_literal_arg() {
        // Cloudflare API Shield JWT validation. Argument is a UUID string
        // *literal*, not a field — see scheme.rs comment + CF docs.
        for name in ["is_jwt_valid", "is_jwt_present"] {
            SCHEME
                .get_function(name)
                .unwrap_or_else(|_| panic!("function {name:?} not registered"));
        }
        // Parse with a literal UUID argument — the documented usage.
        let result = SCHEME.parse(r#"is_jwt_valid("51231d16-01f1-48e3-93f8-91c99e81288e")"#);
        assert!(
            result.is_ok(),
            "literal-arg parse failed: {:?}",
            result.err()
        );
    }

    // ── Speculative-API removals — regression guard ──
    //
    // These four fields were registered earlier by pattern-matching CF
    // surface ("if request side has it, response side must too"; "if
    // other JWT claims have .sec siblings, exp must too") without
    // verifying CF accepts them. CF doesn't. Adding any of these back
    // must be backed by current CF docs evidence.

    #[test]
    fn removed_speculative_fields_stay_removed() {
        for name in [
            "http.request.jwt.claims.exp.sec",
            "http.request.jwt.claims.exp.sec.names",
            "http.request.jwt.claims.exp.sec.values",
            "http.response.headers.truncated",
        ] {
            assert!(
                SCHEME.get_field(name).is_err(),
                "{name:?} is intentionally absent (speculative addition not \
                 backed by CF docs); do not re-add without grep-verifying \
                 against the canonical CF fields YAML"
            );
        }
    }

    #[test]
    fn scheme_uri_path_is_field() {
        let field = SCHEME.get_field("http.request.uri.path").unwrap();
        assert_eq!(field.name(), "http.request.uri.path");
    }

    #[test]
    fn scheme_can_parse_uri_path_as_field() {
        let result = SCHEME.parse(r#"http.request.uri.path eq "/test""#);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }

    // ── Field and function lookup tests ──────────────────────

    #[test]
    fn can_look_up_http_host() {
        let field = SCHEME.get_field("http.host").unwrap();
        assert_eq!(field.name(), "http.host");
    }

    #[test]
    fn can_look_up_ip_src() {
        let field = SCHEME.get_field("ip.src").unwrap();
        assert_eq!(field.name(), "ip.src");
    }

    #[test]
    fn can_look_up_function_lower() {
        SCHEME.get_function("lower").unwrap();
    }

    #[test]
    fn can_parse_simple_expression() {
        let result = SCHEME.parse(r#"http.host eq "example.com""#);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }

    // ── Sync checks: COMMON_*_NAMES match registered scheme ──

    #[test]
    fn common_field_exclusions_are_real_and_excluded() {
        let exposed: std::collections::HashSet<_> =
            common_field_defs().iter().map(|(n, _)| *n).collect();
        for name in COMMON_FIELD_EXCLUSIONS {
            assert!(
                SCHEME.get_field(name).is_ok(),
                "exclusion {name:?} is not a real SCHEME field"
            );
            assert!(
                !exposed.contains(name),
                "exclusion {name:?} must not be exposed by common_field_defs()"
            );
        }
    }

    #[test]
    fn all_common_functions_exist_in_scheme() {
        // `any` and `all` are parsed natively as quantifiers (upstream
        // af1a1e96) rather than registered; callability is asserted by
        // quantifiers_parse_without_registration below.
        for name in COMMON_FUNCTION_NAMES {
            if matches!(*name, "any" | "all") {
                continue;
            }
            assert!(
                SCHEME.get_function(name).is_ok(),
                "COMMON_FUNCTION_NAMES contains {name:?} but it's not registered in SCHEME"
            );
        }
    }

    #[test]
    fn quantifiers_parse_without_registration() {
        for expr in [
            r#"any(http.request.headers.names[*] == "x")"#,
            r#"all(http.request.headers.names[*] != "y")"#,
        ] {
            assert!(
                SCHEME.parse(expr).is_ok(),
                "quantifier expression failed to parse: {expr}"
            );
        }
    }

    // ── type_to_python covers all registered fields ──

    #[test]
    fn common_field_defs_have_types() {
        for &(name, py_type) in common_field_defs() {
            assert!(
                !py_type.is_empty(),
                "type_to_python returned empty for field {name:?}"
            );
        }
    }

    // ── Named list support ──

    #[test]
    fn scheme_parses_ip_named_list() {
        let ast = SCHEME
            .parse("ip.src in $blocked_ips")
            .expect("should parse ip named list");
        let _ = ast; // Parsing succeeded — type check passed
    }

    #[test]
    fn scheme_parses_string_named_list() {
        let ast = SCHEME
            .parse("http.host in $allowed_hosts")
            .expect("should parse string named list");
        let _ = ast;
    }

    #[test]
    fn scheme_parses_int_named_list() {
        let ast = SCHEME
            .parse("cf.bot_management.score in $suspicious_scores")
            .expect("should parse int named list");
        let _ = ast;
    }

    #[test]
    fn scheme_parses_negated_named_list() {
        let ast = SCHEME
            .parse("not ip.src in $allowlist")
            .expect("should parse negated named list");
        let _ = ast;
    }

    #[test]
    fn scheme_parses_named_list_in_compound_expr() {
        let ast = SCHEME
            .parse("ip.src in $blocked and http.host eq \"example.com\"")
            .expect("should parse compound expr with named list");
        let _ = ast;
    }

    // ── Wildcard star limit (ParserSettings) ──

    #[test]
    fn wildcard_ten_stars_accepted() {
        use crate::parser_settings;
        let pattern = format!("http.host wildcard \"{}\"", "*.".repeat(10) + "com");
        let parser = SCHEME.parser_with_settings(parser_settings());
        assert!(parser.parse(&pattern).is_ok());
    }

    #[test]
    fn wildcard_eleven_stars_rejected() {
        use crate::parser_settings;
        let pattern = format!("http.host wildcard \"{}\"", "*.".repeat(11) + "com");
        let parser = SCHEME.parser_with_settings(parser_settings());
        assert!(parser.parse(&pattern).is_err());
    }
}
