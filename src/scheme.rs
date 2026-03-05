//! Wirefilter field scheme builder.
//!
//! Registers Cloudflare fields and functions with their types.
//! Two schemes are built once and cached in `LazyLock` statics:
//!
//! - `DEFAULT_SCHEME` — 170 fields (incl. `http.request.uri.path`), 34 functions.
//!   Used for all phases except transform phases.
//!
//! - `TRANSFORM_SCHEME` — 169 fields, 35 functions. `http.request.uri.path` is
//!   registered as a function (not a field) because in transform phases it is
//!   callable.

use std::sync::LazyLock;

use wirefilter::{
    AllFunction, AnyFunction, ConcatFunction, FunctionArgs, GetType, LhsValue, Scheme,
    SchemeBuilder, SimpleFunctionArgKind, SimpleFunctionDefinition, SimpleFunctionImpl,
    SimpleFunctionOptParam, SimpleFunctionParam, Type,
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

/// Transform phases where `http.request.uri.path` is a callable function
/// rather than a plain field.  Must match `_TRANSFORM_PHASES` in
/// `src/octorules/linter/schemas/functions.py`.
pub const TRANSFORM_PHASES: &[&str] = &[
    "url_rewrite_rules",
    "request_header_rules",
    "response_header_rules",
];

/// Default scheme — used for all non-transform phases.
pub static DEFAULT_SCHEME: LazyLock<Scheme> = LazyLock::new(|| {
    let mut b = SchemeBuilder::new();
    register_common_fields(&mut b);
    // In the default scheme, http.request.uri.path is a regular field.
    b.add_field("http.request.uri.path", Type::Bytes).unwrap();
    register_common_functions(&mut b);
    b.build()
});

/// Transform scheme — used for `url_rewrite_rules`, `request_header_rules`,
/// and `response_header_rules`.  `http.request.uri.path` is registered as a
/// function (Bytes → Bytes) instead of a field.
pub static TRANSFORM_SCHEME: LazyLock<Scheme> = LazyLock::new(|| {
    let mut b = SchemeBuilder::new();
    register_common_fields(&mut b);
    register_common_functions(&mut b);
    // In transform phases, http.request.uri.path is a callable function.
    b.add_function(
        "http.request.uri.path",
        simple_fn(vec![field_param(Type::Bytes)], Type::Bytes),
    )
    .unwrap();
    b.build()
});

/// Return the appropriate scheme for the given phase.
///
/// - `None` or unknown phase → `DEFAULT_SCHEME`
/// - One of the 3 transform phases → `TRANSFORM_SCHEME`
pub fn get_scheme(phase: Option<&str>) -> &'static Scheme {
    match phase {
        Some(p) if TRANSFORM_PHASES.contains(&p) => &TRANSFORM_SCHEME,
        _ => &DEFAULT_SCHEME,
    }
}

/// Register fields shared by both schemes (everything except
/// `http.request.uri.path`, which is scheme-specific).
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
    b.add_field("cf.edge.server_ip", Type::Ip).unwrap();
    b.add_field("cf.edge.server_port", Type::Int).unwrap();
    b.add_field("cf.hostname.metadata", Type::Bytes).unwrap();
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
    b.add_field("cf.timings.client_tcp_rtt_msec", Type::Int)
        .unwrap();
    b.add_field("cf.timings.edge_msec", Type::Int).unwrap();
    b.add_field("cf.timings.origin_ttfb_msec", Type::Int)
        .unwrap();
    b.add_field("cf.tls_cipher", Type::Bytes).unwrap();
    b.add_field("cf.tls_ciphers_sha1", Type::Bytes).unwrap();
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
    b.add_field("http.response.headers.truncated", Type::Bool)
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

/// Register all 34 functions shared by both schemes.
///
/// Source: <https://developers.cloudflare.com/ruleset-engine/rules-language/functions/>
fn register_common_functions(b: &mut SchemeBuilder) {
    // Built-in wirefilter functions
    b.add_function("any", AnyFunction::default()).unwrap();
    b.add_function("all", AllFunction::default()).unwrap();
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
}

/// Common field definitions as `(name, python_type)` tuples.
///
/// Does NOT include `http.request.uri.path` (scheme-specific) or deprecated fields.
pub fn common_field_defs() -> &'static [(&'static str, &'static str)] {
    static FIELD_DEFS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
        // Map wirefilter Type → Python FieldType enum name by inspecting the
        // default scheme.  We use a helper that walks the registered fields.
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
                                _ => "STRING",
                            }
                        }
                        _ => "STRING",
                    }
                }
                Type::Map(inner) => {
                    let inner_ty: Type = (*inner).into();
                    match inner_ty {
                        Type::Array(inner2) => {
                            let inner2_ty: Type = inner2.into();
                            match inner2_ty {
                                Type::Bytes => "MAP_ARRAY_STRING",
                                Type::Int => "MAP_ARRAY_INT",
                                _ => "STRING",
                            }
                        }
                        _ => "STRING",
                    }
                }
            }
        }

        COMMON_FIELD_NAMES
            .iter()
            .map(|name| {
                let field = DEFAULT_SCHEME.get_field(name).unwrap_or_else(|_| {
                    panic!("COMMON_FIELD_NAMES entry {name:?} not in DEFAULT_SCHEME")
                });
                (*name, type_to_python(&field.get_type()))
            })
            .collect()
    });
    &FIELD_DEFS
}

/// Common function names shared by both schemes.
///
/// Does NOT include `http.request.uri.path` (transform-specific).
pub fn common_function_names() -> &'static [&'static str] {
    COMMON_FUNCTION_NAMES
}

/// Field names registered in `register_common_fields`, in registration order.
/// Excludes `http.request.uri.path` (scheme-specific) and deprecated/account fields.
const COMMON_FIELD_NAMES: &[&str] = &[
    "cf.api_gateway.auth_id_present",
    "cf.api_gateway.fallthrough_detected",
    "cf.api_gateway.request_violates_schema",
    "cf.bot_management.corporate_proxy",
    "cf.bot_management.detection_ids",
    "cf.bot_management.ja3_hash",
    "cf.bot_management.ja4",
    "cf.bot_management.js_detection.passed",
    "cf.bot_management.score",
    "cf.bot_management.static_resource",
    "cf.bot_management.verified_bot",
    "cf.client.bot",
    "cf.edge.client_tcp",
    "cf.edge.server_ip",
    "cf.edge.server_port",
    "cf.hostname.metadata",
    "cf.llm.prompt.detected",
    "cf.llm.prompt.injection_score",
    "cf.llm.prompt.pii_categories",
    "cf.llm.prompt.pii_detected",
    "cf.llm.prompt.unsafe_topic_categories",
    "cf.llm.prompt.unsafe_topic_detected",
    "cf.random_seed",
    "cf.ray_id",
    "cf.response.1xxx_code",
    "cf.response.error_type",
    "cf.threat_score",
    "cf.timings.client_tcp_rtt_msec",
    "cf.timings.edge_msec",
    "cf.timings.origin_ttfb_msec",
    "cf.tls_cipher",
    "cf.tls_ciphers_sha1",
    "cf.tls_client_auth.cert_fingerprint_sha1",
    "cf.tls_client_auth.cert_fingerprint_sha256",
    "cf.tls_client_auth.cert_issuer_dn",
    "cf.tls_client_auth.cert_issuer_dn_legacy",
    "cf.tls_client_auth.cert_issuer_dn_rfc2253",
    "cf.tls_client_auth.cert_issuer_serial",
    "cf.tls_client_auth.cert_issuer_ski",
    "cf.tls_client_auth.cert_not_after",
    "cf.tls_client_auth.cert_not_before",
    "cf.tls_client_auth.cert_presented",
    "cf.tls_client_auth.cert_revoked",
    "cf.tls_client_auth.cert_serial",
    "cf.tls_client_auth.cert_ski",
    "cf.tls_client_auth.cert_subject_dn",
    "cf.tls_client_auth.cert_subject_dn_legacy",
    "cf.tls_client_auth.cert_subject_dn_rfc2253",
    "cf.tls_client_auth.cert_verified",
    "cf.tls_client_extensions_sha1",
    "cf.tls_client_extensions_sha1_le",
    "cf.tls_client_hello_length",
    "cf.tls_client_random",
    "cf.tls_version",
    "cf.verified_bot_category",
    "cf.waf.auth_detected",
    "cf.waf.content_scan.has_failed",
    "cf.waf.content_scan.has_malicious_obj",
    "cf.waf.content_scan.has_obj",
    "cf.waf.content_scan.num_malicious_obj",
    "cf.waf.content_scan.num_obj",
    "cf.waf.content_scan.obj_results",
    "cf.waf.content_scan.obj_sizes",
    "cf.waf.content_scan.obj_types",
    "cf.waf.credential_check.password_leaked",
    "cf.waf.credential_check.username_and_password_leaked",
    "cf.waf.credential_check.username_leaked",
    "cf.waf.credential_check.username_password_similar",
    "cf.waf.score",
    "cf.waf.score.class",
    "cf.waf.score.rce",
    "cf.waf.score.sqli",
    "cf.waf.score.xss",
    "cf.worker.upstream_zone",
    "http.cookie",
    "http.host",
    "http.referer",
    "http.request.accepted_languages",
    "http.request.body.form",
    "http.request.body.form.names",
    "http.request.body.form.values",
    "http.request.body.mime",
    "http.request.body.multipart",
    "http.request.body.multipart.content_dispositions",
    "http.request.body.multipart.content_transfer_encodings",
    "http.request.body.multipart.content_types",
    "http.request.body.multipart.filenames",
    "http.request.body.multipart.names",
    "http.request.body.multipart.values",
    "http.request.body.raw",
    "http.request.body.size",
    "http.request.body.truncated",
    "http.request.cookies",
    "http.request.full_uri",
    "http.request.headers",
    "http.request.headers.names",
    "http.request.headers.truncated",
    "http.request.headers.values",
    "http.request.jwt.claims.aud",
    "http.request.jwt.claims.aud.names",
    "http.request.jwt.claims.aud.values",
    "http.request.jwt.claims.iat.sec",
    "http.request.jwt.claims.iat.sec.names",
    "http.request.jwt.claims.iat.sec.values",
    "http.request.jwt.claims.iss",
    "http.request.jwt.claims.iss.names",
    "http.request.jwt.claims.iss.values",
    "http.request.jwt.claims.jti",
    "http.request.jwt.claims.jti.names",
    "http.request.jwt.claims.jti.values",
    "http.request.jwt.claims.nbf.sec",
    "http.request.jwt.claims.nbf.sec.names",
    "http.request.jwt.claims.nbf.sec.values",
    "http.request.jwt.claims.sub",
    "http.request.jwt.claims.sub.names",
    "http.request.jwt.claims.sub.values",
    "http.request.method",
    "http.request.timestamp.msec",
    "http.request.timestamp.sec",
    "http.request.uri",
    "http.request.uri.args",
    "http.request.uri.args.names",
    "http.request.uri.args.values",
    "http.request.uri.path.extension",
    "http.request.uri.query",
    "http.request.version",
    "http.response.code",
    "http.response.content_type.media_type",
    "http.response.headers",
    "http.response.headers.names",
    "http.response.headers.values",
    "http.response.headers.truncated",
    "http.user_agent",
    "http.x_forwarded_for",
    "ip.src",
    "ip.src.asnum",
    "ip.src.city",
    "ip.src.continent",
    "ip.src.country",
    "ip.src.is_in_european_union",
    "ip.src.lat",
    "ip.src.lon",
    "ip.src.metro_code",
    "ip.src.postal_code",
    "ip.src.region",
    "ip.src.region_code",
    "ip.src.subdivision_1_iso_code",
    "ip.src.subdivision_2_iso_code",
    "ip.src.timezone.name",
    "raw.http.request.full_uri",
    "raw.http.request.uri",
    "raw.http.request.uri.args",
    "raw.http.request.uri.args.names",
    "raw.http.request.uri.args.values",
    "raw.http.request.uri.path",
    "raw.http.request.uri.path.extension",
    "raw.http.request.uri.query",
    "raw.http.response.headers",
    "raw.http.response.headers.names",
    "raw.http.response.headers.values",
    "ssl",
];

/// Function names shared by both schemes (excludes `http.request.uri.path`).
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
];

#[cfg(test)]
mod tests {
    use super::*;

    // ── DEFAULT_SCHEME tests ─────────────────────────────────────────

    #[test]
    fn default_scheme_has_all_fields() {
        // 169 common + 1 (http.request.uri.path as field) = 170
        assert_eq!(DEFAULT_SCHEME.field_count(), 170);
    }

    #[test]
    fn default_scheme_has_all_functions() {
        // 3 built-in (any, all, concat) + 31 custom = 34
        assert_eq!(DEFAULT_SCHEME.function_count(), 34);
    }

    #[test]
    fn default_scheme_uri_path_is_field() {
        let field = DEFAULT_SCHEME.get_field("http.request.uri.path").unwrap();
        assert_eq!(field.name(), "http.request.uri.path");
    }

    #[test]
    fn default_scheme_uri_path_is_not_function() {
        assert!(
            DEFAULT_SCHEME
                .get_function("http.request.uri.path")
                .is_err()
        );
    }

    #[test]
    fn default_scheme_can_parse_uri_path_as_field() {
        let result = DEFAULT_SCHEME.parse(r#"http.request.uri.path eq "/test""#);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }

    // ── TRANSFORM_SCHEME tests ───────────────────────────────────────

    #[test]
    fn transform_scheme_has_fields() {
        // 169 common fields (no http.request.uri.path)
        assert_eq!(TRANSFORM_SCHEME.field_count(), 169);
    }

    #[test]
    fn transform_scheme_has_functions() {
        // 34 common + 1 (http.request.uri.path as function) = 35
        assert_eq!(TRANSFORM_SCHEME.function_count(), 35);
    }

    #[test]
    fn transform_scheme_uri_path_is_function() {
        TRANSFORM_SCHEME
            .get_function("http.request.uri.path")
            .unwrap();
    }

    #[test]
    fn transform_scheme_uri_path_is_not_field() {
        assert!(TRANSFORM_SCHEME.get_field("http.request.uri.path").is_err());
    }

    // ── get_scheme dispatcher tests ──────────────────────────────────

    #[test]
    fn get_scheme_none_returns_default() {
        let s = get_scheme(None);
        assert_eq!(s.field_count(), 170);
    }

    #[test]
    fn get_scheme_unknown_phase_returns_default() {
        let s = get_scheme(Some("http_request_firewall_custom"));
        assert_eq!(s.field_count(), 170);
    }

    #[test]
    fn get_scheme_url_rewrite_rules_returns_transform() {
        let s = get_scheme(Some("url_rewrite_rules"));
        assert_eq!(s.field_count(), 169);
        assert_eq!(s.function_count(), 35);
    }

    #[test]
    fn get_scheme_request_header_rules_returns_transform() {
        let s = get_scheme(Some("request_header_rules"));
        assert_eq!(s.function_count(), 35);
    }

    #[test]
    fn get_scheme_response_header_rules_returns_transform() {
        let s = get_scheme(Some("response_header_rules"));
        assert_eq!(s.function_count(), 35);
    }

    // ── Existing tests (updated to use DEFAULT_SCHEME) ───────────────

    #[test]
    fn can_look_up_http_host() {
        let field = DEFAULT_SCHEME.get_field("http.host").unwrap();
        assert_eq!(field.name(), "http.host");
    }

    #[test]
    fn can_look_up_ip_src() {
        let field = DEFAULT_SCHEME.get_field("ip.src").unwrap();
        assert_eq!(field.name(), "ip.src");
    }

    #[test]
    fn can_look_up_function_lower() {
        DEFAULT_SCHEME.get_function("lower").unwrap();
    }

    #[test]
    fn can_parse_simple_expression() {
        let result = DEFAULT_SCHEME.parse(r#"http.host eq "example.com""#);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }
}
