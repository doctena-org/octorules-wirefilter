# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.2] - 2026-08-08

### Changed
- wirefilter-engine updated to upstream `ec8e24e` (2026-07-27). Expressions nested deeper than 128 levels now fail to parse, matching Cloudflare's parser; `any()`/`all()` are handled natively by the engine. Parse output and `get_schema_info()` are unchanged.
- Vendored `rand` updated from 0.9.3 to 0.9.5.

## [0.5.1] - 2026-07-26

### Added
- `octorules_wirefilter.pyi` type stub ships in the wheel — IDE signatures and result-shape documentation for `parse_expression` and `get_schema_info`.

## [0.5.0] - 2026-07-01

### Added
- Magic Firewall (Layer-4) field scheme: `parse_expression` and
  `get_schema_info` accept `scheme="magic_firewall"`, exposing packet-level
  fields (`ip.proto`, `tcp.*`, `udp.*`, …) for Cloudflare Magic Transit
  phases. The default scheme remains HTTP.

### Changed
- `parse_expression`/`get_schema_info` take a `scheme` argument (previously an
  unused `phase` parameter).

## [0.4.2] - 2026-06-15

### Changed
- Updated `pyo3` 0.28.2 -> 0.29.0 for security advisories
  GHSA-36hh-v3qg-5jq4 (out-of-bounds read in `PyList`/`PyTuple`
  `nth`/`nth_back`, CVSS 8.7) and GHSA-chgr-c6px-7xpp. Re-vendored.
  No API or schema changes.

## [0.4.1] - 2026-06-11

### Changed
- Vendored `once_cell` 1.21.4 and `rand` 0.9.3 for upstream security
  advisories. No API or schema changes.

## [0.4.0] - 2026-05-04

### Added
- 4 RFC 9440 mTLS Client-Cert fields: `cf.tls_client_auth.cert_chain_rfc9440`,
  `cert_chain_rfc9440_too_large`, `cert_rfc9440`, `cert_rfc9440_too_large`.
- `cf.edge.l4.delivery_rate`, `cf.timings.client_quic_rtt_msec`,
  `cf.timings.worker_msec`, `cf.llm.prompt.custom_topic_categories`,
  `cf.llm.prompt.token_count`.
- JWT validation functions `is_jwt_valid(uuid)` and `is_jwt_present(uuid)`
  (Cloudflare API Shield). The argument is a UUID literal, not a field —
  passing a field is a parse error.
- `regex_field_pairs` in the `parse_expression` result dict — `(field, regex)`
  tuples for `matches` operators with a plain field LHS, alongside the existing
  flat `regex_literals` list.

### Removed
- `http.request.jwt.claims.exp.sec`, `.sec.names`, `.sec.values` — Cloudflare
  validates `exp` internally via `is_jwt_valid()` and doesn't expose it as a
  queryable field.
- `http.response.headers.truncated` — not in Cloudflare docs; only the
  request-side variant exists.

A regression test (`removed_speculative_fields_stay_removed`) prevents
re-adding these by symmetry.

### Changed
- Field count: 173 → 178. Function count: 34 → 36.

## [0.3.6] - 2026-04-27

### Documentation
- Schema path references corrected; `edition = "2024"` requirement
  made explicit in the README.
- `phase` parameter behavior clarified.
- Named list support and the wildcard-star limit are now documented.

## [0.3.5] - 2026-04-02

### Added
- Named list support in the production scheme — expressions like
  ``ip.src in $my_list`` now parse without error.  ``AlwaysList`` is
  registered for Int, Ip, and Bytes types so wirefilter accepts any
  ``$name`` reference.  Actual list validation (existence, type
  compatibility) is handled by the Python linter (CF102/CF104).
- ``ParserSettings`` with ``wildcard_star_limit: 10`` to catch excessive
  wildcard metacharacters at lint time.

### Changed
- Dev dependencies pinned to minimum versions (`pytest>=7.0`, `ruff>=0.4.0`,
  `yamllint>=1.35.0`) for reproducible builds.
- Added `per-file-ignores` for test files (`RUF043`).
- Added pre-commit hook (`cargo fmt`, `cargo clippy`, `ruff check/format`).

## [0.3.4] - 2026-03-31

### Fixed
- `dedup_add!` macro now truly performs zero allocations for duplicate values
  (was incorrectly claiming this since v0.3.1 but still allocating on every call).

### Changed
- All dependencies vendored into `vendor/` to eliminate runtime dependency on
  remote git repositories.

### Added
- 29 Rust unit tests for `ExpressionExtractor` covering deduplication, boolean
  fields, named lists (`$list_name`), IP ranges, operators, functions, logical
  operators, and depth guards.

## [0.3.3] - 2026-03-14

### Changed
- `parse_expression()` docstring clarifies that the `phase` parameter is
  accepted for forward compatibility but currently ignored.
- CI: added `yamllint` job for `.github/workflows/*.yml` files.
- `RESULT_KEYS` now includes `int_literals` — eliminates the manual
  `set_item` call that was separate from the loop.
- `pyproject.toml`: added Python 3.10–3.14 version classifiers to match
  CI matrix and `requires-python`.

## [0.3.2] - 2026-03-07

### Fixed
- `parse_expression()` error responses (syntax errors, oversized input) now
  include all 7 standard keys (`fields`, `functions`, `operators`,
  `string_literals`, `regex_literals`, `ip_literals`, `int_literals`) with
  empty lists, matching the structure of successful responses. Previously,
  error dicts only contained the `error` key, forcing callers to check for
  key existence before accessing fields.
- Extracted `RESULT_KEYS` constant and `set_empty_result_keys()` helper in
  `lib.rs` — eliminates 3× copy-pasted error response dict construction.

### Changed
- `dedup_add!` macro replaces 6 near-identical `add_field`/`add_function`/etc.
  methods in `ExpressionExtractor`. Each uses `HashSet::insert()` return value
  to avoid the `contains()` + `insert()` double-lookup.
- `extract_explicit_ip_range<T: Display + PartialEq>` generic method eliminates
  duplicate IPv4/IPv6 range extraction logic.
- Error responses use `PyList::empty(py)` instead of allocating empty `Vec`s.

### Added
- Scheme count assertion tests: `COMMON_FIELD_NAMES` (164) and
  `COMMON_FUNCTION_NAMES` (34) — guards against accidental additions/removals.

## [0.3.1] - 2026-03-06

### Added
- 3 JWT `exp` claim fields: `http.request.jwt.claims.exp.sec` (Map<Array<Int>>),
  `http.request.jwt.claims.exp.sec.names` (Array<Bytes>),
  `http.request.jwt.claims.exp.sec.values` (Array<Int>). Scheme now has
  173 fields.
- `# Panics` doc sections on `LazyLock` scheme registrations (replaced bare
  `panic!` calls with documented `.expect()` calls).

### Changed
- Visitor `clone()` optimization: removed unnecessary clones in `add_field`,
  `add_function`, `add_operator` — duplicates now require 0 allocations.

### Removed
- `TRANSFORM_SCHEME` and `TRANSFORM_PHASES` — octorules always uses a single
  scheme where `http.request.uri.path` is a field (since octorules v0.12.1).
  Transform-phase function-call syntax is handled on the Python side.
- `get_scheme(phase)` dispatcher — replaced by direct `SCHEME` static.
  `parse_expression()` still accepts `phase` for API compatibility but ignores it.
- `get_schema_info()` no longer returns `transform_phases` or
  `transform_field_as_function` keys.

## [0.3.0] - 2026-03-06

### Changed
- Upgraded PyO3 from 0.24 to 0.28, enabling Python 3.14 support.
- Added Python 3.14 to CI test matrix and release wheel builds.
- Release wheel builds now use `--find-interpreter` instead of explicit
  version list.
- Bumped GitHub Actions (`checkout`, `setup-python`, `upload-artifact`,
  `download-artifact`) to v6.

## [0.2.0] - 2026-03-05

### Added
- `get_schema_info()` FFI function — returns field names/types, function names,
  transform phases, and the transform-specific field-as-function name. Enables
  automated schema synchronization with the Python linter schemas.
- Input size limit: expressions exceeding 1 MiB are rejected with an error dict
  before parsing.
- Nesting depth limit: AST visitor stops descending at depth 100, preventing
  stack overflow on pathological expressions. Result dict includes
  `depth_exceeded: true` when triggered.
- `http.response.headers.truncated` field to default scheme (170 fields).
- Boundary/stress tests: oversized expressions, near-limit expressions, deep
  nesting, many unique fields, i64 max value, null bytes, empty string literals.
- Phase parameter edge case tests: misspelled, empty, None, uppercase phases.
- `get_schema_info()` test suite: return type, required keys, field/function
  validation, transform phase metadata.
- Test coverage for `wildcard`, `strict_wildcard`, `bitwise_and`, `xor`,
  `ge`, `le`, `lt` operators.
- Tests for `is_timed_hmac_valid_v0` with 3, 4, and 5 arguments.
- Tests for `remove_query_args` with 2, 3, 5, and 8 arguments.
- CI: `cargo fmt --check` and `cargo clippy` in Rust job, Ruff lint/format
  check for Python tests, yamllint for YAML files.

### Fixed
- `is_timed_hmac_valid_v0` now accepts optional 4th (Bytes) and 5th (Int)
  parameters. Previously, valid expressions with 4–5 args failed to parse.
- `remove_query_args` now accepts up to 8 Bytes arguments (1 required + 7
  optional). Previously, expressions with 3+ args failed to parse.
- AST visitor now matches `IntOp` variant explicitly instead of using `..`
  catch-all — prevents silent misclassification if wirefilter adds new int ops.
- Non-UTF-8 byte strings now captured via `from_utf8_lossy` instead of being
  silently dropped.

### Changed
- Visitor uses `HashSet` instead of `BTreeSet` for deduplication (faster lookups).
- Visitor `add_*` methods reduce allocations: duplicates require 0 allocations
  (was 1), uniques require 1 alloc + 1 clone (was 2 independent allocs).
- `TRANSFORM_PHASES` is now `pub` (was `const`) for use by `get_schema_info()`.

## [0.1.0] - 2026-03-05

### Added
- Initial release: PyO3 bindings for Cloudflare's wirefilter expression parser.
- Phase-aware schemes: default (169 fields, 34 functions) and transform
  (168 fields, 35 functions).
- AST visitor extracts fields, functions, operators, and literals.
- `parse_expression(expr, phase=None)` returns structured dict or error.

### Removed
- Dead `Visitor` trait implementation in `visitor.rs` — the `extract()` method
  uses manual walk methods directly and the trait impl was never called.
