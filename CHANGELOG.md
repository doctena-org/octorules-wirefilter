# Changelog

All notable changes to this project will be documented in this file.

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
