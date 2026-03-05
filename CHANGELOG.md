# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `http.response.headers.truncated` field to default scheme (170 fields).
- Test coverage for `wildcard`, `strict_wildcard`, `bitwise_and`, `xor`,
  `ge`, `le`, `lt` operators.

### Fixed
- AST visitor now matches `IntOp` variant explicitly instead of using `..`
  catch-all — prevents silent misclassification if wirefilter adds new int ops.
- Non-UTF-8 byte strings now captured via `from_utf8_lossy` instead of being
  silently dropped.

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
