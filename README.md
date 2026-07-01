# octorules-wirefilter

Rust FFI bindings for Cloudflare's [wirefilter](https://github.com/cloudflare/wirefilter) expression parser, exposed to Python via [PyO3](https://pyo3.rs/). [`octorules-cloudflare`](https://github.com/doctena-org/octorules-cloudflare) depends on this package to parse and type-check rule expressions — both the HTTP scheme and the Magic Transit / Layer-4 (`magic_firewall`) scheme — instead of regex heuristics.

## Installation

```bash
# octorules-cloudflare installs this automatically as a required dependency.
# To install standalone:
pip install octorules-wirefilter
```

## How it works

```
octorules lint
    │
    ▼
expression_bridge.py          Python-side routing layer
    │
    ├─► octorules_wirefilter   (if installed)
    │       │
    │       ├── lib.rs         PyO3 parse_expression(expr, scheme=None)
    │       ├── scheme.rs      HTTP + Magic Transit (L4) field/function schemes
    │       └── visitor.rs     AST walker → fields, functions, operators, literals
    │       │
    │       ▼
    │   wirefilter-engine      Cloudflare's Rust expression parser
    │
    └─► regex fallback         Built-in patterns (always available)
```

`octorules-cloudflare` requires `octorules_wirefilter`, so valid expressions are parsed by the real Cloudflare wirefilter engine. When wirefilter *rejects* an expression (e.g. a type mismatch or unknown function), the bridge runs a regex pass to still extract fields/operators — so the linter's own semantic rules can report on it — while preserving wirefilter's error. That same regex pass also covers the (now unsupported) case where the native extension can't be imported. Either path returns the same `ExpressionInfo` dataclass consumed by the linter.

## Scheme

Two wirefilter schemes are built at startup and cached:

- **HTTP scheme** (default): 169 fields exposed via `get_schema_info()`, 36 functions.
- **Magic Transit / Layer-4 scheme** (`magic_firewall`): 33 packet-level fields
  (`ip.proto`, `tcp.*`, `udp.*`, …) for account-level network phases.
- **Named list support** — expressions like `ip.src in $my_list` parse
  without error. `AlwaysList` is registered for Int, Ip, and Bytes types
  so any `$name` reference is accepted. Actual list validation (existence,
  type compatibility) is handled by the Python linter ([CF102](https://github.com/doctena-org/octorules-cloudflare/blob/main/docs/lint/README.md): unresolved list reference, [CF104](https://github.com/doctena-org/octorules-cloudflare/blob/main/docs/lint/README.md): field type incompatible with list kind).
- **Wildcard limit** — `ParserSettings` enforces a maximum of 10 `*`
  metacharacters per wildcard pattern to prevent catastrophic backtracking.

The `scheme` parameter selects the field set: `"magic_firewall"` parses against the Layer-4 packet scheme; any other value (or `None`) uses the default HTTP scheme. Transform-phase function-call syntax (where `http.request.uri.path` is callable) is handled on the Python side.

## Building from source

### Prerequisites

- Rust toolchain **>= 1.86**, edition 2024 (stable, via [rustup](https://rustup.rs/))
- Python >= 3.10 with venv
- [maturin](https://github.com/PyO3/maturin) (`pip install maturin`)

### Development build

```bash
maturin develop
```

Builds the Rust crate and installs the resulting Python extension module into the active virtualenv.

### Wheel build

```bash
maturin build --release
```

Produces a wheel in `target/wheels/`.

## Testing

```bash
# Install test dependencies
pip install pytest

# Run FFI tests (requires octorules-wirefilter to be installed via maturin develop)
pytest tests/
```

Tests skip gracefully if the native extension is not installed.

## API

This package exposes two functions:

### `parse_expression(expr, scheme=None)`

```python
from octorules_wirefilter import parse_expression

# Parse an expression against the default scheme
result = parse_expression('http.host eq "example.com"')
# {'fields': ['http.host'], 'operators': ['eq'], 'string_literals': ['example.com'], ...}

# Pass scheme="magic_firewall" to parse against the Layer-4 packet scheme
# (Cloudflare Magic Transit / network phases).
result = parse_expression('ip.proto eq "tcp" and tcp.dstport eq 22', scheme="magic_firewall")

# Parse errors return an error key (all list keys present but empty)
result = parse_expression('bogus_field eq "x"')
# {'error': '...', 'fields': [], 'functions': [], 'operators': [], ...}
```

**Returns** a dict with keys `fields`, `functions`, `operators`, `string_literals`, `regex_literals`, `ip_literals`, `int_literals`, `regex_field_pairs` (all lists), plus:
- On success: lists populated with extracted values. `regex_field_pairs` holds `[field, regex]` pairs showing which field each regex is matched against (e.g. `[["http.request.uri.path", "^/api"]]`). If AST nesting exceeded the depth limit, `depth_exceeded: true` is included.
- On failure: `error` (string) with all list keys present but empty.

Expressions exceeding 1 MiB are rejected with an error dict before parsing.
Nesting depth is capped at 100 levels to prevent stack overflow on pathological input.

### `get_schema_info(scheme=None)`

```python
from octorules_wirefilter import get_schema_info

info = get_schema_info()
# {'fields': [{'name': 'http.host', 'type': 'STRING'}, ...],
#  'functions': ['lower', 'upper', ...]}
```

Returns schema metadata for the requested scheme (`scheme="magic_firewall"` for the Layer-4 set; default is HTTP). `octorules-cloudflare` builds its linter field/function registry from this at import time. Field types use the Python `FieldType` enum names (`STRING`, `INT`, `BOOL`, `IP`, `ARRAY_STRING`, etc.).

## Contributing

Field and function definitions live in one place — `src/scheme.rs` (`register_common_fields`, `register_magic_firewall_fields`, `register_common_functions`). `octorules-cloudflare` derives its Python field/function registry from these at import time via `get_schema_info()`; there is no second copy to keep in sync and no generated `schemas.json`.

### Adding fields

Add the field to `register_common_fields()` (HTTP scheme) or `register_magic_firewall_fields()` (Magic Transit / Layer-4 scheme) in `src/scheme.rs`, then rebuild (`maturin develop`). `octorules-cloudflare` picks it up automatically. Python-only metadata (`requires_plan`, `is_response`) lives in that repo's `overlay.toml`.

### Adding functions

Register the function in `register_common_functions()` in `src/scheme.rs` (and the `COMMON_FUNCTION_NAMES` list it's enumerated by), then rebuild. Function metadata (`restricted_phases`, `requires_plan`) lives in `octorules-cloudflare`'s `overlay.toml`.

## Design decisions

- **Separate PyPI package.** The Rust build needs a toolchain, so this ships as prebuilt per-platform wheels. Keeping it standalone lets `octorules-cloudflare` depend on a versioned, wheel-distributed artifact instead of vendoring Rust into the provider.
- **Git dependency pinning.** `wirefilter-engine` is pinned to a specific commit because the required APIs (`SchemeBuilder`, function registration) are not in the published crates.io version.
- **Stub function implementations.** Functions are registered with correct type signatures but no-op execution. Expressions parse and extract correctly; runtime evaluation is not supported.
- **cdylib crate type.** Required by PyO3's extension-module feature for Python to load the native extension.

## License

octorules-wirefilter is licensed under the [Apache License 2.0](LICENSE).
