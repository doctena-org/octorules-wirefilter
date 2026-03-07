# octorules-wirefilter

Rust FFI bindings for Cloudflare's [wirefilter](https://github.com/cloudflare/wirefilter) expression parser, exposed to Python via [PyO3](https://pyo3.rs/). When installed, [`octorules lint`](https://github.com/doctena-org/octorules) uses the real wirefilter parser for authoritative expression analysis instead of the built-in regex fallback.

## Installation

```bash
# Install octorules with wirefilter support
pip install octorules[wirefilter]

# Or install standalone
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
    │       ├── lib.rs         PyO3 parse_expression(expr, phase=None)
    │       ├── scheme.rs      Phase-aware field/function schemes
    │       └── visitor.rs     AST walker → fields, functions, operators, literals
    │       │
    │       ▼
    │   wirefilter-engine      Cloudflare's Rust expression parser
    │
    └─► regex fallback         Built-in patterns (always available)
```

`octorules` tries to import `octorules_wirefilter` at module load time. If available, expressions are parsed by the real Cloudflare wirefilter engine. On import failure or parse error, the bridge transparently falls back to regex extraction. Either path returns the same `ExpressionInfo` dataclass consumed by the linter.

## Scheme

A single wirefilter scheme is built at startup and cached:

- **173 fields** (including `http.request.uri.path`), **34 functions**.

The `phase` parameter is accepted for API compatibility but currently unused — all expressions are parsed against the same scheme. Transform-phase function-call syntax (where `http.request.uri.path` is callable) is handled on the Python side.

## Building from source

### Prerequisites

- Rust toolchain **>= 1.86** (stable, via [rustup](https://rustup.rs/))
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

### `parse_expression(expr, phase=None)`

```python
from octorules_wirefilter import parse_expression

# Parse an expression against the default scheme
result = parse_expression('http.host eq "example.com"')
# {'fields': ['http.host'], 'operators': ['eq'], 'string_literals': ['example.com'], ...}

# Parse with phase-aware scheme selection
result = parse_expression('lower(http.host) eq "test"', phase="url_rewrite_rules")

# Parse errors return an error key
result = parse_expression('bogus_field eq "x"')
# {'error': 'unknown field bogus_field'}
```

**Returns** a dict with keys `fields`, `functions`, `operators`, `string_literals`, `regex_literals`, `ip_literals`, `int_literals` (all lists), plus:
- On success: lists populated with extracted values. If AST nesting exceeded the depth limit, `depth_exceeded: true` is included.
- On failure: `error` (string) with all list keys present but empty.

Expressions exceeding 1 MiB are rejected with an error dict before parsing.
Nesting depth is capped at 100 levels to prevent stack overflow on pathological input.

### `get_schema_info()`

```python
from octorules_wirefilter import get_schema_info

info = get_schema_info()
# {'fields': [{'name': 'http.host', 'type': 'STRING'}, ...],
#  'functions': ['lower', 'upper', ...]}
```

Returns schema metadata for automated synchronization with the Python linter schemas. Field types use the Python `FieldType` enum names (`STRING`, `INT`, `BOOL`, `IP`, `ARRAY_STRING`, etc.).

## Contributing

**Important:** Field and function registries exist in two places: `src/scheme.rs` (Rust — used by wirefilter for parsing and type checking) and `src/octorules/linter/schemas/` in the octorules repo (Python — used by the regex fallback parser and lint rules). A `sync_schemas.py` script in the octorules repo regenerates the Python schemas from wirefilter's `get_schema_info()` function, but Rust-side changes must still be made manually.

### Adding fields

When Cloudflare adds new fields, update `src/scheme.rs` — add the field to `register_common_fields()` **and** to the `COMMON_FIELD_NAMES` array.

Then run `python scripts/sync_schemas.py` in the octorules repo to regenerate the Python schemas. If the field needs Python-only metadata (`requires_plan`, `is_response`), add it to `overlay.toml` first.

### Adding functions

Update `src/scheme.rs` — register in `register_common_functions()` and add the name to the `COMMON_FUNCTION_NAMES` array.

Then run `python scripts/sync_schemas.py` in the octorules repo. If the function needs `restricted_phases` or `requires_plan`, add it to `overlay.toml` first.

## Design decisions

- **Separate PyPI package.** The Rust build requires a toolchain and takes longer to compile. Users who want fast installs get `pip install octorules`; those who want authoritative parsing opt in with `pip install octorules[wirefilter]`.
- **Git dependency pinning.** `wirefilter-engine` is pinned to a specific commit because the required APIs (`SchemeBuilder`, function registration) are not in the published crates.io version.
- **Stub function implementations.** Functions are registered with correct type signatures but no-op execution. Expressions parse and extract correctly; runtime evaluation is not supported.
- **cdylib crate type.** Required by PyO3's extension-module feature for Python to load the native extension.

## License

Apache-2.0 — see [LICENSE](LICENSE).
