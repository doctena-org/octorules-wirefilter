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

## Schemes

Two wirefilter schemes are built at startup and cached:

- **Default scheme** — 170 fields, 34 functions. Used for all phases except transform phases.
- **Transform scheme** — 169 fields, 35 functions. `http.request.uri.path` is registered as a callable function (not a field) because transform phases treat it differently.

The `phase` parameter selects the scheme: `url_rewrite_rules`, `request_header_rules`, and `response_header_rules` use the transform scheme; everything else uses the default.

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

This package exposes a single function:

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

**Returns** a dict with either:
- On success: `fields`, `functions`, `operators`, `string_literals`, `regex_literals`, `ip_literals`, `int_literals` (all lists)
- On failure: `error` (string)

## Contributing

### Adding fields

When Cloudflare adds new fields, update `src/scheme.rs` — add the field to `register_common_fields()` (shared by both schemes). If the field behaves differently in transform phases, add it to the scheme-specific sections instead.

Also update the field registry in the [octorules](https://github.com/doctena-org/octorules) repo: `src/octorules/linter/schemas/fields.py`.

### Adding functions

Update `src/scheme.rs` — register in `register_common_functions()` (for all phases) or in the `TRANSFORM_SCHEME` builder (for transform-only functions).

Also update the function registry in the [octorules](https://github.com/doctena-org/octorules) repo: `src/octorules/linter/schemas/functions.py`.

## Design decisions

- **Separate PyPI package.** The Rust build requires a toolchain and takes longer to compile. Users who want fast installs get `pip install octorules`; those who want authoritative parsing opt in with `pip install octorules[wirefilter]`.
- **Git dependency pinning.** `wirefilter-engine` is pinned to a specific commit because the required APIs (`SchemeBuilder`, function registration) are not in the published crates.io version.
- **Stub function implementations.** Functions are registered with correct type signatures but no-op execution. Expressions parse and extract correctly; runtime evaluation is not supported.
- **cdylib crate type.** Required by PyO3's extension-module feature for Python to load the native extension.

## License

Apache-2.0 — see [LICENSE](LICENSE).
