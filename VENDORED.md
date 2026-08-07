# Vendored Dependencies

## wirefilter-engine (git-pinned)

**What is pinned:** Cloudflare's [wirefilter](https://github.com/cloudflare/wirefilter) expression parser engine (Rust crate).

**Why:** The `SchemeBuilder` and function registration APIs required to expose both the HTTP and Magic Transit (Layer-4) packet-level field schemes are not present in the published crates.io version `wirefilter-engine = "0.7.0"`. The engine must be pinned to a specific git commit that includes these unstable APIs.

**Exact pin:**
```toml
wirefilter-engine = { git = "https://github.com/cloudflare/wirefilter", rev = "ec8e24e26e2707a88034bfe161beeb2a4f51f8df", default-features = false, features = ["regex"] }
```

**Commit:** `ec8e24e26e2707a88034bfe161beeb2a4f51f8df` (upstream master, 2026-07-27)

**Features:** `default-features = false` skips `get-size2` (LhsValue memory
accounting — an execution-side concern; this crate only parses). `regex`
stays on: the scheme has regex-typed fields and `matches()` support.

## Update Procedure

To update the wirefilter-engine pin to a newer commit:

1. Update `Cargo.toml`: change the `rev` field to the desired commit SHA.
2. Test the update:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets
   cargo test --all
   ```
3. Run the full integration test suite (includes field-count assertions):
   ```bash
   # Verify 169 HTTP fields and 36 callable functions (34 registered + native any/all)
   # Verify 33 Magic Transit (Layer-4) fields
   pytest tests/
   ```
4. Run the octorules-cloudflare test suite as the integration gate (ensure CF's lint still works with the new engine).
5. Create a commit with a clear message: "Pin wirefilter-engine to commit XXXXX" (with rationale in the commit body if applicable).

## Divergence Policy

**No local patches to the vendored engine.** If the engine exhibits a bug or limitation that blocks octorules development:

1. File an issue or PR against [cloudflare/wirefilter](https://github.com/cloudflare/wirefilter).
2. Once the fix lands in cloudflare/wirefilter and is pushed, create a new pin to the fixed commit in octorules-wirefilter (following the Update Procedure above).

Local patches in `vendor/` or elsewhere would create a fork that drifts from upstream and becomes a maintenance burden. A new pin is always preferred.
