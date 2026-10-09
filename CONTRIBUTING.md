# Contributing

## Before you start

Temper targets `no_std` with `alloc`. Any change must build on the full feature
matrix, not just the default set:

```sh
cargo test --all-features
cargo test --no-default-features --features alloc
cargo fmt --all --check
cargo clippy --all-features -- -D warnings
```

CI runs the same list; see `.github/workflows/ci.yml`.

## Formatting

The tree is indented with hard tabs and `max_width = 120`. Run `cargo fmt` — the
settings are in `rustfmt.toml` and match the upstream project this crate is
developed in, so a plain `cargo fmt --check` should pass with no config.

## Crypto changes

These need more than a passing test suite:

- **Do not change a serialized type.** `Seal`, `SealContext`, `Envelope`,
  `KernelChainEnvelope`, `HandshakeProposal` and `HandshakeAcceptance` cross
  process, wire, and on-disk boundaries with existing deployments. Field names,
  field order, and encodings are frozen. `DelegationToken` is a `repr(C)` binary
  ABI. Adding a field is a breaking change even when it compiles.
- **Do not rename a BLAKE3 domain string.** They are domain separators; a rename
  silently changes every derived key.
- **New primitives need a negative control.** A test that passes proves the happy
  path works, not that the check is load-bearing. Break the check deliberately,
  confirm the test fails, then restore it. Several bugs found in this codebase
  were in tests that could not fail.
- **Entropy tests are statistical.** They are inherently probabilistic; do not
  loosen a bound to make a run go green.

## Commits

Keep messages short and factual. Explain *why* in the commit body when the change
is not self-evident; the code comments are for what the code cannot say itself.
