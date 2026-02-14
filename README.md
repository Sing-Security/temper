# Temper — Quantum-Safe Cryptographic Protocol

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

> **NOTE:** Temper is currently at internal version **v0.5**. This repository is not yet released for public use. Documentation, APIs, and features may change before first public release.

## Overview

**Temper** is a Rust cryptographic protocol library designed for quantum-safe, embedded, and server environments. Every protocol, pattern, and test reflects the internal state at **v0.5**.

- 100% `#![no_std]` compatible (embedded-first, `alloc` required, `std` optional)
- All cryptographic primitives chosen for post-quantum resistance
- Internal memory/pattern system governs all code and test structure

## Core Features

- **Hardened Entropy Generation**  
  Multi-source entropy pool (OS, hardware, jitter, process) > BLAKE3 mixing > ChaCha20 DRBG. Designed for forward secrecy and statistical audit.
- **Dual PQC Signatures**  
  Both ML-DSA-65 (lattice, FIPS 204) and SLH-DSA-SHA2-128s (hash-based, FIPS 205) must be broken to forge a valid seal.
- **Deterministic IDs**  
  All structures keyed by BLAKE3 content hashing for reproducibility.
- **Automatic Reseeds**  
  DRBG re-seeds after every 2²⁰ bytes, sourcing new entropy pools automatically.
- **Statistical Verification**  
  Test suite includes:  
  - Byte distribution (chi-squared, 255df at p=0.001)  
  - Bit balance (each bit ~50%)  
  - Autocorrelation (|r| < 0.019)  
  - Avalanche/SAC (~50% bits flip on input bit change)  
  - Zero collisions (birthday bound) in 1M u64 samples

## Protocol Architecture

### Entropy

```
Entropy Sources (OS, Jitter, HW, PID)
    ↓
 BLAKE3 Entropy Pool (domain-separated)
    ↓
 ChaCha20 DRBG (reseeds every 1MiB)
    ↓
 Random Output / Key Material
```

### Seal Construction

```
message ─BLAKE3→ content hash
             ↓
     (context, hash) → binding = hex(hash) || postcard(context)
             ↓
      [ML-DSA-65 signature]
      [SLH-DSA signature]
All must verify for seal validity
```

## Key Types & Algorithms (as of v0.5)

- **ML-DSA-65**: Lattice-based, NIST L3, signatures ~3309B, pk ~1952B
- **SLH-DSA-SHA2-128s**: Stateless, hash-based, NIST L5, signatures ~7856B, pk ~32B
- **Hash**: BLAKE3 (128-bit collision resistance)
- **DRBG**: ChaCha20 (256-bit key)
- **Entropy**: Any platform source + custom trait implementations

## Internal Usage

See crate for internal API usage. All features/APIs are documented inline for internal contributors.

- `TemperEntropy` — main CSPRNG, accepts custom entropy sources
- `generate_keypair`, `create_seal`, `verify_seal` — main protocol API
- Metadata must use deterministic types (no HashMap, use BTreeMap)
- All error handling and region comments follow `.github/copilot-instructions.md` conventions

## Testing & Validation

Run `cargo test` (`--no-default-features --features alloc` on embedded).  
Tests reflect statistical and algebraic properties defined in `/instructions/` and `/tests/`.

All code and tests are `no_std` first. Build regularly both with and without the `std` feature:

```bash
# Minimal embedded build
cargo check --no-default-features --features alloc

# Standard build with std
cargo check

# All tests (16 tests including performance optimizations)
cargo test

# With BLAKE3 SIMD acceleration (std only)
cargo test --features blake3_simd

# With parallel hashing for large content (std only)
cargo test --features blake3_parallel
```

## Feature Flags

Temper provides granular feature flags for different deployment scenarios:

### Core Features

- **`alloc`** (implicit with `std`): Heap allocation support (required for all builds)
- **`std`** (default): Standard library support, enables OS entropy sources and convenience APIs

### Performance Features (std only)

- **`blake3_simd`**: BLAKE3 SIMD acceleration (NEON on ARM, AVX2/AVX512 on x86)
- **`blake3_parallel`**: Rayon-based parallel hashing for content >= 1 MiB (includes `blake3_simd`)

### Optional Features

- **`hardware_example`**: Example hardware TRNG integration (works with both std and no_std)

### Usage Examples

```toml
# Minimal embedded (Cortex-M, RISC-V)
temper = { version = "0.1", default-features = false, features = ["alloc"] }

# Desktop with SIMD acceleration
temper = { version = "0.1", features = ["std", "blake3_simd"] }

# High-performance server with parallel hashing
temper = { version = "0.1", features = ["std", "blake3_parallel"] }

# Embedded with hardware RNG example
temper = { version = "0.1", default-features = false, features = ["alloc", "hardware_example"] }
```

## Build Profiles

### Embedded (Size-Optimized)

Default release profile optimizes for binary size:

```bash
cargo build --release --no-default-features --features alloc
```

See `BINARY_SIZE_GUIDE.md` for detailed size analysis with `cargo-bloat`.

### Server (Speed-Optimized)

Use the `release-server` profile for maximum performance:

```bash
cargo build --profile release-server --features blake3_parallel
```

### Benchmarks

Run performance benchmarks (requires std):

```bash
cargo bench --bench seal_bench
```

Benchmarks test seal creation/verification across multiple content sizes (1KB - 10MB).

## Contributions

All contributors must:

- Maintain `#![no_std]` compatibility
- Document any change in inline comments referencing origin pattern/memory (see `.github/copilot-instructions.md`)
- Consult `.github/MEMORY_PATTERN_EXAMPLES.md` before establishing or deviating from any pattern

This repo is under active development and not yet intended for external consumption.  
Submit issues, improvement suggestions, and deviations from internal conventions via direct message or team forum.

---

**For questions or proposed changes, contact Sing-Security core contributors directly.**

**Built with ❤️ for a quantum-safe future.**
