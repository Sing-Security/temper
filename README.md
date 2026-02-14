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
cargo check --no-default-features --features alloc
cargo check
cargo test
```

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
