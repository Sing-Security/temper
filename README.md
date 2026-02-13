# Temper — Quantum-Safe Cryptographic Protocol

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

**Temper** is a quantum-safe cryptographic protocol crate for Rust, designed to be fully `#![no_std]` compatible for embedded systems (Cortex-M, RISC-V MCUs, etc.) while also supporting standard server environments.

## Features

- **Hardened Entropy Generation**: Multi-source entropy pooling with BLAKE3 mixing and ChaCha20 DRBG
- **Dual PQC Signatures**: Defense-in-depth with ML-DSA-65 (lattice-based) + SLH-DSA (hash-based)
- **Automatic Re-seeding**: DRBG re-seeds every 2²⁰ (1,048,576) bytes for forward secrecy
- **`#![no_std]` First**: Works on embedded devices with only `alloc`, `std` features are optional
- **Content-Addressed IDs**: BLAKE3-based deterministic identifiers for all structures
- **Statistical Verification**: Comprehensive test suite with chi-squared, autocorrelation, avalanche, and bit balance tests

---

## Architecture

### Entropy Generation

```text
┌─────────────────┐
│ Entropy Sources │ (OS, Jitter, Process, Hardware TRNG)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  BLAKE3 Pool    │ (Keyed hash with domain separation)
│  "Temper.DRBG"  │
└────────┬────────┘
         │ derive_key("Temper.DRBG.Init.v1")
         ▼
┌─────────────────┐
│ ChaCha20 DRBG   │ (RngCore + CryptoRng)
└────────┬────────┘
         │ Auto re-seed every 2²⁰ bytes
         ▼
    Random Bytes
```

**Key Properties:**
- Multi-source entropy collection (OS, jitter, process ID, hardware RNG)
- BLAKE3 domain-separated key derivation
- ChaCha20 DRBG for cryptographically secure output
- Automatic re-seeding for forward secrecy

### Seal Protocol

```text
┌──────────┐
│ Message  │
└────┬─────┘
     │ BLAKE3
     ▼
┌──────────────┐
│ Content Hash │ (32 bytes)
└────┬─────────┘
     │
     ├─────────────────┐
     │                 │
     ▼                 ▼
┌─────────┐      ┌──────────┐
│ Context │      │   Hex    │
│  JSON   │      │  String  │
└────┬────┘      └────┬─────┘
     │                │
     └────────┬───────┘ Concatenate
              │
              ▼
      ┌──────────────┐
      │   Binding    │ = hex(hash) || json(context)
      └──────┬───────┘
             │
     ┌───────┴────────┐
     ▼                ▼
┌─────────┐      ┌─────────┐
│ ML-DSA  │      │ SLH-DSA │
│   σ₁    │      │   σ₂    │
└─────────┘      └─────────┘
```

**Verification Requirements:**
ALL three checks must pass:
1. `BLAKE3(content) == seal.content_hash` — Content integrity
2. `ML-DSA.Verify(pk₁, binding, σ₁)` — Primary signature (lattice-based)
3. `SLH-DSA.Verify(pk₂, binding, σ₂)` — Backup signature (hash-based)

---

## Usage

### Desktop (std feature)

```rust
use temper::{TemperEntropy, generate_keypair, create_seal, verify_seal};
use alloc::collections::BTreeMap;

// Generate entropy from OS + jitter + process sources
let mut rng = TemperEntropy::new()?;

// Generate quantum-safe keypair
let keypair = generate_keypair(&mut rng, "alice@example.com")?;

// Create a seal for your content
let content = b"Secret document";
let mut metadata = BTreeMap::new();
metadata.insert("classification".into(), "TOP SECRET".into());
let seal = create_seal(&mut rng, content, &keypair, metadata)?;

// Verify the seal
let result = verify_seal(
    content,
    &seal,
    &keypair.mldsa_public_key,
    &keypair.slhdsa_public_key,
)?;

assert!(result.valid);
```

### Embedded (no_std with alloc)

```rust
#![no_std]
extern crate alloc;

use temper::{TemperEntropy, EntropySource};

// Implement EntropySource for your hardware RNG
struct HardwareTrng; // Your STM32 TRNG, ESP32 RNG, etc.

impl EntropySource for HardwareTrng {
    fn name(&self) -> &str { "STM32-TRNG" }
    
    fn fill_entropy(&mut self, buf: &mut [u8]) -> Result<usize, EntropyError> {
        // Read from hardware RNG peripheral
        // ...
        Ok(buf.len())
    }
    
    fn is_available(&self) -> bool { true }
}

// Create entropy generator with custom source
let mut hw_rng = HardwareTrng;
let mut entropy = TemperEntropy::from_sources(&mut [&mut hw_rng])?;

// Generate random bytes
let random_u64 = entropy.next_u64();
```

---

## Security Properties

| Property | Guarantee | Hardness Assumption |
|----------|-----------|---------------------|
| **Entropy Prediction** | Computationally infeasible | ChaCha20 stream cipher security |
| **Signature Forgery** | Dual-scheme protection | ML-DSA (Module-LWE) AND SLH-DSA (hash-based) |
| **Content Tampering** | Detectable via BLAKE3 | 128-bit collision resistance |
| **Forward Secrecy** | Auto re-seed every 2²⁰ bytes | ChaCha20 one-way function |
| **Quantum Resistance** | Post-quantum signatures | FIPS 204 (ML-DSA-65) + FIPS 205 (SLH-DSA) |

### Hardness Assumptions

| Component | Algorithm | Security Basis |
|-----------|-----------|----------------|
| **Content Hash** | BLAKE3 | Collision resistance (128-bit) |
| **DRBG** | ChaCha20 | Stream cipher security (256-bit key) |
| **Primary Signature** | ML-DSA-65 | Module-LWE (NIST Level 3) |
| **Backup Signature** | SLH-DSA | Hash function security (SHA-256) |

**Defense-in-Depth:** Even if one signature scheme is broken (e.g., lattice cryptanalysis advances), the other remains secure.

---

## Dependencies

All dependencies are `no_std` compatible:

| Dependency | Version | Purpose | no_std Compatible |
|------------|---------|---------|-------------------|
| `blake3` | 1.x | Cryptographic hashing | ✅ |
| `rand_chacha` | 0.3 | ChaCha20 DRBG | ✅ |
| `rand_core` | 0.6 | RNG trait definitions | ✅ |
| `getrandom` | 0.2 | OS entropy (std only) | ⚠️ (std feature) |
| `serde` | 1.x | Serialization | ✅ (with alloc) |
| `serde_json` | 1.x | JSON encoding | ✅ (with alloc) |
| `spin` | 0.9 | Spinlock mutex | ✅ |
| `hex` | 0.4 | Hex encoding | ✅ (with alloc) |
| `zeroize` | 1.x | Secure memory clearing | ✅ |
| `derive_more` | 2.x | Error derive macros | ✅ |

---

## Build Commands

```bash
# Standard build (with std feature)
cargo build

# Embedded build (no_std with alloc only)
cargo build --no-default-features --features alloc

# Run all tests (requires std)
cargo test

# Run specific test module
cargo test --lib entropy_tests

# Check both configurations
cargo check --no-default-features --features alloc && cargo check
```

---

## Testing

Temper includes comprehensive statistical and cryptographic tests:

### Statistical Tests (Entropy)
1. **Uniqueness**: Zero collisions in 1M u64 samples (birthday bound: 10⁻⁷)
2. **Distribution**: Chi-squared test for uniform byte distribution (255 df, p=0.001)
3. **Avalanche**: Single bit flip changes ~50% of output bits (SAC)
4. **Autocorrelation**: Independence of sequential samples (|r| < 0.019)
5. **Re-seed Independence**: Uncorrelated state before/after re-seed
6. **Bit Balance**: Each bit position has equal probability
7. **Health Metrics**: Accurate tracking of internal counters

### Cryptographic Tests (Seal)
1. **Roundtrip**: Sign and verify produces valid=true (ignored until PQC wired)
2. **Tamper Detection**: Modified content invalidates seal (ignored)
3. **Key Isolation**: Wrong key rejects seal (ignored)
4. **Seal ID Determinism**: Same inputs produce same BLAKE3 ID ✅
5. **Serde Roundtrip**: Serialization preserves structure ✅
6. **Key ID Determinism**: BLAKE3(pk₁ || pk₂) is deterministic ✅

**Note:** Tests 1-3 for Seal are marked `#[ignore]` until ML-DSA and SLH-DSA primitives are wired. The protocol structure and binding logic are complete.

---

## Post-Quantum Cryptography Status

### Current Implementation
- ✅ Seal protocol structure (complete)
- ✅ Dual signature binding construction (complete)
- ✅ Verification logic (complete)
- ⚠️ PQC primitives (stubs with `todo!()`)

### To Wire
1. **ML-DSA-65** (FIPS 204): Use [ml-dsa](https://docs.rs/ml-dsa) from RustCrypto
   - Key sizes: sk=4032 bytes, pk=1952 bytes, sig=3309 bytes
2. **SLH-DSA** (FIPS 205): Use [slh-dsa](https://docs.rs/slh-dsa) from RustCrypto
   - Algorithm: SLH-DSA-SHA2-128s (small, fast)
   - Key sizes: sk=64 bytes, pk=32 bytes, sig=7856 bytes

Once wired, remove `#[ignore]` from seal tests 1-3.

---

## Roadmap

### v0.1.0 (Current)
- ✅ `no_std` compatible entropy generation
- ✅ Dual PQC signature protocol structure
- ✅ Statistical verification tests
- ⚠️ PQC primitives (stubs)

### v0.2.0 (Planned)
- [ ] ML-KEM-1024 hybrid key encapsulation (Envelope module)
- [ ] ChaCha20-Poly1305 authenticated encryption
- [ ] X25519 hybrid KEM

### v0.3.0 (Future)
- [ ] Key rotation protocol
- [ ] Multi-signature support (N-of-M threshold)
- [ ] Seal chaining (Merkle tree)
- [ ] Revocation mechanism

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please ensure:
- All code is `no_std` compatible
- Statistical tests pass (`cargo test`)
- Both build configurations work (`cargo check --no-default-features --features alloc && cargo check`)
- Follow the code style in `.github/copilot-instructions.md`

---

## Security Disclosure

For security vulnerabilities, please email: [security@sing-security.com](mailto:security@sing-security.com)

Do not open public issues for security-related matters.

---

## Acknowledgments

- **NIST**: Post-Quantum Cryptography Standardization (FIPS 204, 205)
- **RustCrypto**: Cryptographic primitives for Rust
- **BLAKE3 Team**: Fast, secure hashing
- **ChaCha20**: Daniel J. Bernstein's stream cipher

---

**Built with ❤️ for a quantum-safe future.**
