---
applyTo: "src/seal*.rs"
---

# Seal Module Instructions

## Overview

The Seal module implements a dual post-quantum signature protocol that binds a BLAKE3 content hash to two independent quantum-safe signatures (ML-DSA-65 and SLH-DSA). This provides defense-in-depth: even if one signature scheme is broken, the other remains secure.

## Cryptographic Protocol

### Binding Construction

```
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
     └────────┬───────┘
              │ Concatenate
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

### Verification Requirements

**ALL THREE checks must pass:**
1. `BLAKE3(content) == seal.content_hash` — Content integrity
2. `ML-DSA.Verify(pk₁, binding, σ₁) == true` — Primary signature (lattice-based)
3. `SLH-DSA.Verify(pk₂, binding, σ₂) == true` — Backup signature (hash-based)

If any check fails, the entire seal is invalid.

## Data Structures

### TemperKeypair

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemperKeypair {
    pub schema_version: u16,
    
    // ML-DSA-65 keys
    pub mldsa_secret_key: Vec<u8>,
    pub mldsa_public_key: Vec<u8>,
    
    // SLH-DSA keys
    pub slhdsa_secret_key: Vec<u8>,
    pub slhdsa_public_key: Vec<u8>,
    
    // Metadata
    pub signer_id: String,
    pub key_id: String,  // BLAKE3(mldsa_pk || slhdsa_pk)
}
```

**Key ID Computation:**
```rust
let mut hasher = blake3::Hasher::new();
hasher.update(&keypair.mldsa_public_key);
hasher.update(&keypair.slhdsa_public_key);
let key_id = hex::encode(hasher.finalize().as_bytes());
```

### Seal

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Seal {
    pub schema_version: u16,
    pub content_hash: String,  // Hex-encoded BLAKE3 hash
    pub primary: SignatureBlock,
    pub backup: SignatureBlock,
    pub context: SealContext,
    pub seal_id: String,  // BLAKE3(json(seal with empty seal_id))
}
```

### SignatureBlock

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureBlock {
    pub algorithm: String,  // "ML-DSA-65" or "SLH-DSA"
    pub signature: String,  // Hex-encoded signature bytes
    pub key_id: String,     // BLAKE3(public_key)
}
```

### SealContext

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealContext {
    pub domain: String,  // "Temper.Seal.v1"
    pub timestamp: String,  // ISO 8601
    pub signer_id: String,
    pub tool_version: String,  // e.g., "temper-0.1.0"
    pub metadata: BTreeMap<String, String>,  // User-provided, deterministic
}
```

**Important:** Use `BTreeMap` (not `HashMap`) for deterministic JSON serialization.

### VerifyResult

```rust
#[derive(Debug, Clone, Copy)]
pub struct VerifyResult {
    pub content_hash_valid: bool,
    pub primary_valid: bool,
    pub backup_valid: bool,
    pub valid: bool,  // true iff all three above are true
}
```

## Public API Functions

### 1. generate_keypair

```rust
pub fn generate_keypair(
    rng: &mut TemperEntropy,
    signer_id: &str
) -> Result<TemperKeypair>
```

**Process:**
1. Call `mldsa_keygen(rng)` → `(sk₁, pk₁)`
2. Call `slhdsa_keygen(rng)` → `(sk₂, pk₂)`
3. Compute `key_id = BLAKE3(pk₁ || pk₂)`
4. Return `TemperKeypair { schema_version: 1, ... }`

### 2. create_seal

```rust
pub fn create_seal(
    rng: &mut TemperEntropy,
    content: &[u8],
    keypair: &TemperKeypair,
    metadata: BTreeMap<String, String>
) -> Result<Seal>
```

**Process:**
1. Compute `content_hash = BLAKE3(content)`
2. Create `SealContext`:
   - `domain = "Temper.Seal.v1"`
   - `timestamp = current_time_iso8601()` (std only, or user-provided)
   - `signer_id = keypair.signer_id.clone()`
   - `tool_version = "temper-0.1.0"`
   - `metadata = metadata`
3. Construct binding:
   ```rust
   let binding = [
       hex::encode(content_hash.as_bytes()).as_bytes(),
       serde_json::to_vec(&context)?.as_slice()
   ].concat();
   ```
4. Sign:
   - `σ₁ = mldsa_sign(&keypair.mldsa_secret_key, &binding, rng)`
   - `σ₂ = slhdsa_sign(&keypair.slhdsa_secret_key, &binding, rng)`
5. Create signature blocks
6. Compute `seal_id`:
   ```rust
   let mut temp_seal = seal.clone();
   temp_seal.seal_id = String::new();
   let seal_json = serde_json::to_vec(&temp_seal)?;
   let seal_id = hex::encode(blake3::hash(&seal_json).as_bytes());
   ```
7. Return complete `Seal`

### 3. verify_seal

```rust
pub fn verify_seal(
    content: &[u8],
    seal: &Seal,
    mldsa_pk: &[u8],
    slhdsa_pk: &[u8]
) -> Result<VerifyResult>
```

**Process:**
1. Compute `actual_hash = BLAKE3(content)`
2. Check `content_hash_valid = (hex::encode(actual_hash) == seal.content_hash)`
3. Reconstruct binding (same as signing)
4. Verify primary:
   ```rust
   let primary_sig = hex::decode(&seal.primary.signature)?;
   let primary_valid = mldsa_verify(mldsa_pk, &binding, &primary_sig);
   ```
5. Verify backup:
   ```rust
   let backup_sig = hex::decode(&seal.backup.signature)?;
   let backup_valid = slhdsa_verify(slhdsa_pk, &binding, &backup_sig);
   ```
6. Return `VerifyResult`:
   ```rust
   VerifyResult {
       content_hash_valid,
       primary_valid,
       backup_valid,
       valid: content_hash_valid && primary_valid && backup_valid,
   }
   ```

## PQC Primitive Wrappers

**Current Status:** Stubs with `todo!()` placeholders.

### ML-DSA-65 (Lattice-based)

```rust
fn mldsa_keygen(rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!("Wire ML-DSA-65 from RustCrypto/signatures crate")
    // Use: https://docs.rs/ml-dsa
    // Algorithm: FIPS 204 ML-DSA-65
    // Key sizes: sk=4032 bytes, pk=1952 bytes, sig=3309 bytes
}

fn mldsa_sign(sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>> {
    todo!("Wire ML-DSA-65 signing")
}

fn mldsa_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    todo!("Wire ML-DSA-65 verification")
}
```

### SLH-DSA (Hash-based)

```rust
fn slhdsa_keygen(rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
    todo!("Wire SLH-DSA from RustCrypto/signatures crate")
    // Use: https://docs.rs/slh-dsa
    // Algorithm: FIPS 205 SLH-DSA-SHA2-128s (small, fast)
    // Key sizes: sk=64 bytes, pk=32 bytes, sig=7856 bytes
}

fn slhdsa_sign(sk: &[u8], message: &[u8], rng: &mut TemperEntropy) -> Result<Vec<u8>> {
    todo!("Wire SLH-DSA signing")
}

fn slhdsa_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    todo!("Wire SLH-DSA verification")
}
```

**Documentation Comment (include in seal.rs):**
```rust
//! # Post-Quantum Signature Primitives
//!
//! The following functions are stubs for integrating RustCrypto PQC libraries:
//! - ML-DSA: https://docs.rs/ml-dsa (FIPS 204, lattice-based)
//! - SLH-DSA: https://docs.rs/slh-dsa (FIPS 205, hash-based)
//!
//! These are currently `todo!()` to allow the rest of the crate to compile.
//! Seal tests 1-3 are marked `#[ignore]` until these are wired.
```

## Domain Separation

```rust
const DOMAIN_SEAL: &str = "Temper.Seal.v1";
```

Use this constant in `SealContext.domain` field.

## Security Theorem

**Claim:** Breaking a Temper seal requires:
1. Finding a BLAKE3 collision (preimage resistance), AND
2. Forging EITHER an ML-DSA signature (lattice hardness) OR an SLH-DSA signature (hash-based security)

**Hardness Assumptions:**
- BLAKE3 provides 128-bit collision resistance
- ML-DSA-65 relies on Module-LWE (NIST security level 3)
- SLH-DSA relies on hash function security (SHA-256 in this case)

These are **independent assumptions**. Quantum computers break ML-DSA's lattice assumption but NOT SLH-DSA's hash assumption.

## Testing Strategy

**Unit Tests (non-ignored):**
- Seal ID determinism
- Serde roundtrip
- Key ID determinism

**Integration Tests (ignored until PQC wired):**
- Seal roundtrip (sign + verify)
- Tamper detection
- Wrong key rejection

See `.github/instructions/testing.instructions.md` for test patterns.

## Common Pitfalls

❌ **DON'T:**
- Use `HashMap` for metadata — Must be `BTreeMap` for determinism
- Forget to check all three verification conditions
- Serialize timestamps without timezone (use ISO 8601 with 'Z')
- Hardcode `schema_version` — Use constant
- Mix up primary/backup signatures

✅ **DO:**
- Use `BTreeMap` for all key-value metadata
- Return `VerifyResult` with individual check results
- Include timezone in timestamps (`chrono` or manual "...Z")
- Define `const SCHEMA_VERSION: u16 = 1;` and reference it
- Document which signature is lattice-based vs. hash-based
- Zeroize secret keys after use (in `drop()` if needed)

## Integration Example

```rust
use temper::{TemperEntropy, generate_keypair, create_seal, verify_seal};
use alloc::collections::BTreeMap;

// Generate keys
let mut rng = TemperEntropy::new()?;
let keypair = generate_keypair(&mut rng, "alice@example.com")?;

// Create seal
let content = b"Secret document";
let mut metadata = BTreeMap::new();
metadata.insert("classification".into(), "TOP SECRET".into());
let seal = create_seal(&mut rng, content, &keypair, metadata)?;

// Verify seal
let result = verify_seal(
    content,
    &seal,
    &keypair.mldsa_public_key,
    &keypair.slhdsa_public_key
)?;

assert!(result.valid);
```

## Future Work (v0.2.0+)

- Key rotation protocol
- Multi-signature support (N-of-M threshold)
- Seal chaining (linking seals in a Merkle tree)
- Revocation via CRL or OCSP-style checks

## References

- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- NIST Post-Quantum Cryptography Standardization
- "Multiple Signature Schemes: A New Approach to Joint Security" (Koblitz & Menezes)
