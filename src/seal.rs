//! Dual post-quantum signature protocol (ML-DSA-65 + SLH-DSA).
//!
//! The Seal binds a BLAKE3 content hash to two independent quantum-safe signatures,
//! providing defense-in-depth against cryptanalytic breakthroughs.
//!
//! # Protocol
//!
//! 1. `content_hash = BLAKE3(message)` — 256-bit
//! 2. `context = SealContext { domain, timestamp, signer_id, ... }`
//! 3. `binding = hex(content_hash) || json(context)`
//! 4. `σ₁ = ML-DSA-65.Sign(sk₁, binding)` — lattice-based
//! 5. `σ₂ = SLH-DSA.Sign(sk₂, binding)` — hash-based
//!
//! # Verification
//!
//! ALL three checks must pass:
//! - `BLAKE3(content) == seal.content_hash`
//! - `ML-DSA.Verify(pk₁, binding, σ₁)`
//! - `SLH-DSA.Verify(pk₂, binding, σ₂)`

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(feature = "alloc")]
use alloc::format;

use core::convert::TryFrom;

use ml_dsa::signature::{Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{EncodedVerifyingKey as MlEncodedVerifyingKey, KeyGen, MlDsa65};
use slh_dsa::signature::{Keypair as SlhKeypair, Signer as SlhSigner, Verifier as SlhVerifier};
use slh_dsa::Sha2_128s;
use zeroize::Zeroize;

use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};
use rand_core::RngCore;

// region:    --- Constants

/// Schema version for all seal structures.
const SCHEMA_VERSION: u16 = 1;

/// Domain separation string for seal protocol.
const DOMAIN_SEAL: &str = "Temper.Seal.v1";

/// Tool version string.
const TOOL_VERSION: &str = "temper-0.1.0";

// endregion: --- Constants

// region:    --- Data Structures

/// Temper keypair containing both ML-DSA-65 and SLH-DSA keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemperKeypair {
    /// Schema version for future compatibility.
    pub schema_version: u16,

    // ML-DSA-65 keys
    /// ML-DSA-65 secret key.
    pub mldsa_secret_key: Vec<u8>,
    /// ML-DSA-65 public key.
    pub mldsa_public_key: Vec<u8>,

    // SLH-DSA keys
    /// SLH-DSA secret key.
    pub slhdsa_secret_key: Vec<u8>,
    /// SLH-DSA public key.
    pub slhdsa_public_key: Vec<u8>,

    // Metadata
    /// Human-readable signer identifier.
    pub signer_id: String,
    /// BLAKE3(mldsa_pk || slhdsa_pk) as hex.
    pub key_id: String,
}

impl Drop for TemperKeypair {
    fn drop(&mut self) {
        self.mldsa_secret_key.zeroize();
        self.slhdsa_secret_key.zeroize();
    }
}

/// Complete seal binding a content hash to dual quantum-safe signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Seal {
    /// Schema version for future compatibility.
    pub schema_version: u16,

    /// BLAKE3 hash of the content (hex-encoded).
    pub content_hash: String,

    /// Primary signature (ML-DSA-65).
    pub primary: SignatureBlock,

    /// Backup signature (SLH-DSA).
    pub backup: SignatureBlock,

    /// Context information for the seal.
    pub context: SealContext,

    /// BLAKE3(json(seal with empty seal_id)) as hex.
    pub seal_id: String,
}

/// A single signature with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureBlock {
    /// Algorithm name (e.g., "ML-DSA-65", "SLH-DSA").
    pub algorithm: String,

    /// Hex-encoded signature bytes.
    pub signature: String,

    /// BLAKE3(public_key) as hex.
    pub key_id: String,
}

/// Context information for a seal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealContext {
    /// Domain separation string.
    pub domain: String,

    /// ISO 8601 timestamp (e.g., "2024-01-01T00:00:00Z").
    pub timestamp: String,

    /// Signer identifier.
    pub signer_id: String,

    /// Tool version string.
    pub tool_version: String,

    /// User-provided metadata (must be BTreeMap for determinism).
    pub metadata: BTreeMap<String, String>,
}

/// Result of seal verification.
#[derive(Debug, Clone, Copy)]
pub struct VerifyResult {
    /// Content hash matches.
    pub content_hash_valid: bool,

    /// Primary signature (ML-DSA-65) is valid.
    pub primary_valid: bool,

    /// Backup signature (SLH-DSA) is valid.
    pub backup_valid: bool,

    /// All checks passed (true iff all three above are true).
    pub valid: bool,
}

// endregion: --- Data Structures

// region:    --- Post-Quantum Signature Primitives

// # Post-Quantum Signature Primitives
//
// The following functions are stubs for integrating RustCrypto PQC libraries:
// - ML-DSA: https://docs.rs/ml-dsa (FIPS 204, lattice-based)
// - SLH-DSA: https://docs.rs/slh-dsa (FIPS 205, hash-based)
//
// These are currently `todo!()` to allow the rest of the crate to compile.
// Seal tests 1-3 are marked `#[ignore]` until these are wired.

/// Generate ML-DSA-65 keypair.
///
/// # Algorithm
///
/// FIPS 204 ML-DSA-65 (lattice-based, NIST security level 3)
///
/// # Key Sizes
///
/// - Secret key: 4032 bytes
/// - Public key: 1952 bytes
/// - Signature: 3309 bytes
fn mldsa_keygen(rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut seed_bytes = [0u8; 32];
    rng.fill_bytes(&mut seed_bytes);

    let seed = ml_dsa::Seed::from(seed_bytes);
    let keypair = MlDsa65::from_seed(&seed);
    let pk = keypair.verifying_key().encode().as_slice().to_vec();
    let sk = seed.as_slice().to_vec();

    seed_bytes.zeroize();

    Ok((sk, pk))
}

/// Sign a message with ML-DSA-65.
fn mldsa_sign(sk: &[u8], message: &[u8], _rng: &mut TemperEntropy) -> Result<Vec<u8>> {
    let seed = ml_dsa::Seed::try_from(sk)
        .map_err(|_| Error::CryptoError("Invalid ML-DSA-65 seed".to_string()))?;
    let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
    let signature = MlSigner::try_sign(&signing_key, message)
        .map_err(|_| Error::CryptoError("ML-DSA-65 signing failed".to_string()))?;
    Ok(signature.encode().as_slice().to_vec())
}

/// Verify an ML-DSA-65 signature.
fn mldsa_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let encoded_pk = match MlEncodedVerifyingKey::<MlDsa65>::try_from(pk) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded_pk);
    let signature = match ml_dsa::Signature::<MlDsa65>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    MlVerifier::verify(&verifying_key, message, &signature).is_ok()
}

/// Generate SLH-DSA keypair.
///
/// # Algorithm
///
/// FIPS 205 SLH-DSA-SHA2-128s (hash-based, small signatures, fast)
///
/// # Key Sizes
///
/// - Secret key: 64 bytes
/// - Public key: 32 bytes
/// - Signature: 7856 bytes
fn slhdsa_keygen(rng: &mut TemperEntropy) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut sk_seed = [0u8; 16];
    let mut sk_prf = [0u8; 16];
    let mut pk_seed = [0u8; 16];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    let signing_key =
        slh_dsa::SigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let sk = signing_key.to_bytes().as_slice().to_vec();
    let pk = signing_key.verifying_key().to_bytes().as_slice().to_vec();

    sk_seed.zeroize();
    sk_prf.zeroize();
    pk_seed.zeroize();

    Ok((sk, pk))
}

/// Sign a message with SLH-DSA.
fn slhdsa_sign(sk: &[u8], message: &[u8], _rng: &mut TemperEntropy) -> Result<Vec<u8>> {
    let signing_key = slh_dsa::SigningKey::<Sha2_128s>::try_from(sk)
        .map_err(|_| Error::CryptoError("Invalid SLH-DSA signing key".to_string()))?;
    let signature = SlhSigner::try_sign(&signing_key, message)
        .map_err(|_| Error::CryptoError("SLH-DSA signing failed".to_string()))?;
    Ok(signature.to_bytes().as_slice().to_vec())
}

/// Verify an SLH-DSA signature.
fn slhdsa_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let verifying_key = match slh_dsa::VerifyingKey::<Sha2_128s>::try_from(pk) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match slh_dsa::Signature::<Sha2_128s>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    SlhVerifier::verify(&verifying_key, message, &signature).is_ok()
}

// endregion: --- Post-Quantum Signature Primitives

// region:    --- Public API

/// Generate a new Temper keypair.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `signer_id` - Human-readable identifier for the signer
///
/// # Returns
///
/// A new `TemperKeypair` containing both ML-DSA-65 and SLH-DSA keys.
pub fn generate_keypair(rng: &mut TemperEntropy, signer_id: &str) -> Result<TemperKeypair> {
    // Generate ML-DSA-65 keypair
    let (mldsa_sk, mldsa_pk) = mldsa_keygen(rng)?;

    // Generate SLH-DSA keypair
    let (slhdsa_sk, slhdsa_pk) = slhdsa_keygen(rng)?;

    // Compute key ID: BLAKE3(mldsa_pk || slhdsa_pk)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&mldsa_pk);
    hasher.update(&slhdsa_pk);
    let key_id = hex::encode(hasher.finalize().as_bytes());

    Ok(TemperKeypair {
        schema_version: SCHEMA_VERSION,
        mldsa_secret_key: mldsa_sk,
        mldsa_public_key: mldsa_pk,
        slhdsa_secret_key: slhdsa_sk,
        slhdsa_public_key: slhdsa_pk,
        signer_id: signer_id.to_string(),
        key_id,
    })
}

/// Create a seal for content.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `content` - The content to seal
/// * `keypair` - The keypair to sign with
/// * `metadata` - User-provided metadata (must be BTreeMap)
///
/// # Returns
///
/// A complete `Seal` with dual quantum-safe signatures.
pub fn create_seal(
    rng: &mut TemperEntropy,
    content: &[u8],
    keypair: &TemperKeypair,
    metadata: BTreeMap<String, String>,
) -> Result<Seal> {
    // Compute content hash
    let content_hash_bytes = blake3::hash(content);
    let content_hash = hex::encode(content_hash_bytes.as_bytes());

    // Create context
    let timestamp = current_timestamp();
    let context = SealContext {
        domain: DOMAIN_SEAL.to_string(),
        timestamp,
        signer_id: keypair.signer_id.clone(),
        tool_version: TOOL_VERSION.to_string(),
        metadata,
    };

    // Construct binding: hex(content_hash) || json(context)
    let context_json = serde_json::to_vec(&context)
        .map_err(|e| Error::Serialization(format!("Failed to serialize context: {}", e)))?;

    let mut binding = Vec::new();
    binding.extend_from_slice(content_hash.as_bytes());
    binding.extend_from_slice(&context_json);

    // Sign with ML-DSA-65 (primary)
    let primary_sig = mldsa_sign(&keypair.mldsa_secret_key, &binding, rng)?;
    let primary_key_id = hex::encode(blake3::hash(&keypair.mldsa_public_key).as_bytes());
    let primary = SignatureBlock {
        algorithm: "ML-DSA-65".to_string(),
        signature: hex::encode(&primary_sig),
        key_id: primary_key_id,
    };

    // Sign with SLH-DSA (backup)
    let backup_sig = slhdsa_sign(&keypair.slhdsa_secret_key, &binding, rng)?;
    let backup_key_id = hex::encode(blake3::hash(&keypair.slhdsa_public_key).as_bytes());
    let backup = SignatureBlock {
        algorithm: "SLH-DSA".to_string(),
        signature: hex::encode(&backup_sig),
        key_id: backup_key_id,
    };

    // Compute seal ID
    let temp_seal = Seal {
        schema_version: SCHEMA_VERSION,
        content_hash: content_hash.clone(),
        primary: primary.clone(),
        backup: backup.clone(),
        context: context.clone(),
        seal_id: String::new(), // Empty for seal_id computation
    };

    let seal_json = serde_json::to_vec(&temp_seal)
        .map_err(|e| Error::Serialization(format!("Failed to serialize seal: {}", e)))?;
    let seal_id = hex::encode(blake3::hash(&seal_json).as_bytes());

    // Return complete seal
    Ok(Seal {
        schema_version: SCHEMA_VERSION,
        content_hash,
        primary,
        backup,
        context,
        seal_id,
    })
}

/// Verify a seal.
///
/// # Arguments
///
/// * `content` - The content that was sealed
/// * `seal` - The seal to verify
/// * `mldsa_pk` - ML-DSA-65 public key
/// * `slhdsa_pk` - SLH-DSA public key
///
/// # Returns
///
/// `VerifyResult` with individual check results and overall validity.
pub fn verify_seal(
    content: &[u8],
    seal: &Seal,
    mldsa_pk: &[u8],
    slhdsa_pk: &[u8],
) -> Result<VerifyResult> {
    // Check content hash
    let actual_hash_bytes = blake3::hash(content);
    let actual_hash = hex::encode(actual_hash_bytes.as_bytes());
    let content_hash_valid = actual_hash == seal.content_hash;

    // Reconstruct binding
    let context_json = serde_json::to_vec(&seal.context)
        .map_err(|e| Error::Serialization(format!("Failed to serialize context: {}", e)))?;

    let mut binding = Vec::new();
    binding.extend_from_slice(seal.content_hash.as_bytes());
    binding.extend_from_slice(&context_json);

    // Verify primary signature (ML-DSA-65)
    let primary_sig_bytes = hex::decode(&seal.primary.signature)
        .map_err(|e| Error::InvalidSignature(format!("Invalid primary signature hex: {}", e)))?;
    let primary_valid = mldsa_verify(mldsa_pk, &binding, &primary_sig_bytes);

    // Verify backup signature (SLH-DSA)
    let backup_sig_bytes = hex::decode(&seal.backup.signature)
        .map_err(|e| Error::InvalidSignature(format!("Invalid backup signature hex: {}", e)))?;
    let backup_valid = slhdsa_verify(slhdsa_pk, &binding, &backup_sig_bytes);

    // Overall validity requires all three checks to pass
    let valid = content_hash_valid && primary_valid && backup_valid;

    Ok(VerifyResult {
        content_hash_valid,
        primary_valid,
        backup_valid,
        valid,
    })
}

// endregion: --- Public API

// region:    --- Helper Functions

/// Get current timestamp (std) or placeholder (no_std).
fn current_timestamp() -> String {
    #[cfg(feature = "std")]
    {
        use std::time::SystemTime;
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => {
                // Format as ISO 8601 (simplified)
                let secs = duration.as_secs();
                format!("{}-01-01T00:00:00Z", 1970 + secs / 31557600) // Approximate year
            }
            Err(_) => "1970-01-01T00:00:00Z".to_string(),
        }
    }

    #[cfg(not(feature = "std"))]
    {
        // In no_std, user should provide timestamp via metadata
        "0000-00-00T00:00:00Z".to_string()
    }
}

// endregion: --- Helper Functions
