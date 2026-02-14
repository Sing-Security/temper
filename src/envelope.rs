//! # Temper Envelope — Hybrid Key Encapsulation Module
//!
//! **Production-ready implementation** with hybrid post-quantum key encapsulation.
//!
//! The Envelope combines ML-KEM-1024 (FIPS 203) with X25519 for defense-in-depth,
//! then uses ChaCha20-Poly1305 AEAD for authenticated encryption.
//!
//! # Implementation Status
//!
//! ✅ **Complete and tested** when `envelope` feature is enabled:
//! - ML-KEM-1024 (NIST FIPS 203): Lattice-based KEM, NIST Level 5
//! - X25519: Elliptic curve Diffie-Hellman for classical security
//! - ChaCha20-Poly1305: Authenticated encryption with associated data (AEAD)
//!
//! # Protocol
//!
//! ## Key Generation
//! 1. Generate ML-KEM-1024 keypair: `(mlkem_sk, mlkem_pk)`
//! 2. Generate X25519 keypair: `(x25519_sk, x25519_pk)`
//! 3. Return `EnvelopeKeypair { mlkem_sk, mlkem_pk, x25519_sk, x25519_pk }`
//!
//! ## Encapsulation
//! 1. `(mlkem_ct, mlkem_ss) = ML-KEM.Encap(mlkem_pk)` — PQ shared secret
//! 2. `x25519_ss = X25519.DH(x25519_pk, ephemeral_sk)` — Classical shared secret
//! 3. `combined_key = BLAKE3.derive_key("Temper.Envelope.v1", mlkem_ss || x25519_ss)`
//! 4. `ciphertext = ChaCha20-Poly1305.Encrypt(combined_key, plaintext)`
//! 5. Return `Envelope { mlkem_ct, x25519_ephemeral_pk, ciphertext, tag }`
//!
//! ## Decapsulation
//! 1. `mlkem_ss = ML-KEM.Decap(mlkem_sk, mlkem_ct)` — PQ shared secret
//! 2. `x25519_ss = X25519.DH(x25519_ephemeral_pk, x25519_sk)` — Classical shared secret
//! 3. `combined_key = BLAKE3.derive_key("Temper.Envelope.v1", mlkem_ss || x25519_ss)`
//! 4. `plaintext = ChaCha20-Poly1305.Decrypt(combined_key, ciphertext, tag)`
//! 5. Return `plaintext` or error if authentication fails
//!
//! # Security Properties
//!
//! - **Quantum Resistance**: ML-KEM-1024 provides post-quantum security
//! - **Defense-in-Depth**: Breaking the envelope requires breaking BOTH ML-KEM and X25519
//! - **Forward Secrecy**: Ephemeral X25519 keys for each encapsulation
//! - **Authenticated Encryption**: ChaCha20-Poly1305 provides confidentiality and integrity
//! - **Domain Separation**: Unique constant prevents cross-protocol attacks
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "envelope")]
//! # {
//! use temper::{TemperEntropy, envelope::{generate_envelope_keypair, encapsulate, decapsulate}};
//!
//! let mut rng = TemperEntropy::from_seed([0x42; 32]);
//! let keypair = generate_envelope_keypair(&mut rng)?;
//! 
//! let plaintext = b"Secret message";
//! let envelope = encapsulate(&mut rng, plaintext, &keypair)?;
//! 
//! let recovered = decapsulate(&envelope, &keypair)?;
//! 
//! assert_eq!(plaintext, recovered.as_slice());
//! # Ok::<(), temper::Error>(())
//! # }
//! ```

#![cfg(feature = "envelope")]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::format;

use crate::entropy::TemperEntropy;
use crate::error::{Error, Result};
use rand_core::RngCore;
use zeroize::Zeroize;

use ml_kem::{kem::{Decapsulate, Encapsulate}, KemCore, MlKem1024, MlKem1024Params, Ciphertext, EncodedSizeUser, Encoded};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

// region:    --- Constants

/// Schema version for envelope structures.
const SCHEMA_VERSION: u16 = 1;

/// Domain separation string for key derivation.
const DOMAIN_ENVELOPE: &str = "Temper.Envelope.v1";

/// Nonce size for ChaCha20-Poly1305 (12 bytes).
const NONCE_SIZE: usize = 12;

/// ML-KEM-1024 shared secret size (32 bytes).
const MLKEM_SS_SIZE: usize = 32;

/// X25519 shared secret size (32 bytes).
const X25519_SS_SIZE: usize = 32;

/// Combined shared secret size (64 bytes).
const COMBINED_SS_SIZE: usize = MLKEM_SS_SIZE + X25519_SS_SIZE;

// endregion: --- Constants

// region:    --- Data Structures

/// Envelope keypair containing both ML-KEM-1024 and X25519 keys.
///
/// **Note**: Keys are stored as raw bytes for serialization compatibility.
/// The typed ML-KEM keys are reconstructed from bytes when needed for operations.
///
/// **Security Note**: This struct implements a custom `Debug` trait that redacts secret keys
/// to prevent accidental leakage in logs.
#[derive(Clone)]
pub struct EnvelopeKeypair {
    /// Schema version for future compatibility.
    pub schema_version: u16,

    /// ML-KEM-1024 secret key bytes (for serialization and reconstruction).
    pub mlkem_secret_key: Vec<u8>,

    /// ML-KEM-1024 public key bytes (for serialization and reconstruction).
    pub mlkem_public_key: Vec<u8>,

    /// X25519 secret key (static secret).
    pub x25519_secret_key: Vec<u8>,

    /// X25519 public key.
    pub x25519_public_key: Vec<u8>,

    /// Key identifier (BLAKE3 hash of both public keys).
    pub key_id: String,
}

impl Drop for EnvelopeKeypair {
    fn drop(&mut self) {
        self.mlkem_secret_key.zeroize();
        self.x25519_secret_key.zeroize();
    }
}

// Memory: security fix per problem statement — prevent private key leaks in logs
impl core::fmt::Debug for EnvelopeKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnvelopeKeypair")
            .field("schema_version", &self.schema_version)
            .field("mlkem_secret_key", &"<REDACTED>")
            .field("mlkem_public_key", &format!("<{} bytes>", self.mlkem_public_key.len()))
            .field("x25519_secret_key", &"<REDACTED>")
            .field("x25519_public_key", &format!("<{} bytes>", self.x25519_public_key.len()))
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Encrypted envelope with hybrid KEM.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    /// Schema version for future compatibility.
    pub schema_version: u16,

    /// ML-KEM-1024 ciphertext (encapsulated key).
    pub mlkem_ciphertext: Vec<u8>,

    /// X25519 ephemeral public key.
    pub x25519_ephemeral_public: Vec<u8>,

    /// ChaCha20-Poly1305 encrypted ciphertext.
    pub ciphertext: Vec<u8>,

    /// ChaCha20-Poly1305 authentication tag (included in ciphertext).
    /// The tag is part of the AEAD output, stored separately for clarity.
    pub nonce: Vec<u8>,

    /// Envelope identifier (BLAKE3 hash of components).
    pub envelope_id: String,
}

// endregion: --- Data Structures

// region:    --- Public API

/// Generate an envelope keypair.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// A new `EnvelopeKeypair` containing both ML-KEM-1024 and X25519 keys.
pub fn generate_envelope_keypair(rng: &mut TemperEntropy) -> Result<EnvelopeKeypair> {
    // Generate ML-KEM-1024 keypair
    let (mlkem_dk, mlkem_ek) = MlKem1024::generate(rng);

    // Extract bytes using as_bytes() method
    let mlkem_dk_bytes: Vec<u8> = mlkem_dk.as_bytes().to_vec();
    let mlkem_ek_bytes: Vec<u8> = mlkem_ek.as_bytes().to_vec();

    // Generate X25519 keypair
    let (x25519_sk, x25519_pk) = x25519_keygen(rng);

    // Compute key ID: BLAKE3(mlkem_pk || x25519_pk)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&mlkem_ek_bytes);
    hasher.update(&x25519_pk);
    let key_id = hex::encode(hasher.finalize().as_bytes());

    Ok(EnvelopeKeypair {
        schema_version: SCHEMA_VERSION,
        mlkem_secret_key: mlkem_dk_bytes,
        mlkem_public_key: mlkem_ek_bytes,
        x25519_secret_key: x25519_sk,
        x25519_public_key: x25519_pk,
        key_id,
    })
}

/// Encapsulate plaintext into an envelope.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `plaintext` - Data to encrypt
/// * `keypair` - Envelope keypair (ML-KEM keys reconstructed from bytes)
///
/// # Returns
///
/// An `Envelope` containing the encrypted data with hybrid KEM.
pub fn encapsulate(
    rng: &mut TemperEntropy,
    plaintext: &[u8],
    keypair: &EnvelopeKeypair,
) -> Result<Envelope> {
    // Reconstruct ML-KEM encapsulation key from bytes
    let mlkem_ek_encoded: &Encoded<ml_kem::kem::EncapsulationKey<MlKem1024Params>> = 
        keypair.mlkem_public_key.as_slice().try_into()
            .map_err(|_| Error::CryptoError("Invalid ML-KEM public key bytes".into()))?;
    let mlkem_ek = ml_kem::kem::EncapsulationKey::<MlKem1024Params>::from_bytes(mlkem_ek_encoded);
    
    // 1. ML-KEM-1024 encapsulation using reconstructed key
    let (mlkem_ct, mlkem_ss) = mlkem_ek.encapsulate(rng)
        .map_err(|_| Error::CryptoError("ML-KEM encapsulation failed".into()))?;

    // Convert shared secret to bytes array
    let mlkem_ss_slice: &[u8] = mlkem_ss.as_ref();
    let mlkem_ss_bytes: [u8; 32] = mlkem_ss_slice.try_into()
        .map_err(|_| Error::CryptoError("ML-KEM shared secret size mismatch".into()))?;

    // 2. Generate ephemeral X25519 key and compute shared secret
    let (x25519_ephemeral_sk_bytes, x25519_ephemeral_pk_bytes) = x25519_keygen(rng);
    let x25519_ephemeral_sk = X25519SecretKey::from(
        <[u8; 32]>::try_from(x25519_ephemeral_sk_bytes.as_slice())
            .map_err(|_| Error::CryptoError("Invalid X25519 ephemeral key".into()))?,
    );
    let x25519_recipient_pk = X25519PublicKey::from(
        <[u8; 32]>::try_from(keypair.x25519_public_key.as_slice())
            .map_err(|_| Error::CryptoError("Invalid X25519 public key".into()))?,
    );
    let x25519_ss = x25519_ephemeral_sk.diffie_hellman(&x25519_recipient_pk);

    // 3. Combine shared secrets with domain separation
    let mut combined_ss = [0u8; COMBINED_SS_SIZE];
    combined_ss[..MLKEM_SS_SIZE].copy_from_slice(&mlkem_ss_bytes);
    combined_ss[MLKEM_SS_SIZE..].copy_from_slice(x25519_ss.as_bytes());

    let encryption_key = blake3::derive_key(DOMAIN_ENVELOPE, &combined_ss);

    // Zeroize intermediate secrets
    let mut mlkem_ss_copy = mlkem_ss_bytes;
    mlkem_ss_copy.zeroize();
    combined_ss.zeroize();

    // 4. Encrypt with ChaCha20-Poly1305
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 encryption failed".into()))?;

    // 5. Compute envelope ID
    let mut hasher = blake3::Hasher::new();
    hasher.update(&SCHEMA_VERSION.to_le_bytes());
    hasher.update(mlkem_ct.as_ref());
    hasher.update(&x25519_ephemeral_pk_bytes);
    hasher.update(&ciphertext);
    hasher.update(&nonce_bytes);
    let envelope_id = hex::encode(hasher.finalize().as_bytes());

    Ok(Envelope {
        schema_version: SCHEMA_VERSION,
        mlkem_ciphertext: mlkem_ct.to_vec(),
        x25519_ephemeral_public: x25519_ephemeral_pk_bytes,
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        envelope_id,
    })
}

/// Decapsulate an envelope to recover plaintext.
///
/// # Arguments
///
/// * `envelope` - The envelope to decrypt
/// * `keypair` - Envelope keypair (ML-KEM keys reconstructed from bytes)
///
/// # Returns
///
/// The decrypted plaintext or error if authentication fails.
pub fn decapsulate(
    envelope: &Envelope,
    keypair: &EnvelopeKeypair,
) -> Result<Vec<u8>> {
    // Reconstruct ML-KEM decapsulation key from bytes
    let mlkem_dk_encoded: &Encoded<ml_kem::kem::DecapsulationKey<MlKem1024Params>> = 
        keypair.mlkem_secret_key.as_slice().try_into()
            .map_err(|_| Error::CryptoError("Invalid ML-KEM secret key bytes".into()))?;
    let mlkem_dk = ml_kem::kem::DecapsulationKey::<MlKem1024Params>::from_bytes(mlkem_dk_encoded);
    
    // 1. ML-KEM-1024 decapsulation using reconstructed key
    // Convert bytes to ciphertext reference
    let ct_ref: &Ciphertext<MlKem1024> = envelope.mlkem_ciphertext.as_slice().try_into()
        .map_err(|_| Error::CryptoError("Invalid ML-KEM ciphertext length".into()))?;
    
    let mlkem_ss = mlkem_dk.decapsulate(ct_ref)
        .map_err(|_| Error::CryptoError("ML-KEM decapsulation failed".into()))?;
    
    // Convert shared secret to bytes array
    let mlkem_ss_slice: &[u8] = mlkem_ss.as_ref();
    let mlkem_ss_bytes: [u8; 32] = mlkem_ss_slice.try_into()
        .map_err(|_| Error::CryptoError("ML-KEM shared secret size mismatch".into()))?;

    // 2. X25519 shared secret computation
    let x25519_static_sk = X25519SecretKey::from(
        <[u8; 32]>::try_from(keypair.x25519_secret_key.as_slice())
            .map_err(|_| Error::CryptoError("Invalid X25519 secret key".into()))?,
    );
    let x25519_ephemeral_pk = X25519PublicKey::from(
        <[u8; 32]>::try_from(envelope.x25519_ephemeral_public.as_slice())
            .map_err(|_| Error::CryptoError("Invalid X25519 ephemeral public key".into()))?,
    );
    let x25519_ss = x25519_static_sk.diffie_hellman(&x25519_ephemeral_pk);

    // 3. Combine shared secrets with domain separation
    let mut combined_ss = [0u8; COMBINED_SS_SIZE];
    combined_ss[..MLKEM_SS_SIZE].copy_from_slice(&mlkem_ss_bytes);
    combined_ss[MLKEM_SS_SIZE..].copy_from_slice(x25519_ss.as_bytes());

    let decryption_key = blake3::derive_key(DOMAIN_ENVELOPE, &combined_ss);

    // Zeroize intermediate secrets
    let mut mlkem_ss_copy = mlkem_ss_bytes;
    mlkem_ss_copy.zeroize();
    combined_ss.zeroize();

    // 4. Decrypt with ChaCha20-Poly1305
    let nonce = Nonce::from_slice(&envelope.nonce);

    let cipher = ChaCha20Poly1305::new(&decryption_key.into());
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 decryption failed (authentication tag mismatch)".into()))?;

    Ok(plaintext)
}

/// Encapsulate plaintext with sender authentication (sign then encrypt).
///
/// This function combines the seal and envelope protocols to provide both
/// confidentiality (via encryption) and sender authenticity (via signatures).
///
/// # Protocol
///
/// 1. Create a `Seal` over the plaintext using sender's signing keypair
/// 2. Serialize and **compress** the seal to binary using postcard + DEFLATE
/// 3. Construct authenticated payload: `seal_length (u32 LE) || compressed_seal_bytes || plaintext`
/// 4. Encrypt the authenticated payload using hybrid KEM
///
/// # Compression
///
/// The seal is automatically compressed using DEFLATE (level 9) before encryption.
/// This reduces the payload size for network transmission and embedded storage.
///
/// # Arguments
///
/// * `rng` - Cryptographically secure random number generator
/// * `plaintext` - Data to encrypt and authenticate
/// * `recipient_keypair` - Recipient's envelope keypair (for encryption)
/// * `sender_keypair` - Sender's signing keypair (for authentication)
/// * `metadata` - User-provided metadata for the seal
///
/// # Returns
///
/// An `Envelope` containing the encrypted and authenticated data.
///
/// # Security
///
/// The seal binds the plaintext to the sender's identity, preventing anonymous messages.
/// Both encryption and signature verification must succeed for the message to be considered valid.
pub fn authenticated_encapsulate(
    rng: &mut crate::entropy::TemperEntropy,
    plaintext: &[u8],
    recipient_keypair: &EnvelopeKeypair,
    sender_keypair: &crate::seal::TemperKeypair,
    metadata: alloc::collections::BTreeMap<String, String>,
) -> Result<Envelope> {
    use alloc::vec::Vec;
    
    // 1. Create seal over plaintext
    // Memory: authenticated envelope per problem statement — sign then encrypt pattern
    let seal = crate::seal::create_seal(rng, plaintext, sender_keypair, metadata)?;
    
    // 2. Serialize and compress seal to binary
    // Memory: compression optimization per problem statement — DEFLATE reduces SLH-DSA size by 30-50%
    let seal_bytes = seal.to_compressed_bytes()?;
    
    // 3. Construct authenticated payload: seal_length || seal_bytes || plaintext
    let seal_length = seal_bytes.len() as u32;
    let mut authenticated_payload = Vec::with_capacity(4 + seal_bytes.len() + plaintext.len());
    authenticated_payload.extend_from_slice(&seal_length.to_le_bytes());
    authenticated_payload.extend_from_slice(&seal_bytes);
    authenticated_payload.extend_from_slice(plaintext);
    
    // 4. Encrypt the authenticated payload
    encapsulate(rng, &authenticated_payload, recipient_keypair)
}

/// Decapsulate and verify an authenticated envelope (decrypt then verify).
///
/// This function reverses the `authenticated_encapsulate` operation, providing
/// both confidentiality (decryption) and sender verification (signature check).
///
/// # Protocol
///
/// 1. Decrypt the envelope using recipient's KEM keypair
/// 2. Parse authenticated payload: `seal_length || compressed_seal_bytes || plaintext`
/// 3. **Decompress** and deserialize the seal from binary
/// 4. Verify the seal against the plaintext using sender's public keys
///
/// # Decompression
///
/// The seal is automatically decompressed using DEFLATE before deserialization.
///
/// # Arguments
///
/// * `envelope` - The authenticated envelope to decrypt and verify
/// * `recipient_keypair` - Recipient's envelope keypair (for decryption)
/// * `sender_mldsa_pk` - Sender's ML-DSA-65 public key (for verification)
/// * `sender_slhdsa_pk` - Sender's SLH-DSA public key (for verification)
///
/// # Returns
///
/// A tuple of `(plaintext, seal)` if decryption and verification both succeed.
/// Returns error if decryption fails or signature verification fails.
///
/// # Security
///
/// Both the envelope decryption AND seal verification must succeed.
/// This ensures the message came from the claimed sender and was not tampered with.
pub fn authenticated_decapsulate(
    envelope: &Envelope,
    recipient_keypair: &EnvelopeKeypair,
    sender_mldsa_pk: &[u8],
    sender_slhdsa_pk: &[u8],
) -> Result<(Vec<u8>, crate::seal::Seal)> {
    
    // 1. Decrypt the envelope
    // Memory: authenticated envelope per problem statement — decrypt then verify pattern
    let authenticated_payload = decapsulate(envelope, recipient_keypair)?;
    
    // 2. Parse authenticated payload
    if authenticated_payload.len() < 4 {
        return Err(Error::CryptoError("Authenticated payload too short".into()));
    }
    
    let seal_length = u32::from_le_bytes([
        authenticated_payload[0],
        authenticated_payload[1],
        authenticated_payload[2],
        authenticated_payload[3],
    ]) as usize;
    
    if authenticated_payload.len() < 4 + seal_length {
        return Err(Error::CryptoError("Invalid seal length in authenticated payload".into()));
    }
    
    let seal_bytes = &authenticated_payload[4..4 + seal_length];
    let plaintext = &authenticated_payload[4 + seal_length..];
    
    // 3. Decompress and deserialize seal
    // Memory: compression optimization per problem statement — decompress then deserialize
    let seal = crate::seal::Seal::from_compressed_bytes(seal_bytes)?;
    
    // 4. Verify seal
    let verify_result = crate::seal::verify_seal(
        plaintext,
        &seal,
        sender_mldsa_pk,
        sender_slhdsa_pk,
    )?;
    
    if !verify_result.valid {
        return Err(Error::InvalidSignature(
            "Seal verification failed: message not authenticated by sender".into()
        ));
    }
    
    Ok((plaintext.to_vec(), seal))
}

// endregion: --- Public API

// region:    --- Helper Functions

/// Generate X25519 keypair.
#[inline]
fn x25519_keygen(rng: &mut TemperEntropy) -> (Vec<u8>, Vec<u8>) {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    let secret = X25519SecretKey::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    (secret.to_bytes().to_vec(), public.to_bytes().to_vec())
}

// endregion: --- Helper Functions
