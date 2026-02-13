#![no_std]
#![doc = "Temper — Quantum-safe cryptographic protocol with hardened entropy and dual PQC signatures."]

#[cfg(feature = "alloc")]
extern crate alloc;

// When std is enabled, make std available
#[cfg(feature = "std")]
extern crate std;

// When std is enabled, alloc is implicitly available
#[cfg(all(feature = "std", not(feature = "alloc")))]
extern crate alloc;

// region:    --- Modules

pub mod entropy_source;
pub mod entropy;
pub mod error;
pub mod seal;
pub mod envelope;

#[cfg(test)]
#[path = "entropy_tests.rs"]
mod entropy_tests;

#[cfg(test)]
#[path = "seal_tests.rs"]
mod seal_tests;

// endregion: --- Modules

// region:    --- Re-exports

pub use entropy::{TemperEntropy, EntropyHealth};
pub use entropy_source::{EntropySource, EntropyError};
pub use error::{Error, Result};
pub use seal::{Seal, SealContext, SignatureBlock, TemperKeypair, VerifyResult};
pub use seal::{generate_keypair, create_seal, verify_seal};

// endregion: --- Re-exports
