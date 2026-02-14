//! Tests for the envelope key encapsulation module.

#![cfg(all(test, feature = "envelope"))]

#[cfg(test)]
mod tests {
    use crate::envelope::{decapsulate, encapsulate, generate_envelope_keypair};
    use crate::entropy::TemperEntropy;
    use alloc::vec;
    use alloc::string::ToString;
    use alloc::format;

    // region:    --- Integration Tests

    #[test]
    fn test_envelope_roundtrip() {
        // Property: Encapsulate and decapsulate should recover original plaintext

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x60; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate envelope keypair");
        let plaintext = b"Secret message for hybrid KEM";

        // -- Exec
        let envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate");

        let recovered = decapsulate(
            &envelope,
            &keypair,
        )
        .expect("Failed to decapsulate");

        // -- Check
        assert_eq!(
            plaintext,
            recovered.as_slice(),
            "Recovered plaintext should match original"
        );
    }

    #[test]
    fn test_envelope_wrong_key_fails() {
        // Property: Decapsulation with wrong key should fail

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x61; 32]);
        let keypair1 = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair 1");
        let keypair2 = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair 2");
        let plaintext = b"Secret message";

        // -- Exec
        let envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair1,
        )
        .expect("Failed to encapsulate");

        let result = decapsulate(
            &envelope,
            &keypair2,
        );

        // -- Check
        assert!(
            result.is_err(),
            "Decapsulation with wrong key should fail"
        );
    }

    #[test]
    fn test_envelope_tampered_ciphertext_fails() {
        // Property: Tampered ciphertext should fail authentication

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x62; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = b"Secret message";

        // -- Exec
        let mut envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate");

        // Tamper with ciphertext
        if let Some(byte) = envelope.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = decapsulate(
            &envelope,
            &keypair,
        );

        // -- Check
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail authentication"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authentication tag mismatch"),
            "Error should indicate authentication failure"
        );
    }

    #[test]
    fn test_envelope_tampered_mlkem_ct_fails() {
        // Property: Tampered ML-KEM ciphertext should fail authentication

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x63; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = b"Secret message";

        // -- Exec
        let mut envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate");

        // Tamper with ML-KEM ciphertext
        if let Some(byte) = envelope.mlkem_ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = decapsulate(
            &envelope,
            &keypair,
        );

        // -- Check
        assert!(
            result.is_err(),
            "Tampered ML-KEM ciphertext should fail authentication"
        );
    }

    #[test]
    fn test_envelope_large_plaintext() {
        // Property: Should handle large plaintext (> 1 MB)

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x64; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1 MB

        // -- Exec
        let envelope = encapsulate(
            &mut rng,
            &plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate large plaintext");

        let recovered = decapsulate(
            &envelope,
            &keypair,
        )
        .expect("Failed to decapsulate large plaintext");

        // -- Check
        assert_eq!(
            plaintext.len(),
            recovered.len(),
            "Recovered plaintext should have same length"
        );
        assert_eq!(
            plaintext, recovered,
            "Recovered plaintext should match original"
        );
    }

    // endregion: --- Integration Tests

    // region:    --- Unit Tests

    #[test]
    fn test_envelope_id_deterministic() {
        // Property: Same envelope components should produce same envelope_id

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x65; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = b"Test determinism";

        // -- Exec
        // Create two envelopes with same seed (deterministic)
        let mut rng1 = TemperEntropy::from_seed([0x66; 32]);
        let envelope1 = encapsulate(
            &mut rng1,
            plaintext,
            &keypair,
        )
        .expect("Failed to create envelope 1");

        let mut rng2 = TemperEntropy::from_seed([0x66; 32]); // Same seed
        let envelope2 = encapsulate(
            &mut rng2,
            plaintext,
            &keypair,
        )
        .expect("Failed to create envelope 2");

        // -- Check
        assert_eq!(
            envelope1.envelope_id, envelope2.envelope_id,
            "Envelope IDs should be deterministic for same inputs"
        );
        assert_eq!(
            envelope1.mlkem_ciphertext, envelope2.mlkem_ciphertext,
            "ML-KEM ciphertexts should be deterministic"
        );
    }

    #[test]
    fn test_keypair_key_id_deterministic() {
        // Property: Key ID should be deterministic for same public keys

        // -- Setup & Fixtures
        let mut rng1 = TemperEntropy::from_seed([0x67; 32]);
        let keypair1 = generate_envelope_keypair(&mut rng1)
            .expect("Failed to generate keypair 1");

        let mut rng2 = TemperEntropy::from_seed([0x67; 32]); // Same seed
        let keypair2 = generate_envelope_keypair(&mut rng2)
            .expect("Failed to generate keypair 2");

        // -- Exec & Check
        assert_eq!(
            keypair1.key_id, keypair2.key_id,
            "Key IDs should be deterministic for same keys"
        );
        assert_eq!(
            keypair1.mlkem_public_key, keypair2.mlkem_public_key,
            "ML-KEM public keys should be deterministic"
        );
        assert_eq!(
            keypair1.x25519_public_key, keypair2.x25519_public_key,
            "X25519 public keys should be deterministic"
        );
    }

    #[test]
    fn test_envelope_serde_roundtrip() {
        // Property: Serialize and deserialize should preserve envelope

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x68; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = b"Test serialization";

        let envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate");

        // -- Exec
        let serialized = postcard::to_allocvec(&envelope)
            .expect("Failed to serialize envelope");
        let deserialized: crate::envelope::Envelope = postcard::from_bytes(&serialized)
            .expect("Failed to deserialize envelope");

        // -- Check
        assert_eq!(
            envelope.envelope_id, deserialized.envelope_id,
            "Envelope IDs should match after serde roundtrip"
        );
        assert_eq!(
            envelope.mlkem_ciphertext, deserialized.mlkem_ciphertext,
            "ML-KEM ciphertexts should match"
        );
        assert_eq!(
            envelope.ciphertext, deserialized.ciphertext,
            "Ciphertexts should match"
        );

        // Verify decapsulation still works
        let recovered = decapsulate(
            &deserialized,
            &keypair,
        )
        .expect("Failed to decapsulate after serde roundtrip");

        assert_eq!(plaintext, recovered.as_slice());
    }

    #[test]
    fn test_envelope_empty_plaintext() {
        // Property: Should handle empty plaintext

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x69; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate keypair");
        let plaintext = b"";

        // -- Exec
        let envelope = encapsulate(
            &mut rng,
            plaintext,
            &keypair,
        )
        .expect("Failed to encapsulate empty plaintext");

        let recovered = decapsulate(
            &envelope,
            &keypair,
        )
        .expect("Failed to decapsulate empty plaintext");

        // -- Check
        assert_eq!(
            plaintext,
            recovered.as_slice(),
            "Empty plaintext should be recovered correctly"
        );
        assert_eq!(recovered.len(), 0, "Recovered should be empty");
    }

    #[test]
    fn test_envelope_keypair_debug_redacts_secrets() {
        // Property: Debug output should redact secret keys to prevent accidental logging
        // Memory: security fix per problem statement — verify Debug redaction
        
        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x71; 32]);
        let keypair = generate_envelope_keypair(&mut rng)
            .expect("Failed to generate envelope keypair");
        
        // -- Exec
        let debug_output = format!("{:?}", keypair);
        
        // -- Check
        assert!(
            debug_output.contains("<REDACTED>"),
            "Debug output should contain <REDACTED> for secret keys"
        );
        assert!(
            !debug_output.contains(&format!("{:?}", keypair.mlkem_secret_key)),
            "Debug output should NOT contain raw ML-KEM secret key"
        );
        assert!(
            !debug_output.contains(&format!("{:?}", keypair.x25519_secret_key)),
            "Debug output should NOT contain raw X25519 secret key"
        );
        assert!(
            debug_output.contains(&keypair.key_id),
            "Debug output should contain key_id"
        );
    }

    // endregion: --- Unit Tests
}
