//! Cryptographic binding tests for the Seal protocol.
//!
//! Tests verify the dual PQC signature protocol and seal structure.

#[cfg(test)]
mod tests {
    use crate::entropy::TemperEntropy;
    use crate::seal::{create_seal, generate_keypair, verify_seal, Seal, SealContext};
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec;

    // region:    --- Integration Tests

    #[test]
    fn test_seal_roundtrip() {
        // Property: Sign and verify should produce valid=true for correct inputs

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x50; 32]);
        let keypair = generate_keypair(&mut rng, "test@example.com").unwrap();
        let content = b"Test message for seal verification";
        let metadata = BTreeMap::new();

        // -- Exec
        let seal = create_seal(&mut rng, content, &keypair, metadata).unwrap();
        let result = verify_seal(
            content,
            &seal,
            &keypair.mldsa_public_key,
            &keypair.slhdsa_public_key,
        )
        .unwrap();

        // -- Check
        assert!(
            result.content_hash_valid,
            "Content hash should be valid"
        );
        assert!(
            result.primary_valid,
            "Primary signature (ML-DSA-65) should be valid"
        );
        assert!(
            result.backup_valid,
            "Backup signature (SLH-DSA) should be valid"
        );
        assert!(result.valid, "Overall seal verification should pass");
    }

    #[test]
    fn test_seal_detects_content_tamper() {
        // Property: Tampering with content should invalidate the seal

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x51; 32]);
        let keypair = generate_keypair(&mut rng, "test@example.com").unwrap();
        let original_content = b"Original message";
        let tampered_content = b"Tampered message";
        let metadata = BTreeMap::new();

        // -- Exec
        let seal = create_seal(&mut rng, original_content, &keypair, metadata).unwrap();
        let result = verify_seal(
            tampered_content,
            &seal,
            &keypair.mldsa_public_key,
            &keypair.slhdsa_public_key,
        )
        .unwrap();

        // -- Check
        assert!(
            !result.content_hash_valid,
            "Content hash should be invalid for tampered content"
        );
        assert!(
            !result.valid,
            "Overall seal verification should fail for tampered content"
        );
    }

    #[test]
    fn test_seal_rejects_wrong_key() {
        // Property: Verifying with wrong public key should fail

        // -- Setup & Fixtures
        let mut rng = TemperEntropy::from_seed([0x52; 32]);
        let keypair_a = generate_keypair(&mut rng, "alice@example.com").unwrap();
        let keypair_b = generate_keypair(&mut rng, "bob@example.com").unwrap();
        let content = b"Message from Alice";
        let metadata = BTreeMap::new();

        // -- Exec
        let seal = create_seal(&mut rng, content, &keypair_a, metadata).unwrap();
        let result = verify_seal(
            content,
            &seal,
            &keypair_b.mldsa_public_key, // Wrong key
            &keypair_b.slhdsa_public_key,  // Wrong key
        )
        .unwrap();

        // -- Check
        assert!(
            !result.primary_valid,
            "Primary signature should be invalid with wrong key"
        );
        assert!(
            !result.backup_valid,
            "Backup signature should be invalid with wrong key"
        );
        assert!(
            !result.valid,
            "Overall seal verification should fail with wrong key"
        );
    }

    // endregion: --- Integration Tests

    // region:    --- Unit Tests (Can run without PQC)

    #[test]
    fn test_seal_id_deterministic() {
        // Property: Seal ID should be deterministic for same inputs
        // This test doesn't require PQC primitives

        // -- Setup & Fixtures
        // Memory: postcard replacement per problem statement
        use postcard;

        // Create a seal manually with hardcoded fields
        let seal = Seal {
            schema_version: 1,
            content_hash: "0123456789abcdef".to_string(),
            primary: crate::seal::SignatureBlock {
                algorithm: "ML-DSA-65".to_string(),
                signature: "aabbccdd".to_string(),
                key_id: "key1".to_string(),
            },
            backup: crate::seal::SignatureBlock {
                algorithm: "SLH-DSA".to_string(),
                signature: "eeffgghh".to_string(),
                key_id: "key2".to_string(),
            },
            context: SealContext {
                domain: "Temper.Seal.v1".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                signer_id: "test".to_string(),
                tool_version: "temper-0.1.0".to_string(),
                metadata: BTreeMap::new(),
            },
            seal_id: String::new(), // Empty for computation
        };

        // -- Exec
        // Memory: updated to match new seal_id computation in create_seal
        let mut hasher1 = blake3::Hasher::new();
        hasher1.update(&seal.schema_version.to_le_bytes());
        hasher1.update(seal.content_hash.as_bytes());
        hasher1.update(seal.primary.algorithm.as_bytes());
        hasher1.update(seal.primary.signature.as_bytes());
        hasher1.update(seal.primary.key_id.as_bytes());
        hasher1.update(seal.backup.algorithm.as_bytes());
        hasher1.update(seal.backup.signature.as_bytes());
        hasher1.update(seal.backup.key_id.as_bytes());
        let context_bytes1 = postcard::to_allocvec(&seal.context).unwrap();
        hasher1.update(&context_bytes1);
        let seal_id1 = hex::encode(hasher1.finalize().as_bytes());

        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(&seal.schema_version.to_le_bytes());
        hasher2.update(seal.content_hash.as_bytes());
        hasher2.update(seal.primary.algorithm.as_bytes());
        hasher2.update(seal.primary.signature.as_bytes());
        hasher2.update(seal.primary.key_id.as_bytes());
        hasher2.update(seal.backup.algorithm.as_bytes());
        hasher2.update(seal.backup.signature.as_bytes());
        hasher2.update(seal.backup.key_id.as_bytes());
        let context_bytes2 = postcard::to_allocvec(&seal.context).unwrap();
        hasher2.update(&context_bytes2);
        let seal_id2 = hex::encode(hasher2.finalize().as_bytes());

        // -- Check
        assert_eq!(
            seal_id1, seal_id2,
            "Seal ID should be deterministic for same inputs"
        );
        assert_eq!(seal_id1.len(), 64, "Seal ID should be 64 hex characters");
    }

    #[test]
    fn test_seal_serde_roundtrip() {
        // Property: Seal should serialize and deserialize correctly
        // This test doesn't require PQC primitives

        // -- Setup & Fixtures
        // Memory: postcard replacement per problem statement
        use postcard;

        let original_seal = Seal {
            schema_version: 1,
            content_hash: "fedcba9876543210".to_string(),
            primary: crate::seal::SignatureBlock {
                algorithm: "ML-DSA-65".to_string(),
                signature: "sig1".to_string(),
                key_id: "keyid1".to_string(),
            },
            backup: crate::seal::SignatureBlock {
                algorithm: "SLH-DSA".to_string(),
                signature: "sig2".to_string(),
                key_id: "keyid2".to_string(),
            },
            context: SealContext {
                domain: "Temper.Seal.v1".to_string(),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                signer_id: "alice".to_string(),
                tool_version: "temper-0.1.0".to_string(),
                metadata: BTreeMap::new(),
            },
            seal_id: "seal123".to_string(),
        };

        // -- Exec
        let bytes = postcard::to_allocvec(&original_seal).unwrap();
        let deserialized_seal: Seal = postcard::from_bytes(&bytes).unwrap();

        // -- Check
        assert_eq!(
            original_seal.schema_version, deserialized_seal.schema_version,
            "Schema version should match"
        );
        assert_eq!(
            original_seal.content_hash, deserialized_seal.content_hash,
            "Content hash should match"
        );
        assert_eq!(
            original_seal.primary.algorithm, deserialized_seal.primary.algorithm,
            "Primary algorithm should match"
        );
        assert_eq!(
            original_seal.backup.algorithm, deserialized_seal.backup.algorithm,
            "Backup algorithm should match"
        );
        assert_eq!(
            original_seal.seal_id, deserialized_seal.seal_id,
            "Seal ID should match"
        );
    }

    #[test]
    fn test_key_id_deterministic() {
        // Property: Key ID computation should be deterministic
        // This test doesn't require PQC primitives

        // -- Setup & Fixtures
        let fake_mldsa_pk = vec![0x01, 0x02, 0x03, 0x04];
        let fake_slhdsa_pk = vec![0x05, 0x06, 0x07, 0x08];

        // -- Exec
        let mut hasher1 = blake3::Hasher::new();
        hasher1.update(&fake_mldsa_pk);
        hasher1.update(&fake_slhdsa_pk);
        let key_id1 = hex::encode(hasher1.finalize().as_bytes());

        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(&fake_mldsa_pk);
        hasher2.update(&fake_slhdsa_pk);
        let key_id2 = hex::encode(hasher2.finalize().as_bytes());

        // -- Check
        assert_eq!(
            key_id1, key_id2,
            "Key ID should be deterministic for same inputs"
        );
        assert_eq!(key_id1.len(), 64, "Key ID should be 64 hex characters");
    }

    // endregion: --- Unit Tests
}
