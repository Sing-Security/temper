//! Demonstration of EscrowEnvelope - escrowed dual-KEM encryption.
//!
//! This example shows how to:
//! 1. Generate keypairs for recipient and escrow holder
//! 2. Encapsulate a message with dual-KEM (recipient plus escrow holder shares)
//! 3. Escrow holder extracts its shared secret
//! 4. Recipient decapsulates using the holder's secret
//!
//! Run with: cargo run --example c03-escrow

use temper::{
	TemperEntropy,
	envelope::{escrow_decapsulate, escrow_encapsulate, escrow_extract_secret, generate_envelope_keypair},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("=== EscrowEnvelope Demo ===\n");

	// Initialize RNG
	let mut rng = TemperEntropy::from_seed([0x42; 32]);

	// 1. Generate keypairs
	println!("1. Generating keypairs...");
	let recipient_keypair = generate_envelope_keypair(&mut rng)?;
	let escrow_keypair = generate_envelope_keypair(&mut rng)?;
	println!("   ✓ Recipient keypair: {}", recipient_keypair.key_id);
	println!("   ✓ Escrow holder keypair: {}\n", escrow_keypair.key_id);

	// 2. Sender creates envelope
	let plaintext = b"Secret IPC message from process A to process B";
	println!("2. Sender encapsulates message...");
	println!("   Plaintext: {:?}", String::from_utf8_lossy(plaintext));

	let envelope = escrow_encapsulate(&mut rng, plaintext, &recipient_keypair, &escrow_keypair)?;

	println!("   ✓ Envelope created:");
	println!("     - Envelope ID: {}", envelope.envelope_id);
	println!(
		"     - ML-KEM recipient CT: {} bytes",
		envelope.mlkem_ct_recipient.len()
	);
	println!("     - ML-KEM escrow CT: {} bytes", envelope.mlkem_ct_escrow.len());
	println!("     - Ciphertext: {} bytes\n", envelope.ciphertext.len());

	// 3. Holder inspects envelope (extracts its shared secret)
	println!("3. Escrow holder extracts shared secret for IPC delivery...");
	let escrow_shared_secret = escrow_extract_secret(&envelope, &escrow_keypair)?;
	println!("   ✓ Escrow holder extracted its ML-KEM shared secret (32 bytes)\n");

	// 4. Recipient decapsulates with holder-provided secret
	println!("4. Recipient decapsulates using the escrow holder's secret...");
	let recovered_plaintext = escrow_decapsulate(&envelope, &recipient_keypair, &escrow_shared_secret)?;

	println!("   ✓ Decryption successful!");
	println!("   Recovered: {:?}\n", String::from_utf8_lossy(&recovered_plaintext));

	// 5. Verify correctness
	assert_eq!(plaintext, recovered_plaintext.as_slice());
	println!("✅ Verification: Plaintext matches!");

	// Performance note
	println!("\n=== Performance Note ===");
	println!("EscrowEnvelope cost: ~0.3 ms per message");
	println!("  - 2× ML-KEM-1024 Encap (~0.1 ms each)");
	println!("  - 1× X25519 DH (~0.05 ms)");
	println!("  - ChaCha20-Poly1305 encrypt (GB/s throughput)");
	println!("\nCompare to SLH-DSA seals: ~36 ms create + ~2.4 ms verify");
	println!("→ 100× faster for per-message IPC encryption!");

	Ok(())
}
