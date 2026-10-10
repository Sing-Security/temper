//! Benchmarks for the authenticated session protocol: the handshake's
//! flights (whole and one-by-one, so the cost profile is readable), the
//! record layer at the sizes a tunnel actually carries, and raw BLAKE3 as
//! the reference point both are built on. The document-signing path is
//! seal_bench.rs; this file is the session wire protocol as carried.
//!
//! Run with: cargo bench --bench session_bench --features session

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use temper::TemperKeypair;
use temper::envelope::ConcealmentKeypair;
use temper::record::RecordKey;
use temper::session::{self, PeerPolicy};
use temper::{TemperEntropy, generate_keypair};

/// Everything both sides of a handshake need, made once per group - keygen
/// (two PQ signature keys and the concealment key) is minutes of setup cost
/// per run and is not what is being measured. The measured flights reseed
/// their rngs from fixed seeds: the ephemerals repeat, which is fine for
/// timing and makes the numbers comparable between runs.
struct Peers {
	client: TemperKeypair,
	server: TemperKeypair,
	concealment: ConcealmentKeypair,
}

fn peers() -> Peers {
	let mut rng = TemperEntropy::from_seed([0x11; 32]);
	Peers {
		client: generate_keypair(&mut rng, "bench-client@example").expect("client keygen"),
		server: generate_keypair(&mut rng, "bench-server@example").expect("server keygen"),
		concealment: ConcealmentKeypair::generate(&mut rng).expect("concealment keygen"),
	}
}

const ANY: PeerPolicy = PeerPolicy::AcceptAny;

/// One full establishment - all four calls a session costs, both sides.
fn full_handshake(c: &mut Criterion) {
	let mut group = c.benchmark_group("handshake");
	group.throughput(Throughput::Elements(1));
	let p = peers();
	group.bench_function("full", |b| {
		b.iter(|| {
			let mut c_rng = TemperEntropy::from_seed([0x21; 32]);
			let mut s_rng = TemperEntropy::from_seed([0x22; 32]);
			let (init, c_state) =
				session::initiate(&mut c_rng, &p.client, None, &p.concealment.public(), [0u8; 32]).expect("flight 1");
			let (accept, s_state) =
				session::accept(&mut s_rng, &init, &p.server, None, &p.concealment, &ANY, None).expect("flight 2");
			let (confirm, c_secrets) =
				session::finalize_initiator(&mut c_rng, &init, &accept, &c_state, &ANY).expect("flight 3");
			let s_secrets = session::finalize_responder(&init, &accept, &confirm, &s_state, &ANY).expect("flight 4");
			black_box((c_secrets.session_id, s_secrets.session_id))
		});
	});
	group.finish();
}

/// The flights separately, each timed with its setup excluded - where the
/// milliseconds live (concealment, the two PQ signatures, the KEM) decides
/// what is worth optimizing, and a single "full" number hides it.
fn flight_by_flight(c: &mut Criterion) {
	let mut group = c.benchmark_group("handshake_flight");
	let p = peers();

	// Flight 1 - the initiator's opening: concealment encapsulation plus the
	// bare proposal.
	group.bench_function("1_initiate", |b| {
		b.iter_batched(
			|| TemperEntropy::from_seed([0x21; 32]),
			|mut rng| {
				session::initiate(&mut rng, &p.client, None, &p.concealment.public(), [0u8; 32]).expect("flight 1")
			},
			BatchSize::SmallInput,
		);
	});

	// Flight 2 - the responder's answer: cookie check, decapsulation, the
	// bare handshake, and the two responder signatures.
	group.bench_function("2_accept", |b| {
		b.iter_batched(
			|| {
				let mut rng = TemperEntropy::from_seed([0x21; 32]);
				session::initiate(&mut rng, &p.client, None, &p.concealment.public(), [0u8; 32])
					.expect("flight 1")
					.0
			},
			|init| {
				let mut rng = TemperEntropy::from_seed([0x22; 32]);
				session::accept(&mut rng, &init, &p.server, None, &p.concealment, &ANY, None).expect("flight 2")
			},
			BatchSize::SmallInput,
		);
	});

	// Flight 3 - the initiator's finish: responder signature verification,
	// then the two initiator signatures.
	group.bench_function("3_finalize_initiator", |b| {
		b.iter_batched(
			|| {
				let mut c_rng = TemperEntropy::from_seed([0x21; 32]);
				let mut s_rng = TemperEntropy::from_seed([0x22; 32]);
				let (init, c_state) =
					session::initiate(&mut c_rng, &p.client, None, &p.concealment.public(), [0u8; 32])
						.expect("flight 1");
				let (accept, _) =
					session::accept(&mut s_rng, &init, &p.server, None, &p.concealment, &ANY, None).expect("flight 2");
				(c_rng, init, accept, c_state)
			},
			|(mut c_rng, init, accept, c_state)| {
				session::finalize_initiator(&mut c_rng, &init, &accept, &c_state, &ANY).expect("flight 3")
			},
			BatchSize::SmallInput,
		);
	});

	// Flight 4 - the responder's finish: MAC, then initiator verification.
	// No rng: this side signs nothing, it only verifies.
	group.bench_function("4_finalize_responder", |b| {
		b.iter_batched(
			|| {
				let mut c_rng = TemperEntropy::from_seed([0x21; 32]);
				let mut s_rng = TemperEntropy::from_seed([0x22; 32]);
				let (init, c_state) =
					session::initiate(&mut c_rng, &p.client, None, &p.concealment.public(), [0u8; 32])
						.expect("flight 1");
				let (accept, s_state) =
					session::accept(&mut s_rng, &init, &p.server, None, &p.concealment, &ANY, None).expect("flight 2");
				let (confirm, _) =
					session::finalize_initiator(&mut c_rng, &init, &accept, &c_state, &ANY).expect("flight 3");
				(init, accept, confirm, s_state)
			},
			|(init, accept, confirm, s_state)| {
				session::finalize_responder(&init, &accept, &confirm, &s_state, &ANY).expect("flight 4")
			},
			BatchSize::SmallInput,
		);
	});

	group.finish();
}

/// The record layer - ChaCha20-Poly1305 under the counter-nonce discipline,
/// the per-record cost every tunnel byte pays after the handshake.
fn record_layer(c: &mut Criterion) {
	let mut group = c.benchmark_group("record");
	let key = [0x33; 32];

	for (label, size) in [
		("64B", 64usize),
		("1KiB", 1024),
		("16KiB", 16 * 1024),
		("64KiB", 64 * 1024),
		("1MiB", 1024 * 1024),
	] {
		// Seal: one record per iteration, the sender's counter climbing.
		let plaintext = vec![0u8; size];
		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(BenchmarkId::new("seal", label), &size, |b, _| {
			let mut tx = RecordKey::new(key);
			b.iter(|| black_box(tx.seal(black_box(&plaintext)).expect("seal")));
		});

		// Open: a strictly ordered batch per iteration - the receiver's
		// replay window is what forbids a single record being opened twice,
		// so the measurement opens many records in sequence, fresh counters
		// each round. Key setup rides along; it is not the point.
		let mut tx = RecordKey::new(key);
		let records: Vec<Vec<u8>> = (0..256u64)
			.map(|seq| tx.seal_at(seq, &plaintext).expect("seal for the open batch"))
			.collect();
		group.throughput(Throughput::Bytes((size as u64) * records.len() as u64));
		group.bench_with_input(BenchmarkId::new("open", label), &size, |b, _| {
			b.iter(|| {
				let mut rx = RecordKey::new(key);
				for record in &records {
					black_box(rx.open(black_box(record)).expect("open"));
				}
			});
		});
	}

	group.finish();
}

/// Raw BLAKE3, unkeyed, one-shot - the hash the transcript and every key
/// derivation ride on, and the number the vendored build's on-target speed
/// is measured against.
fn blake3_raw(c: &mut Criterion) {
	let mut group = c.benchmark_group("blake3");
	for (label, size) in [("64KiB", 64 * 1024), ("1MiB", 1024 * 1024)] {
		let data = vec![0u8; size];
		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
			b.iter(|| {
				let mut hasher = blake3::Hasher::new();
				hasher.update(black_box(data));
				black_box(hasher.finalize())
			});
		});
	}
	group.finish();
}

criterion_group!(benches, full_handshake, flight_by_flight, record_layer, blake3_raw);
criterion_main!(benches);
