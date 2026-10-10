# Benchmarks

Numbers from this machine (Intel i7-10750H, 6 cores / 12 threads, Linux,
release profile with thin LTO), produced by the two benchmark targets:

```sh
cargo bench -p temper --bench session_bench --features session   # the wire protocol
cargo bench -p temper --bench seal_bench --features signatures   # document signing
```

The protocol numbers measure the library, not a socket: the handshake runs
its flights in-process and the record layer seals and opens on derived keys.
Framing, syscalls, and the network are outside the measurement.

## The session handshake (2026-10)

A full establishment - ML-KEM-1024+X25519 hybrid exchange, identity
concealment, and four ML-DSA-65 plus SLH-DSA-SHA2-128f signatures and
verifications across the two sides - costs **~77 ms** of combined CPU,
about **13 sessions/s per core**.

| flight | work | time |
|---|---|---|
| 1 · initiate | KEM encapsulation, X25519, transcript | 0.32 ms |
| 2 · accept | KEM decapsulation, 2 signatures | 35.2 ms |
| 3 · finalize initiator | 2 verifications, 2 signatures | 37.6 ms |
| 4 · finalize responder | 2 verifications | 2.28 ms |

The two SLH-DSA signatures dominate: hash-based signing is the price of a
second, lattice-independent trust anchor on every session. Placed against
published protocol costs, temper is roughly 50–100× a classical TLS 1.3
handshake (X25519+ECDSA, ~1 ms class) and an order of magnitude above a
hybrid X25519MLKEM768+ML-DSA TLS handshake (~3–5 ms class). What that buys
is what no mainstream protocol carries per-handshake: dual PQ signatures
from two different hardness assumptions and a concealed initiator identity.

## The record layer (2026-10)

ChaCha20-Poly1305 under the counter-nonce discipline, single core:

| record | seal | open |
|---|---|---|
| 1 KiB | ~721 MiB/s | ~694 MiB/s |
| 16 KiB | ~869 MiB/s | ~853 MiB/s |
| 64 KiB | ~850 MiB/s | ~828 MiB/s |
| 1 MiB | ~830 MiB/s | ~802 MiB/s |

~0.85 GiB/s per core is the tunnel ceiling; it is the expected ChaCha class
for portable Rust (no hardware AEAD), well below AES-NI TLS but with no
instruction-set requirement - the same code runs on an ARM host.

## BLAKE3 (vendored, 2026-10)

The vendored build reaches **~3.6 GiB/s** single-core (64 KiB and 1 MiB
inputs alike), which is the published AVX2/AVX512 tier for blake3 on
desktop-class x86 - roughly 4× the record layer, so transcript hashing
disappears inside the AEAD cost.
