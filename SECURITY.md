# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately, not in a public issue.

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. If you cannot use it, contact the maintainers directly.

Please include the affected version, a description of the impact, and a minimal
reproduction if you have one. We will acknowledge receipt and keep you informed
as we work on a fix.

## Scope

Temper implements a protocol on top of audited RustCrypto primitives. The most
useful reports are about the code here - the entropy pool and DRBG, the seal
binding, the envelope construction, the handshake's key derivation, the session
protocol's transcript chain and key schedule, the record layer's nonce and AAD
construction, and any path where a secret could leak, a check could be skipped,
or a length or boundary assumption could be violated.

Bugs in `ml-dsa`, `slh-dsa`, `ml-kem`, `blake3`, `chacha20poly1305` or
`x25519-dalek` are upstream's; report those to the respective RustCrypto or
BLAKE3 projects, but do tell us if Temper uses them in a way that weakens them.

## Cryptographic design notes

These limitations are deliberate and documented, not vulnerabilities:

- **`handshake` is unauthenticated key agreement.** It provides forward secrecy
  but no protection against an active man-in-the-middle on its own. The
  authenticated wrapper is the `session` protocol - dual transcript signatures
  on both sides, mandatory client authentication. Its residual risks (handshake
  replay, cleartext identities, no rekey, caller-side certificate-expiry checks)
  are listed in [`PROTOCOL.md`](PROTOCOL.md); read that list before deploying it.
- **`keychain` and the `host-getrandom` feature are host-platform
  integration**, not general-purpose API. Their BLAKE3 domain strings are
  cryptographic separators bound to an existing deployment; changing them would
  change every derived key. See the README.

## Supported versions

Temper is pre-1.0 and the API moves. Security fixes land on `main`; there are no
maintained release branches yet.
