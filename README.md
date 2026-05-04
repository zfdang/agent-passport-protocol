# Agent Passport Protocol

Public shared contract crates for the Agent Passport ecosystem.

## Crates

### Public Contract Crates

| Crate | Description |
|-------|-------------|
| `kitepass-api-types` | Shared API request/response types |
| `kitepass-crypto` | Shared cryptographic primitives: Ed25519 signing, canonical intent verification, local `CryptoEnvelope` encryption, and Capsule P-384 ECDH wallet-import envelopes |
| `kitepass-attestation` | TEE attestation measurement parsing and verification helpers |

### Shared Infrastructure Crates

| Crate | Description |
|-------|-------------|
| `kap-config` | Configuration loading and environment management |
| `kap-observability` | Logging, tracing, and metrics setup |
| `kap-policy` | Policy types and evaluation logic |

## Consumers

- [`agent-passport`](https://github.com/zfdang/agent-passport) — main platform services
- [`agent-passport-vault-signer`](https://github.com/zfdang/agent-passport-vault-signer) — standalone Vault Signer
- [`agent-passport-cli`](https://github.com/zfdang/agent-passport-cli) — Kitepass CLI

## Current Wallet-Import Crypto

Wallet import now uses `capsule_p384_ecdh_aes256gcm_v1`:

- the owner-side client encrypts locally with P-384 ECDH, HKDF-SHA256, and AES-256-GCM
- the recipient public key is the Capsule runtime's attestation-bound P-384 public key
- Vault Signer decrypts by calling Capsule `/v1/encryption/decrypt`; the attestation-bound private key does not leave Capsule

Older wallet-import prototypes are no longer the active import scheme.

## License

Apache-2.0
