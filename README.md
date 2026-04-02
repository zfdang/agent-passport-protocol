# Agent Passport Protocol

Public shared contract crates for the Agent Passport ecosystem.

## Crates

### Public Contract Crates

| Crate | Description |
|-------|-------------|
| `kitepass-api-types` | Shared API request/response types |
| `kitepass-crypto` | Shared cryptographic primitives — signing, canonicalization, HPKE, envelope encryption |
| `kitepass-attestation` | TEE attestation parsing and verification helpers |

### Shared Infrastructure Crates

| Crate | Description |
|-------|-------------|
| `kap-config` | Configuration loading and environment management |
| `kap-observability` | Logging, tracing, and metrics setup |
| `kap-policy` | Policy types and evaluation logic |

## Consumers

- [`agent-passport`](https://github.com/nicekite/agent-passport) — main platform services
- [`agent-passport-vault-signer`](https://github.com/nicekite/agent-passport-vault-signer) — standalone Vault Signer
- [`agent-passport-cli`](https://github.com/nicekite/agent-passport-cli) — Kitepass CLI

## License

Apache-2.0
