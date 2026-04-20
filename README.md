# zsozso-ledger

A **shared Rust library** providing the blockchain abstraction layer for the [Iceberg Protocol](https://zsozso.info) ecosystem. Consumed as a Cargo git dependency by all Iceberg Protocol apps.

The architecture and critical logic of this project are the results of human-led AI-assisted engineering. This unique workflow ensures industrial-grade reliability and accelerated deployment.

## Purpose

Provides the `Ledger`, `Cyf`, and `SmartContract` traits and their Stellar/Soroban implementations for keypair management, transaction building, and smart contract invocation.

## Core Traits

| Trait | Implementation | Purpose |
|-------|----------------|---------|
| `Ledger` | `StellarLedger` | Keygen, signing, tx building, Horizon API |
| `Cyf` | (stub) | CYF token mint/burn/balance |
| `SmartContract` | `ZsozsoSc`, `ProofOfZsozsoSc` | Soroban contract invocation |
| `LedgerI18n` | Per-language structs | Error message localization |
| `ScI18n` | Per-language structs | SC error localization |

## Module Layout

- `src/stellar.rs` — `StellarLedger` implementing `Ledger`: ed25519 keygen, Strkey, Horizon API
- `src/cyf.rs` — `Cyf` trait (stub for CYF token operations)
- `src/sc/mod.rs` — `SmartContract` trait: XDR encode → simulate → sign → submit → poll
- `src/sc/zsozso_sc.rs` — `ZsozsoSc` client: ping() on testnet contract
- `src/sc/proof_of_zsozso_sc.rs` — `ProofOfZsozsoSc` client: lock/unlock/get_locked/ping (mainnet)
- `src/i18n/` — `LedgerI18n` implementations
- `src/sc/i18n/` — `ScI18n` implementations

## Network Configuration

- **Testnet**: `horizon-testnet.stellar.org`, friendbot faucet available
- **Mainnet**: `horizon.stellar.org`

## Ecosystem

Sibling libraries: [db](https://github.com/ifinta/db), [store](https://github.com/ifinta/store), [zsozso-common](https://github.com/ifinta/zsozso-common)
