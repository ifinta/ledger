# Copilot Instructions — ledger (shared library)

## Overview

This is a **shared Rust library** (git submodule) providing the blockchain abstraction layer for the Iceberg Protocol ecosystem. It is included as a submodule in every Iceberg Protocol app (cyf, proof-of-zsozso, mlm, gun-connect, admin, merlin).

**This is NOT a standalone app.** It is a library crate — no `main.rs`, no `Dioxus.toml`, no PWA assets.

## Purpose

Provides the `Ledger`, `Cyf`, and `SmartContract` traits and their Stellar/Soroban implementations for keypair management, transaction building, and smart contract invocation.

## Module Layout

- **`mod.rs`** — `Ledger` trait (generate_keypair, public_key_from_secret, activate_test_account, build_self_payment, submit_transaction), `KeyPair`, `NetworkEnvironment` (Production/Test), `NetworkInfo`
- **`stellar.rs`** — `StellarLedger` implementing `Ledger`: ed25519 keygen, Strkey encoding, Horizon API (testnet + mainnet)
- **`cyf.rs`** — `Cyf` trait (stub): mint, burn, get_balance for CYBERFORINT token
- **`sc/mod.rs`** — `SmartContract` trait: contract_id(), invoke_contract() (XDR encode → simulate → sign → submit → poll)
- **`sc/zsozso_sc.rs`** — `ZsozsoSc` client: ping() on testnet contract
- **`sc/proof_of_zsozso_sc.rs`** — `ProofOfZsozsoSc` client: lock, unlock, get_locked, ping (mainnet)
- **`i18n/`** — `LedgerI18n` trait + 5 language implementations
- **`sc/i18n/`** — `ScI18n` trait + 5 language implementations
- **`../i18n.rs`** — `Language` enum shared across the ecosystem - it isn't copied here, it is in the App src folder, which App using this library

## Core Traits

| Trait | File | Implementation | Purpose |
|-------|------|----------------|---------|
| `Ledger` | `mod.rs` | `StellarLedger` | Keygen, signing, tx building, Horizon API |
| `Cyf` | `cyf.rs` | (stub) | CYF token mint/burn |
| `SmartContract` | `sc/mod.rs` | `ZsozsoSc`, `ProofOfZsozsoSc` | Soroban contract invocation |
| `LedgerI18n` | `i18n/mod.rs` | Per-language structs | Error message localization |
| `ScI18n` | `sc/i18n/mod.rs` | Per-language structs | Smart contract error localization |

## Network Configuration

- **Testnet**: Horizon at `horizon-testnet.stellar.org`, friendbot faucet available
- **Mainnet**: Horizon at `horizon.stellar.org`, no faucet

## Key Conventions

- All trait async methods use `#[allow(async_fn_in_trait)]`
- Errors are `Result<T, String>` — no custom error types
- Secret keys wrapped in `Zeroizing<String>` (zeroize crate); seed bytes zeroed after use
- I18n: factory functions `ledger_i18n(lang)` and `sc_i18n(lang)` select implementation
- XDR encoding/decoding via `stellar_xdr` crate
- Smart contract flow: decode key → fetch sequence → build unsigned tx → simulate → attach resources → sign → submit → poll status

## Ecosystem

Part of the [Iceberg Protocol](https://zsozso.info) — a decentralized hierarchical MLM infrastructure on the Stellar blockchain.

Sibling shared libraries: `db`, `store`
