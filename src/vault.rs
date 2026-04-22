//! Ledger-independent vault interface used by UI apps.
//!
//! The UI calls the methods on this trait; the concrete impl (currently only
//! [`crate::sc::StellarVault`]) translates the calls into ledger-specific
//! operations. Switching ledger (e.g. to ADA) is a matter of adding a new
//! implementation that fulfils the same contract.

#![allow(async_fn_in_trait)]

/// Time-locked vault interface.
///
/// A vault:
/// - is owned by exactly one account (the caller that runs [`Vault::init`]),
/// - becomes withdrawable only after a per-instance unlock point in time,
/// - drains the entire balance to the owner on [`Vault::withdraw`].
///
/// # Identifiers
///
/// `vault_id` and `token_id` are opaque `String`s whose format is defined by
/// the concrete ledger implementation. For Stellar both are Soroban contract
/// strkeys (`C…`); for a hypothetical ADA implementation they would be
/// whatever identifies a script / native asset on that chain.
pub trait Vault {
    /// Deploy (or otherwise create) a fresh vault owned by the caller.
    ///
    /// The implementation is free to perform any one-time setup it needs
    /// (contract-code upload, script compilation, …) as long as this function
    /// returns the `vault_id` that later calls use.
    ///
    /// - `secret_key`: caller's secret; the resulting vault will be owned by
    ///   the matching public account.
    /// - `token_id`: ledger-specific identifier of the token the vault will
    ///   hold (e.g. ZSOZSO SAC address on Stellar).
    async fn init(
        &self,
        secret_key: &str,
        token_id: &str,
    ) -> Result<String, String>;

    /// Keep-alive. No auth required.
    async fn ping(
        &self,
        secret_key: &str,
        vault_id: &str,
    ) -> Result<String, String>;

    /// Transfer the entire vault balance to the owner. Fails before unlock.
    async fn withdraw(
        &self,
        secret_key: &str,
        vault_id: &str,
    ) -> Result<String, String>;

    /// Read the owner address.
    async fn owner(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<String, String>;

    /// Read the token identifier held by the vault.
    async fn token(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<String, String>;

    /// Read the ledger sequence at which [`Vault::withdraw`] becomes callable.
    async fn unlock_ledger(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<u32, String>;

    /// Read the vault's current balance.
    async fn balance(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<i128, String>;
}
