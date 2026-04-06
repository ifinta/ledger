/// CYF (CYBERFORINT) token operations.
///
/// This module defines the abstract interface for minting, burning,
/// and querying CYF token balances. The concrete implementation
/// will be connected to the Stellar/Soroban contract later.
#[allow(async_fn_in_trait)]
pub trait Cyf {
    /// Mint new CYF tokens to the caller's account.
    async fn mint(&self, amount: u64) -> Result<String, String>;

    /// Burn CYF tokens from the caller's account.
    async fn burn(&self, amount: u64) -> Result<String, String>;

    /// Get the CYF balance for the given public key.
    async fn get_balance(&self, public_key: &str) -> Result<u64, String>;
}
