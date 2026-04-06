mod stellar;
pub mod i18n;
pub mod sc;
pub mod cyf;

pub use stellar::StellarLedger;


/// Key pair: public address (G...) and secret key (S...)
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

/// Network selector — the Ledger implementation decides what it means
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetworkEnvironment {
    Production,
    Test,
}

/// Network description for the UI
pub struct NetworkInfo {
    pub name: &'static str,
    pub has_faucet: bool,
}

/// Abstract interface for the ledger system.
/// main.rs uses this trait — it doesn't know that Stellar is behind it.
#[allow(async_fn_in_trait)]
pub trait Ledger {
    /// Network information for the UI
    fn network_info(&self) -> NetworkInfo;

    /// Generate a new key pair
    fn generate_keypair(&self) -> KeyPair;

    /// Derive public address from secret key
    /// Returns None if the key format is invalid
    fn public_key_from_secret(&self, secret: &str) -> Option<String>;

    /// Activate a test account (faucet) — only on Test network
    async fn activate_test_account(&self, public_key: &str) -> Result<String, String>;

    /// Generate and sign a self-payment transaction
    /// Returns the ready-to-submit XDR (base64) and the sequence number
    async fn build_self_payment(
        &self,
        secret_key: &str,
        amount: i64,
    ) -> Result<(String, i64), String>;

    /// Submit a signed transaction to the network
    async fn submit_transaction(&self, xdr: &str) -> Result<String, String>;
}