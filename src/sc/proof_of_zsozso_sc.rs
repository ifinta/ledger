use zsozso_common::Language;
use crate::NetworkEnvironment;
use super::SmartContract;
use stellar_xdr::curr::{ScVal, ScString, StringM};

/// Deployed proof-of-zsozso contract ID on Stellar testnet.
/// Replace with the actual contract ID after deployment.
const PROOF_OF_ZSOZSO_CONTRACT_ID: &str = "PLACEHOLDER_DEPLOY_FIRST";

/// proof-of-zsozso smart contract client.
/// Records locked ZSOZSO balances on-chain as proof of participation.
pub struct ProofOfZsozsoSc {
    network: NetworkEnvironment,
    language: Language,
}

impl ProofOfZsozsoSc {
    pub fn new(network: NetworkEnvironment, language: Language) -> Self {
        Self { network, language }
    }

    /// Call `lock(user, amount)` on the proof-of-zsozso contract.
    pub async fn lock(&self, secret_key: &str, amount: u64) -> Result<String, String> {
        let pub_key = self.caller_public_key(secret_key)?;
        self.invoke_contract(
            secret_key,
            "lock",
            vec![
                ScVal::String(ScString(StringM::try_from(pub_key).map_err(|e| format!("{e}"))?)),
                ScVal::U64(amount),
            ],
        )
        .await
    }

    /// Call `unlock(user, amount)` on the proof-of-zsozso contract.
    pub async fn unlock(&self, secret_key: &str, amount: u64) -> Result<String, String> {
        let pub_key = self.caller_public_key(secret_key)?;
        self.invoke_contract(
            secret_key,
            "unlock",
            vec![
                ScVal::String(ScString(StringM::try_from(pub_key).map_err(|e| format!("{e}"))?)),
                ScVal::U64(amount),
            ],
        )
        .await
    }

    /// Call `get_locked(user)` on the proof-of-zsozso contract.
    pub async fn get_locked(&self, secret_key: &str) -> Result<String, String> {
        let pub_key = self.caller_public_key(secret_key)?;
        self.invoke_contract(
            secret_key,
            "get_locked",
            vec![
                ScVal::String(ScString(StringM::try_from(pub_key).map_err(|e| format!("{e}"))?)),
            ],
        )
        .await
    }

    /// Call `ping()` to keep the contract alive.
    pub async fn ping(&self, secret_key: &str) -> Result<String, String> {
        self.invoke_contract(secret_key, "ping", vec![]).await
    }

    /// Extract the caller's public key from the secret key.
    fn caller_public_key(&self, secret_key: &str) -> Result<String, String> {
        use stellar_strkey::{ed25519, Strkey};
        use ed25519_dalek::SigningKey;
        let priv_key = match Strkey::from_string(secret_key) {
            Ok(Strkey::PrivateKeyEd25519(pk)) => pk,
            _ => return Err("Invalid secret key".to_string()),
        };
        let signing_key = SigningKey::from_bytes(&priv_key.0);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        Ok(Strkey::PublicKeyEd25519(ed25519::PublicKey(pub_bytes)).to_string())
    }
}

impl SmartContract for ProofOfZsozsoSc {
    fn contract_id(&self) -> &str {
        PROOF_OF_ZSOZSO_CONTRACT_ID
    }

    fn network(&self) -> NetworkEnvironment {
        self.network
    }

    fn language(&self) -> Language {
        self.language
    }
}
