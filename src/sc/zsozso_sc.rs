use zsozso_common::Language;
use crate::NetworkEnvironment;
use super::SmartContract;

/// Deployed contract ID on Stellar testnet.
/// Replace with the actual contract ID after deployment.
const ZSOZSO_CONTRACT_ID: &str = "CCH2DZP5G5CFIWVMA4XZ7VQ4ANHWEL2D6XMFNTCGOBZJXMQCZ7MXQ73Z";

/// zsozso-sc smart contract client.
/// Mirrors the on-chain `Contract` interface from github.com/ifinta/zsozso-sc.
pub struct ZsozsoSc {
    network: NetworkEnvironment,
    language: Language,
}

impl ZsozsoSc {
    pub fn new(network: NetworkEnvironment, language: Language) -> Self {
        Self { network, language }
    }

    /// Call the `ping` function on the zsozso-sc contract.
    /// `ping` keeps the contract (and the network tree) alive by extending the
    /// instance TTL and performing housekeeping (activity timestamps, payments).
    ///
    /// The on-chain signature: `pub fn ping(env: Env)`
    /// — no extra arguments beyond the implicit `Env`.
    pub async fn ping(&self, secret_key: &str) -> Result<String, String> {
        self.invoke_contract(secret_key, "ping", vec![]).await
    }
}

impl SmartContract for ZsozsoSc {
    fn contract_id(&self) -> &str {
        ZSOZSO_CONTRACT_ID
    }

    fn network(&self) -> NetworkEnvironment {
        self.network
    }

    fn language(&self) -> Language {
        self.language
    }
}
