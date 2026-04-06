use rand::RngCore;
use zeroize::Zeroize;

use ed25519_dalek::{Signer, SigningKey};
use stellar_strkey::{ed25519, Strkey};
use stellar_xdr::curr::{
    MuxedAccount, Uint256, Transaction, SequenceNumber, Memo, Operation,
    OperationBody, PaymentOp, Asset, Preconditions, TransactionExt, VecM,
    TransactionEnvelope, TransactionV1Envelope, DecoratedSignature, Hash,
    Signature, BytesM, SignatureHint, WriteXdr, Limits, TimeBounds, TimePoint,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
};
use sha2::{Sha256, Digest};
use serde::Deserialize;

use super::{KeyPair, Ledger, NetworkEnvironment, NetworkInfo};
use zsozso_common::Language;
use super::i18n::ledger_i18n;

struct StellarNetworkConfig {
    name: &'static str,
    horizon_url: &'static str,
    passphrase: &'static str,
    friendbot_url: Option<&'static str>,
}

fn stellar_network(env: NetworkEnvironment) -> StellarNetworkConfig {
    match env {
        NetworkEnvironment::Test => StellarNetworkConfig {
            name: "TESTNET ⚠️",
            horizon_url: "https://horizon-testnet.stellar.org",
            passphrase: "Test SDF Network ; September 2015",
            friendbot_url: Some("https://friendbot.stellar.org"),
        },
        NetworkEnvironment::Production => StellarNetworkConfig {
            name: "MAINNET",
            horizon_url: "https://horizon.stellar.org",
            passphrase: "Public Global Stellar Network ; September 2015",
            friendbot_url: None,
        },
    }
}

#[derive(Deserialize)]
struct HorizonAccount {
    sequence: String,
}

pub struct StellarLedger {
    network: NetworkEnvironment,
    language: Language,
}

impl StellarLedger {
    pub fn new(network: NetworkEnvironment, language: Language) -> Self {
        Self { network, language }
    }
}

impl Ledger for StellarLedger {
    fn network_info(&self) -> NetworkInfo {
        let net = stellar_network(self.network);
        NetworkInfo {
            name: net.name,
            has_faucet: net.friendbot_url.is_some(),
        }
    }

    fn generate_keypair(&self) -> KeyPair {
        let mut seed_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut seed_bytes);

        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let secret_key = Strkey::PrivateKeyEd25519(ed25519::PrivateKey(seed_bytes)).to_string();
        let public_key = Strkey::PublicKeyEd25519(ed25519::PublicKey(pub_bytes)).to_string();

        seed_bytes.zeroize();

        KeyPair { public_key, secret_key }
    }

    fn public_key_from_secret(&self, secret: &str) -> Option<String> {
        if let Ok(Strkey::PrivateKeyEd25519(priv_key)) = Strkey::from_string(secret) {
            let signing_key = SigningKey::from_bytes(&priv_key.0);
            let pub_bytes = signing_key.verifying_key().to_bytes();
            Some(Strkey::PublicKeyEd25519(ed25519::PublicKey(pub_bytes)).to_string())
        } else {
            None
        }
    }

    async fn activate_test_account(&self, public_key: &str) -> Result<String, String> {
        let net = stellar_network(self.network);
        let i18n = ledger_i18n(self.language);
        let friendbot_base = net.friendbot_url
            .ok_or_else(|| i18n.faucet_unavailable().to_string())?;

        let url = format!("{}/?addr={}", friendbot_base, public_key);

        match reqwest::get(url).await {
            Ok(resp) if resp.status().is_success() => {
                Ok(i18n.account_activated().to_string())
            }
            Ok(resp) => {
                Err(i18n.faucet_error(&resp.status().to_string()))
            }
            Err(e) => {
                Err(i18n.network_error(&e.to_string()))
            }
        }
    }

    async fn build_self_payment(
        &self,
        secret_key: &str,
        amount: i64,
    ) -> Result<(String, i64), String> {
        let net = stellar_network(self.network);
        let i18n = ledger_i18n(self.language);

        // 1. Decode key
        let priv_key = match Strkey::from_string(secret_key) {
            Ok(Strkey::PrivateKeyEd25519(pk)) => pk,
            _ => return Err(i18n.invalid_secret_key().to_string()),
        };

        let signing_key = SigningKey::from_bytes(&priv_key.0);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let public_key_str = Strkey::PublicKeyEd25519(ed25519::PublicKey(pub_bytes)).to_string();

        // 2. Fetch sequence number
        let url = format!("{}/accounts/{}", net.horizon_url, public_key_str);
        let client = reqwest::Client::new();

        let response = client.get(url).send().await
            .map_err(|e| i18n.horizon_unreachable(&e.to_string()))?;

        if !response.status().is_success() {
            return Err(i18n.account_not_found().to_string());
        }

        let account_data: HorizonAccount = response.json().await
            .map_err(|e| i18n.json_error(&e.to_string()))?;

        let current_seq: i64 = account_data.sequence.parse().unwrap_or(0);
        let next_seq = current_seq + 1;

        // 3. Build transaction
        let current_unix_time = (js_sys::Date::now() / 1000.0) as u64;

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(pub_bytes)),
            fee: 100,
            seq_num: SequenceNumber(next_seq),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(current_unix_time + 300),
            }),
            memo: Memo::None,
            operations: VecM::try_from(vec![
                Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination: MuxedAccount::Ed25519(Uint256(pub_bytes)),
                        asset: Asset::Native,
                        amount,
                    }),
                }
            ]).unwrap(),
            ext: TransactionExt::V0,
        };

        // 4. Sign
        let network_id = Hash(Sha256::digest(net.passphrase.as_bytes()).into());
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };

        let tx_payload_xdr = payload.to_xdr(Limits::none())
            .map_err(|e| i18n.xdr_serial_error(&e.to_string()))?;
        let tx_hash = Sha256::digest(&tx_payload_xdr);
        let sig_bytes = signing_key.sign(&tx_hash).to_bytes();

        let mut hint_bytes = [0u8; 4];
        hint_bytes.copy_from_slice(&pub_bytes[pub_bytes.len() - 4..]);

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::try_from(vec![
                DecoratedSignature {
                    hint: SignatureHint(hint_bytes),
                    signature: Signature(BytesM::try_from(sig_bytes).unwrap()),
                }
            ]).unwrap(),
        });

        let xdr = envelope.to_xdr_base64(Limits::none())
            .map_err(|e| i18n.xdr_error(&e.to_string()))?;

        Ok((xdr, next_seq))
    }

    async fn submit_transaction(&self, xdr: &str) -> Result<String, String> {
        let net = stellar_network(self.network);
        let i18n = ledger_i18n(self.language);
        let url = format!("{}/transactions", net.horizon_url);
        let client = reqwest::Client::new();
        let params = [("tx", xdr)];

        let response = client.post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .map_err(|e| i18n.network_error(&e.to_string()))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.is_success() {
            Ok(i18n.tx_accepted().to_string())
        } else {
            web_sys::console::log_1(&format!("Horizon error ({}): {}", status, body).into());
            Err(i18n.error(&status.to_string()))
        }
    }
}