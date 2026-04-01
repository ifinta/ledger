pub mod zsozso_sc;
pub mod proof_of_zsozso_sc;
pub mod i18n;

pub use zsozso_sc::ZsozsoSc;
pub use proof_of_zsozso_sc::ProofOfZsozsoSc;

use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Sha256, Digest};
use stellar_strkey::{ed25519, Strkey};
use stellar_xdr::curr::{
    Hash, InvokeContractArgs, InvokeHostFunctionOp, HostFunction,
    MuxedAccount, Operation, OperationBody, Preconditions, SequenceNumber,
    SorobanAuthorizationEntry,
    SorobanTransactionData,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    DecoratedSignature, Signature, SignatureHint, BytesM, Memo,
    ScAddress, ScSymbol, ScVal, ContractId, Uint256,
    TimeBounds, TimePoint, VecM, WriteXdr, ReadXdr, Limits, StringM,
};

use super::NetworkEnvironment;
use crate::i18n::Language;
use self::i18n::sc_i18n;

/// Soroban RPC endpoint configuration
struct SorobanRpcConfig {
    pub rpc_url: &'static str,
    pub horizon_url: &'static str,
    pub passphrase: &'static str,
}

fn soroban_rpc(env: NetworkEnvironment) -> SorobanRpcConfig {
    match env {
        NetworkEnvironment::Test => SorobanRpcConfig {
            rpc_url: "https://soroban-testnet.stellar.org",
            horizon_url: "https://horizon-testnet.stellar.org",
            passphrase: "Test SDF Network ; September 2015",
        },
        NetworkEnvironment::Production => SorobanRpcConfig {
            rpc_url: "https://stellar-soroban-public.nodies.app",
            horizon_url: "https://horizon.stellar.org",
            passphrase: "Public Global Stellar Network ; September 2015",
        },
    }
}

// ── Soroban JSON-RPC request / response types ──────────────────────────────

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulateResult {
    transaction_data: Option<String>,
    min_resource_fee: Option<serde_json::Value>,
    results: Option<Vec<SimulateEntryResult>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SimulateEntryResult {
    auth: Option<Vec<String>>,
    xdr: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendTransactionResult {
    status: String,
    hash: Option<String>,
    error_result_xdr: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetTransactionResult {
    status: String,
    result_xdr: Option<String>,
}

#[derive(Deserialize)]
struct GetAccountResult {
    id: String,
    sequence: String,
}

/// Abstract interface for any Soroban smart contract.
/// Reusable helpers live here — concrete contracts implement `contract_id()`.
#[allow(async_fn_in_trait)]
pub trait SmartContract {
    /// The on-chain contract ID (hex-encoded or C... strkey)
    fn contract_id(&self) -> &str;

    /// Network environment (inherited from the ledger layer)
    fn network(&self) -> NetworkEnvironment;

    /// Language (inherited from the ledger layer)
    fn language(&self) -> Language;

    // ── Reusable helpers (provided) ────────────────────────────────────────

    /// Build an `InvokeContractArgs` XDR for a given function + args.
    fn build_invoke_args(
        &self,
        function_name: &str,
        args: Vec<ScVal>,
    ) -> Result<InvokeContractArgs, String> {
        let contract_bytes = parse_contract_id(self.contract_id())?;

        Ok(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
            function_name: ScSymbol(StringM::try_from(function_name)
                .map_err(|e| format!("Invalid function name: {e}"))?),
            args: VecM::try_from(args)
                .map_err(|e| format!("Too many args: {e}"))?,
        })
    }

    /// Full flow: build tx → simulate → attach resources → sign → send → poll.
    async fn invoke_contract(
        &self,
        secret_key: &str,
        function_name: &str,
        args: Vec<ScVal>,
    ) -> Result<String, String> {
        let rpc = soroban_rpc(self.network());
        let i18n = sc_i18n(self.language());

        web_sys::console::log_1(
            &format!(
                "[SC] invoke_contract: contract={} fn={} network={:?}",
                self.contract_id(), function_name, self.network()
            ).into(),
        );

        // 1. Decode caller key
        let priv_key = match Strkey::from_string(secret_key) {
            Ok(Strkey::PrivateKeyEd25519(pk)) => pk,
            _ => return Err("Invalid secret key".to_string()),
        };
        let signing_key = SigningKey::from_bytes(&priv_key.0);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let public_key_str =
            Strkey::PublicKeyEd25519(ed25519::PublicKey(pub_bytes)).to_string();

        // 2. Fetch sequence number
        let seq = fetch_sequence(&rpc, &public_key_str, &*i18n).await?;

        // 3. Build the unsigned invoke-host-function transaction
        let invoke_args = self.build_invoke_args(function_name, args)?;
        let unsigned_tx = build_invoke_tx(
            &pub_bytes,
            seq + 1,
            invoke_args,
        )?;

        // Wrap in an envelope (simulateTransaction expects TransactionEnvelope, not bare Transaction)
        let unsigned_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: unsigned_tx.clone(),
            signatures: VecM::default(),
        });

        let unsigned_xdr = unsigned_envelope.to_xdr_base64(Limits::none())
            .map_err(|e| format!("XDR error: {e}"))?;

        // 4. Simulate
        let sim = simulate_transaction(&rpc, &unsigned_xdr, &*i18n).await?;

        web_sys::console::log_1(
            &format!(
                "[SC] simulation result: error={:?} min_resource_fee={:?} has_tx_data={} results_count={}",
                sim.error,
                sim.min_resource_fee,
                sim.transaction_data.is_some(),
                sim.results.as_ref().map_or(0, |r| r.len()),
            ).into(),
        );

        if let Some(ref err) = sim.error {
            return Err(i18n.simulation_failed(err));
        }

        // 5. Extract resource data from simulation
        let soroban_data_xdr = sim.transaction_data.clone()
            .ok_or_else(|| i18n.simulation_failed("missing transactionData"))?;
        let soroban_data = SorobanTransactionData::from_xdr_base64(&soroban_data_xdr, Limits::none())
            .map_err(|e| i18n.invalid_response(&e.to_string()))?;

        let resource_fee: i64 = match &sim.min_resource_fee {
            Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
            _ => 0,
        };

        // Extract auth entries from simulation results
        let auth_entries = extract_auth_entries(&sim)?;

        // 6. Rebuild tx with simulation results attached
        let final_tx = attach_simulation(
            unsigned_tx,
            soroban_data,
            resource_fee,
            auth_entries,
        )?;

        // 7. Sign
        let signed_envelope = sign_transaction(
            &final_tx,
            &signing_key,
            &pub_bytes,
            rpc.passphrase,
        )?;

        let signed_xdr = signed_envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| format!("XDR error: {e}"))?;

        // 8. Submit
        let send_result = send_transaction(&rpc, &signed_xdr, &*i18n).await?;

        match send_result.status.as_str() {
            "ERROR" => {
                let detail = send_result.error_result_xdr.unwrap_or_default();
                Err(i18n.tx_submission_failed(&detail))
            }
            // PENDING or TRY_AGAIN_LATER — poll for result
            _ => {
                let hash = send_result.hash.unwrap_or_default();
                poll_transaction(&rpc, &hash, &*i18n).await
            }
        }
    }
}

// ── Private helpers ────────────────────────────────────────────────────────

/// Parse a contract ID from either hex (64 chars) or C... strkey.
fn parse_contract_id(id: &str) -> Result<[u8; 32], String> {
    // Try C... strkey first
    if let Ok(Strkey::Contract(stellar_strkey::Contract(bytes))) = Strkey::from_string(id) {
        return Ok(bytes);
    }
    // Try raw hex
    if id.len() == 64 {
        let mut out = [0u8; 32];
        for (i, chunk) in id.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            out[i] = u8::from_str_radix(hex_str, 16).map_err(|e| e.to_string())?;
        }
        return Ok(out);
    }
    Err(format!("Invalid contract ID: {}", id))
}

/// Build an unsigned Soroban invoke-host-function transaction.
fn build_invoke_tx(
    source_pub: &[u8; 32],
    seq_num: i64,
    invoke_args: InvokeContractArgs,
) -> Result<Transaction, String> {
    let now = (js_sys::Date::now() / 1000.0) as u64;

    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source_pub)),
        fee: 100, // will be adjusted after simulation
        seq_num: SequenceNumber(seq_num),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(now + 300),
        }),
        memo: Memo::None,
        operations: VecM::try_from(vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke_args),
                auth: VecM::default(),
            }),
        }])
        .map_err(|e| format!("Operation error: {e}"))?,
        ext: TransactionExt::V0, // placeholder — will be replaced after simulate
    })
}

/// Attach simulation results (resources, auth, fee) to the transaction.
fn attach_simulation(
    mut tx: Transaction,
    soroban_data: SorobanTransactionData,
    resource_fee: i64,
    auth_entries: Vec<SorobanAuthorizationEntry>,
) -> Result<Transaction, String> {
    // Update fee: base fee + resource fee
    tx.fee = (tx.fee as i64 + resource_fee) as u32;

    // Attach Soroban resource data
    tx.ext = TransactionExt::V1(soroban_data);

    // Attach auth to the operation
    if let Some(op) = tx.operations.first() {
        if let OperationBody::InvokeHostFunction(ref invoke_op) = op.body {
            let new_op = Operation {
                source_account: op.source_account.clone(),
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: invoke_op.host_function.clone(),
                    auth: VecM::try_from(auth_entries)
                        .map_err(|e| format!("Auth entries error: {e}"))?,
                }),
            };
            tx.operations = VecM::try_from(vec![new_op])
                .map_err(|e| format!("Operation error: {e}"))?;
        }
    }

    Ok(tx)
}

/// Sign a transaction, producing a TransactionEnvelope.
fn sign_transaction(
    tx: &Transaction,
    signing_key: &SigningKey,
    pub_bytes: &[u8; 32],
    passphrase: &str,
) -> Result<TransactionEnvelope, String> {
    let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let payload = TransactionSignaturePayload {
        network_id,
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };

    let payload_xdr = payload
        .to_xdr(Limits::none())
        .map_err(|e| format!("XDR error: {e}"))?;
    let tx_hash = Sha256::digest(&payload_xdr);
    let sig_bytes = signing_key.sign(&tx_hash).to_bytes();

    let mut hint = [0u8; 4];
    hint.copy_from_slice(&pub_bytes[28..32]);

    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::try_from(vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(BytesM::try_from(sig_bytes).unwrap()),
        }])
        .unwrap(),
    }))
}

/// Extract `SorobanAuthorizationEntry` items from simulation results.
fn extract_auth_entries(
    sim: &SimulateResult,
) -> Result<Vec<SorobanAuthorizationEntry>, String> {
    let mut entries = Vec::new();
    if let Some(ref results) = sim.results {
        for r in results {
            if let Some(ref auths) = r.auth {
                for auth_xdr in auths {
                    let entry = SorobanAuthorizationEntry::from_xdr_base64(auth_xdr, Limits::none())
                        .map_err(|e| format!("Auth XDR parse error: {e}"))?;
                    entries.push(entry);
                }
            }
        }
    }
    Ok(entries)
}

// ── Soroban JSON-RPC calls ─────────────────────────────────────────────────

use self::i18n::ScI18n;

async fn rpc_call(
    rpc: &SorobanRpcConfig,
    method: &str,
    params: serde_json::Value,
    i18n: &dyn ScI18n,
) -> Result<serde_json::Value, String> {
    let body = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
    };

    let request_json = serde_json::to_string_pretty(&body).unwrap_or_default();

    web_sys::console::log_1(
        &format!("[SC RPC] → {} {}\n{}", method, rpc.rpc_url, request_json).into(),
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(rpc.rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            let msg = i18n.rpc_unreachable(&e.to_string());
            web_sys::console::error_1(&format!("[SC RPC] network error: {}", e).into());
            msg
        })?;

    let status = resp.status();
    let raw_body = resp.text().await.map_err(|e| {
        let msg = i18n.invalid_response(&e.to_string());
        web_sys::console::error_1(&format!("[SC RPC] body read error: {}", e).into());
        msg
    })?;

    web_sys::console::log_1(
        &format!("[SC RPC] ← {} (HTTP {})\n{}", method, status, raw_body).into(),
    );

    let rpc_resp: RpcResponse = serde_json::from_str(&raw_body)
        .map_err(|e| {
            web_sys::console::error_1(
                &format!("[SC RPC] JSON parse error: {}\nraw: {}", e, raw_body).into(),
            );
            i18n.invalid_response(&e.to_string())
        })?;

    if let Some(err) = rpc_resp.error {
        web_sys::console::error_1(
            &format!("[SC RPC] RPC error from {}: {}", method, err.message).into(),
        );
        return Err(i18n.contract_error(&err.message));
    }

    rpc_resp
        .result
        .ok_or_else(|| i18n.invalid_response("null result"))
}

/// Fetch account sequence number via the Horizon REST API
/// (Soroban RPC does not expose a `getAccount` method).
async fn fetch_sequence(
    rpc: &SorobanRpcConfig,
    public_key: &str,
    i18n: &dyn ScI18n,
) -> Result<i64, String> {
    let url = format!("{}/accounts/{}", rpc.horizon_url, public_key);

    web_sys::console::log_1(&format!("[SC] fetch_sequence via Horizon: {}", url).into());

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| i18n.rpc_unreachable(&e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        web_sys::console::error_1(
            &format!("[SC] Horizon error ({}): {}", status, body).into(),
        );
        return Err(i18n.invalid_response(&format!("HTTP {}", status)));
    }

    let acct: GetAccountResult = resp
        .json()
        .await
        .map_err(|e| i18n.invalid_response(&e.to_string()))?;

    acct.sequence
        .parse::<i64>()
        .map_err(|e| i18n.invalid_response(&e.to_string()))
}

async fn simulate_transaction(
    rpc: &SorobanRpcConfig,
    tx_xdr_base64: &str,
    i18n: &dyn ScI18n,
) -> Result<SimulateResult, String> {
    let params = serde_json::json!({ "transaction": tx_xdr_base64 });
    let result = rpc_call(rpc, "simulateTransaction", params, i18n).await?;

    serde_json::from_value(result)
        .map_err(|e| i18n.invalid_response(&e.to_string()))
}

async fn send_transaction(
    rpc: &SorobanRpcConfig,
    tx_xdr_base64: &str,
    i18n: &dyn ScI18n,
) -> Result<SendTransactionResult, String> {
    let params = serde_json::json!({ "transaction": tx_xdr_base64 });
    let result = rpc_call(rpc, "sendTransaction", params, i18n).await?;

    serde_json::from_value(result)
        .map_err(|e| i18n.invalid_response(&e.to_string()))
}

async fn get_transaction(
    rpc: &SorobanRpcConfig,
    hash: &str,
    i18n: &dyn ScI18n,
) -> Result<GetTransactionResult, String> {
    let params = serde_json::json!({ "hash": hash });
    let result = rpc_call(rpc, "getTransaction", params, i18n).await?;

    serde_json::from_value(result)
        .map_err(|e| i18n.invalid_response(&e.to_string()))
}

/// Poll `getTransaction` until the tx settles (success / failure / timeout).
async fn poll_transaction(
    rpc: &SorobanRpcConfig,
    hash: &str,
    i18n: &dyn ScI18n,
) -> Result<String, String> {
    // Poll up to ~30 seconds (6 × 5 s)
    for _ in 0..6 {
        sleep_ms(5000).await;

        let result = get_transaction(rpc, hash, i18n).await?;
        match result.status.as_str() {
            "SUCCESS" => return Ok(i18n.tx_success().to_string()),
            "FAILED" => return Err(i18n.tx_failed(
                &result.result_xdr.unwrap_or_default(),
            )),
            "NOT_FOUND" => continue, // still pending
            other => return Err(i18n.tx_failed(other)),
        }
    }

    Err(i18n.tx_not_found().to_string())
}

/// Async sleep helper (WASM only).
async fn sleep_ms(ms: u64) {
    gloo_timers::future::TimeoutFuture::new(ms as u32).await;
}
