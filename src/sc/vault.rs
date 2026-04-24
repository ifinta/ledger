//! Stellar implementation of the ledger-agnostic [`crate::vault::Vault`] trait.
//!
//! This impl treats a Soroban smart contract as a black box: on first use for
//! a given account it uploads the contract WASM (if not yet installed
//! network-wide) and deploys a fresh per-user instance with the user as
//! owner. Subsequent calls are normal `InvokeHostFunction` transactions or
//! simulate-only reads.
//!
//! The WASM bytes are supplied by the caller at construction time (the UI
//! ships them inside its bundle). Changing the contract just means rebuilding
//! the WASM and shipping a new bundle — there is no on-chain upgrade path.

use ed25519_dalek::SigningKey;
use rand::RngCore;
use sha2::{Digest, Sha256};
use stellar_strkey::{ed25519, Contract as StrContract, Strkey};
use stellar_xdr::curr::{
    AccountId, BytesM, ContractExecutable, ContractId, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateContractArgsV2, Hash, HashIdPreimage,
    HashIdPreimageContractId, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Int128Parts, Limits, Operation, OperationBody,
    PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, SorobanAuthorizationEntry,
    SorobanTransactionData, StringM, Transaction, TransactionEnvelope,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

use super::i18n::sc_i18n;
use super::{
    attach_simulation, build_host_fn_tx, extract_auth_entries, fetch_sequence,
    parse_contract_id, poll_transaction, send_transaction, sign_transaction,
    simulate_transaction, soroban_rpc, SorobanRpcConfig,
};
use crate::vault::Vault;
use crate::NetworkEnvironment;
use zsozso_common::Language;

/// Local tracing helper — routed through the same `[Vault]`-tagged
/// `console.log` stream the UI's log_bridge already captures into the
/// IndexedDB ring buffer. Heavy instrumentation lives here to diagnose
/// `StellarVault::init` (the smart-contract upload + deploy flow).
fn vlog(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

fn host_fn_kind(host_fn: &HostFunction) -> &'static str {
    match host_fn {
        HostFunction::InvokeContract(_) => "InvokeContract",
        HostFunction::CreateContract(_) => "CreateContract",
        HostFunction::CreateContractV2(_) => "CreateContractV2",
        HostFunction::UploadContractWasm(_) => "UploadContractWasm",
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ── Construction ──────────────────────────────────────────────────────────

/// Stellar (Soroban) implementation of [`Vault`].
///
/// Construct with the WASM bytes shipped in the UI bundle:
///
/// ```ignore
/// let wasm = include_bytes!(".../proof_of_zsozso_sc.wasm");
/// let vault = StellarVault::new(network, lang, wasm.to_vec());
/// ```
pub struct StellarVault {
    network: NetworkEnvironment,
    language: Language,
    wasm_code: Vec<u8>,
}

impl StellarVault {
    pub fn new(
        network: NetworkEnvironment,
        language: Language,
        wasm_code: Vec<u8>,
    ) -> Self {
        Self {
            network,
            language,
            wasm_code,
        }
    }

    fn rpc(&self) -> SorobanRpcConfig {
        soroban_rpc(self.network)
    }

    /// SHA-256 of the WASM bytes — the hash Soroban uses as the code-entry key.
    fn wasm_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.wasm_code).into()
    }
}

// ── Trait impl ────────────────────────────────────────────────────────────

impl Vault for StellarVault {
    async fn init(
        &self,
        secret_key: &str,
        token_id: &str,
    ) -> Result<String, String> {
        vlog(&format!(
            "[Vault init] BEGIN network={:?} wasm_len={} token_id={}",
            self.network, self.wasm_code.len(), token_id
        ));
        let (signing_key, pub_bytes) = decode_secret(secret_key)?;
        let owner_strkey = pubkey_to_strkey(&pub_bytes);
        vlog(&format!("[Vault init] owner_strkey={}", owner_strkey));

        let wasm_hash = self.wasm_hash();
        vlog(&format!("[Vault init] wasm_hash=sha256:{}", hex32(&wasm_hash)));

        // 1. Upload WASM (idempotent on Soroban — re-uploads same hash are no-ops).
        vlog("[Vault init] phase 1/3: UploadContractWasm — building HostFunction");
        let upload_fn = HostFunction::UploadContractWasm(
            BytesM::try_from(self.wasm_code.clone())
                .map_err(|e| {
                    vlog(&format!("[Vault init] phase 1 FAIL (WASM too large): {}", e));
                    format!("WASM too large: {e}")
                })?,
        );
        vlog("[Vault init] phase 1/3: submitting UploadContractWasm tx …");
        match submit_host_function(
            &self.rpc(),
            self.language,
            &signing_key,
            &pub_bytes,
            upload_fn,
        )
        .await
        {
            Ok(hash) => vlog(&format!(
                "[Vault init] phase 1/3 OK — upload tx hash={}",
                hash
            )),
            Err(e) => {
                vlog(&format!("[Vault init] phase 1/3 FAIL: {}", e));
                return Err(e);
            }
        }

        // 2. Compute the future contract ID locally from (network_id, preimage).
        vlog("[Vault init] phase 2/3: deriving future contract id …");
        let salt = random_salt();
        vlog(&format!("[Vault init] phase 2/3: salt={}", hex32(&salt)));
        let owner_address = ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pub_bytes)),
        ));
        let preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: owner_address.clone(),
            salt: Uint256(salt),
        });
        let contract_id = derive_contract_id(self.rpc().passphrase, &preimage)
            .map_err(|e| {
                vlog(&format!("[Vault init] phase 2/3 FAIL (derive_contract_id): {}", e));
                e
            })?;
        let contract_strkey =
            Strkey::Contract(StrContract(contract_id)).to_string();
        vlog(&format!(
            "[Vault init] phase 2/3 OK — future contract_id={}",
            contract_strkey
        ));

        // 3. Build constructor args: (owner: String, token: String).
        vlog("[Vault init] phase 3/3: building constructor args (owner, token) …");
        let owner_scval = ScVal::String(
            StringM::try_from(owner_strkey.clone())
                .map_err(|e| {
                    vlog(&format!("[Vault init] phase 3 owner strkey err: {}", e));
                    format!("owner strkey: {e}")
                })?
                .into(),
        );
        let token_scval = ScVal::String(
            StringM::try_from(token_id.to_string())
                .map_err(|e| {
                    vlog(&format!("[Vault init] phase 3 token strkey err: {}", e));
                    format!("token strkey: {e}")
                })?
                .into(),
        );
        let constructor_args = VecM::try_from(vec![owner_scval, token_scval])
            .map_err(|e| {
                vlog(&format!("[Vault init] phase 3 constructor args err: {}", e));
                format!("constructor args: {e}")
            })?;

        // 4. Deploy.
        vlog("[Vault init] phase 3/3: submitting CreateContractV2 tx …");
        let create_fn = HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: preimage,
            executable: ContractExecutable::Wasm(Hash(self.wasm_hash())),
            constructor_args,
        });
        match submit_host_function(
            &self.rpc(),
            self.language,
            &signing_key,
            &pub_bytes,
            create_fn,
        )
        .await
        {
            Ok(hash) => vlog(&format!(
                "[Vault init] phase 3/3 OK — create tx hash={}",
                hash
            )),
            Err(e) => {
                vlog(&format!("[Vault init] phase 3/3 FAIL: {}", e));
                return Err(e);
            }
        }

        vlog(&format!(
            "[Vault init] END ok contract_strkey={}",
            contract_strkey
        ));
        Ok(contract_strkey)
    }

    async fn ping(
        &self,
        secret_key: &str,
        vault_id: &str,
    ) -> Result<String, String> {
        self.invoke_tx(secret_key, vault_id, "ping", vec![]).await
    }

    async fn withdraw(
        &self,
        secret_key: &str,
        vault_id: &str,
    ) -> Result<String, String> {
        self.invoke_tx(secret_key, vault_id, "withdraw", vec![])
            .await
    }

    async fn owner(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<String, String> {
        let sv = self
            .simulate_read(caller_public_key, vault_id, "owner")
            .await?;
        scval_to_address_strkey(&sv)
    }

    async fn token(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<String, String> {
        let sv = self
            .simulate_read(caller_public_key, vault_id, "token")
            .await?;
        scval_to_address_strkey(&sv)
    }

    async fn unlock_ledger(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<u32, String> {
        let sv = self
            .simulate_read(caller_public_key, vault_id, "unlock_ledger")
            .await?;
        match sv {
            ScVal::U32(v) => Ok(v),
            other => Err(format!("expected U32, got {other:?}")),
        }
    }

    async fn balance(
        &self,
        caller_public_key: &str,
        vault_id: &str,
    ) -> Result<i128, String> {
        let sv = self
            .simulate_read(caller_public_key, vault_id, "balance")
            .await?;
        scval_to_i128(&sv)
    }
}

// ── Invoke + simulate helpers ─────────────────────────────────────────────

impl StellarVault {
    /// Full invoke flow (simulate → sign → send → poll).
    async fn invoke_tx(
        &self,
        secret_key: &str,
        vault_id: &str,
        function_name: &str,
        args: Vec<ScVal>,
    ) -> Result<String, String> {
        vlog(&format!(
            "[Vault invoke_tx] BEGIN fn={} vault_id={} network={:?} args_count={}",
            function_name,
            vault_id,
            self.network,
            args.len()
        ));
        let (signing_key, pub_bytes) = decode_secret(secret_key)?;
        let contract_bytes = parse_contract_id(vault_id).map_err(|e| {
            vlog(&format!(
                "[Vault invoke_tx] fn={} parse_contract_id FAIL: {}",
                function_name, e
            ));
            e
        })?;
        let host_fn = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
            function_name: ScSymbol(
                StringM::try_from(function_name)
                    .map_err(|e| format!("fn name: {e}"))?,
            ),
            args: VecM::try_from(args).map_err(|e| format!("args: {e}"))?,
        });
        let result = submit_host_function(
            &self.rpc(),
            self.language,
            &signing_key,
            &pub_bytes,
            host_fn,
        )
        .await;
        match &result {
            Ok(h) => vlog(&format!(
                "[Vault invoke_tx] END fn={} ok hash={}",
                function_name, h
            )),
            Err(e) => vlog(&format!(
                "[Vault invoke_tx] END fn={} err={}",
                function_name, e
            )),
        }
        result
    }

    /// Simulate-only read: no tx submitted, returns the contract's return ScVal.
    async fn simulate_read(
        &self,
        caller_public_key: &str,
        vault_id: &str,
        function_name: &str,
    ) -> Result<ScVal, String> {
        let rpc = self.rpc();
        let i18n = sc_i18n(self.language);

        let pub_bytes = strkey_to_pubbytes(caller_public_key)?;
        let contract_bytes = parse_contract_id(vault_id)?;

        let seq = fetch_sequence(&rpc, caller_public_key, &*i18n).await?;

        let host_fn = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
            function_name: ScSymbol(
                StringM::try_from(function_name)
                    .map_err(|e| format!("fn name: {e}"))?,
            ),
            args: VecM::default(),
        });
        let unsigned_tx = build_host_fn_tx(&pub_bytes, seq + 1, host_fn)?;
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: unsigned_tx,
            signatures: VecM::default(),
        });
        let xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| format!("XDR error: {e}"))?;

        let sim = simulate_transaction(&rpc, &xdr, &*i18n).await?;
        if let Some(ref err) = sim.error {
            return Err(i18n.simulation_failed(err));
        }

        let results = sim
            .results
            .ok_or_else(|| "simulation returned no results".to_string())?;
        let first = results
            .into_iter()
            .next()
            .ok_or_else(|| "simulation returned empty results".to_string())?;
        let xdr = first
            .xdr
            .ok_or_else(|| "simulation result missing xdr".to_string())?;
        ScVal::from_xdr_base64(&xdr, Limits::none())
            .map_err(|e| format!("ScVal parse: {e}"))
    }
}

/// Submit a one-operation host-function transaction (upload, create, or invoke).
async fn submit_host_function(
    rpc: &SorobanRpcConfig,
    lang: Language,
    signing_key: &SigningKey,
    pub_bytes: &[u8; 32],
    host_fn: HostFunction,
) -> Result<String, String> {
    let i18n = sc_i18n(lang);
    let kind = host_fn_kind(&host_fn);

    let caller = pubkey_to_strkey(pub_bytes);
    vlog(&format!(
        "[Vault submit_host_function] BEGIN kind={} caller={}",
        kind, caller
    ));
    let seq = match fetch_sequence(rpc, &caller, &*i18n).await {
        Ok(s) => {
            vlog(&format!(
                "[Vault submit_host_function] kind={} seq fetched={}",
                kind, s
            ));
            s
        }
        Err(e) => {
            vlog(&format!(
                "[Vault submit_host_function] kind={} fetch_sequence FAIL: {}",
                kind, e
            ));
            return Err(e);
        }
    };

    let unsigned_tx = build_host_fn_tx(pub_bytes, seq + 1, host_fn).map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} build_host_fn_tx FAIL: {}",
            kind, e
        ));
        e
    })?;
    let unsigned_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: unsigned_tx.clone(),
        signatures: VecM::default(),
    });
    let unsigned_xdr = unsigned_envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| {
            vlog(&format!(
                "[Vault submit_host_function] kind={} unsigned XDR err: {}",
                kind, e
            ));
            format!("XDR error: {e}")
        })?;
    vlog(&format!(
        "[Vault submit_host_function] kind={} unsigned_xdr_len={}",
        kind,
        unsigned_xdr.len()
    ));

    vlog(&format!(
        "[Vault submit_host_function] kind={} calling simulate …",
        kind
    ));
    let sim = simulate_transaction(rpc, &unsigned_xdr, &*i18n).await.map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} simulate TRANSPORT FAIL: {}",
            kind, e
        ));
        e
    })?;
    if let Some(ref err) = sim.error {
        vlog(&format!(
            "[Vault submit_host_function] kind={} simulate REJECTED: {}",
            kind, err
        ));
        return Err(i18n.simulation_failed(err));
    }
    vlog(&format!(
        "[Vault submit_host_function] kind={} simulate OK (min_fee={:?}, has_tx_data={}, auth_in_sim_results={})",
        kind,
        sim.min_resource_fee,
        sim.transaction_data.is_some(),
        sim.results.as_ref().map(|r| r.len()).unwrap_or(0)
    ));

    let soroban_data_xdr = sim
        .transaction_data
        .clone()
        .ok_or_else(|| {
            vlog(&format!(
                "[Vault submit_host_function] kind={} simulate missing transactionData",
                kind
            ));
            i18n.simulation_failed("missing transactionData")
        })?;
    let soroban_data =
        SorobanTransactionData::from_xdr_base64(&soroban_data_xdr, Limits::none())
            .map_err(|e| {
                vlog(&format!(
                    "[Vault submit_host_function] kind={} soroban_data parse err: {}",
                    kind, e
                ));
                i18n.invalid_response(&e.to_string())
            })?;
    let resource_fee: i64 = match &sim.min_resource_fee {
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
        _ => 0,
    };
    vlog(&format!(
        "[Vault submit_host_function] kind={} resource_fee={}",
        kind, resource_fee
    ));
    let auth_entries = extract_auth_entries(&sim).map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} extract_auth_entries FAIL: {}",
            kind, e
        ));
        e
    })?;
    vlog(&format!(
        "[Vault submit_host_function] kind={} auth_entries_count={}",
        kind,
        auth_entries.len()
    ));

    // Rebuild the operation carrying the original host function + auth.
    let mut final_tx = unsigned_tx;
    final_tx = attach_auth_to_tx(final_tx, auth_entries).map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} attach_auth_to_tx FAIL: {}",
            kind, e
        ));
        e
    })?;
    final_tx = attach_simulation(final_tx, soroban_data, resource_fee, vec![]).map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} attach_simulation FAIL: {}",
            kind, e
        ));
        e
    })?;

    let signed =
        sign_transaction(&final_tx, signing_key, pub_bytes, rpc.passphrase).map_err(|e| {
            vlog(&format!(
                "[Vault submit_host_function] kind={} sign_transaction FAIL: {}",
                kind, e
            ));
            e
        })?;
    let signed_xdr = signed
        .to_xdr_base64(Limits::none())
        .map_err(|e| {
            vlog(&format!(
                "[Vault submit_host_function] kind={} signed XDR err: {}",
                kind, e
            ));
            format!("XDR error: {e}")
        })?;
    vlog(&format!(
        "[Vault submit_host_function] kind={} signed_xdr_len={} — sending to RPC …",
        kind,
        signed_xdr.len()
    ));

    let send_result = send_transaction(rpc, &signed_xdr, &*i18n).await.map_err(|e| {
        vlog(&format!(
            "[Vault submit_host_function] kind={} send_transaction TRANSPORT FAIL: {}",
            kind, e
        ));
        e
    })?;
    vlog(&format!(
        "[Vault submit_host_function] kind={} send result: status={} hash={:?} err_xdr={:?}",
        kind,
        send_result.status,
        send_result.hash,
        send_result.error_result_xdr
    ));
    match send_result.status.as_str() {
        "ERROR" => {
            let detail = send_result.error_result_xdr.unwrap_or_default();
            vlog(&format!(
                "[Vault submit_host_function] kind={} send ERROR: {}",
                kind, detail
            ));
            Err(i18n.tx_submission_failed(&detail))
        }
        _ => {
            let hash = send_result.hash.unwrap_or_default();
            vlog(&format!(
                "[Vault submit_host_function] kind={} polling tx {} …",
                kind, hash
            ));
            match poll_transaction(rpc, &hash, &*i18n).await {
                Ok(msg) => {
                    vlog(&format!(
                        "[Vault submit_host_function] kind={} poll OK: {}",
                        kind, msg
                    ));
                    Ok(msg)
                }
                Err(e) => {
                    vlog(&format!(
                        "[Vault submit_host_function] kind={} poll FAIL: {}",
                        kind, e
                    ));
                    Err(e)
                }
            }
        }
    }
}

/// Re-wrap the tx's operation with the given auth entries (keeping its host function).
fn attach_auth_to_tx(
    mut tx: Transaction,
    auth_entries: Vec<SorobanAuthorizationEntry>,
) -> Result<Transaction, String> {
    if let Some(op) = tx.operations.first() {
        if let OperationBody::InvokeHostFunction(ref invoke_op) = op.body {
            let new_op = Operation {
                source_account: op.source_account.clone(),
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: invoke_op.host_function.clone(),
                    auth: VecM::try_from(auth_entries)
                        .map_err(|e| format!("Auth entries: {e}"))?,
                }),
            };
            tx.operations = VecM::try_from(vec![new_op])
                .map_err(|e| format!("Operation: {e}"))?;
        }
    }
    Ok(tx)
}

// ── Crypto / encoding helpers ─────────────────────────────────────────────

fn decode_secret(secret_key: &str) -> Result<(SigningKey, [u8; 32]), String> {
    let priv_key = match Strkey::from_string(secret_key) {
        Ok(Strkey::PrivateKeyEd25519(pk)) => pk,
        _ => return Err("Invalid secret key".to_string()),
    };
    let signing_key = SigningKey::from_bytes(&priv_key.0);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    Ok((signing_key, pub_bytes))
}

fn pubkey_to_strkey(pub_bytes: &[u8; 32]) -> String {
    Strkey::PublicKeyEd25519(ed25519::PublicKey(*pub_bytes)).to_string()
}

fn strkey_to_pubbytes(strkey: &str) -> Result<[u8; 32], String> {
    match Strkey::from_string(strkey) {
        Ok(Strkey::PublicKeyEd25519(pk)) => Ok(pk.0),
        _ => Err(format!("Invalid public key strkey: {strkey}")),
    }
}

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Derive the future contract ID locally: sha256 of the xdr-encoded
/// `HashIdPreimage::ContractId { network_id, preimage }`.
fn derive_contract_id(
    passphrase: &str,
    preimage: &ContractIdPreimage,
) -> Result<[u8; 32], String> {
    let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let hip = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id,
        contract_id_preimage: preimage.clone(),
    });
    let bytes = hip
        .to_xdr(Limits::none())
        .map_err(|e| format!("preimage xdr: {e}"))?;
    Ok(Sha256::digest(&bytes).into())
}

fn scval_to_address_strkey(sv: &ScVal) -> Result<String, String> {
    match sv {
        ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(bytes)),
        ))) => Ok(Strkey::PublicKeyEd25519(ed25519::PublicKey(*bytes)).to_string()),
        ScVal::Address(ScAddress::Contract(ContractId(Hash(bytes)))) => {
            Ok(Strkey::Contract(StrContract(*bytes)).to_string())
        }
        other => Err(format!("expected Address, got {other:?}")),
    }
}

fn scval_to_i128(sv: &ScVal) -> Result<i128, String> {
    match sv {
        ScVal::I128(Int128Parts { hi, lo }) => {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&hi.to_be_bytes());
            bytes[8..].copy_from_slice(&lo.to_be_bytes());
            Ok(i128::from_be_bytes(bytes))
        }
        other => Err(format!("expected I128, got {other:?}")),
    }
}
