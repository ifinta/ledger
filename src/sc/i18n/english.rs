use zsozso_common::ScI18n;

pub struct EnglishSc;

impl ScI18n for EnglishSc {
    fn rpc_unreachable(&self, error: &str) -> String { format!("Soroban RPC unreachable: {}", error) }
    fn simulation_failed(&self, detail: &str) -> String { format!("Transaction simulation failed: {}", detail) }
    fn tx_submission_failed(&self, detail: &str) -> String { format!("Transaction submission failed: {}", detail) }
    fn tx_pending(&self) -> &'static str { "Transaction pending..." }
    fn tx_success(&self) -> &'static str { "Transaction succeeded." }
    fn tx_failed(&self, detail: &str) -> String { format!("Transaction failed: {}", detail) }
    fn tx_not_found(&self) -> &'static str { "Transaction not found." }
    fn invalid_response(&self, detail: &str) -> String { format!("Invalid RPC response: {}", detail) }
    fn contract_error(&self, detail: &str) -> String { format!("Contract error: {}", detail) }
}
