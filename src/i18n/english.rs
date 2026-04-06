use zsozso_common::LedgerI18n;

pub struct EnglishLedger;

impl LedgerI18n for EnglishLedger {
    fn faucet_unavailable(&self) -> &'static str { "Faucet not available on this network." }
    fn account_activated(&self) -> &'static str { "Account activated!" }
    fn faucet_error(&self, status: &str) -> String { format!("Faucet error: {}", status) }
    fn network_error(&self, error: &str) -> String { format!("Network error: {}", error) }
    fn invalid_secret_key(&self) -> &'static str { "Invalid secret key." }
    fn horizon_unreachable(&self, error: &str) -> String { format!("Horizon unreachable: {}", error) }
    fn account_not_found(&self) -> &'static str { "Account not found! Activate it first!" }
    fn json_error(&self, error: &str) -> String { format!("JSON error: {}", error) }
    fn xdr_serial_error(&self, error: &str) -> String { format!("XDR serialization error: {:?}", error) }
    fn xdr_error(&self, error: &str) -> String { format!("XDR error: {:?}", error) }
    fn tx_accepted(&self) -> &'static str { "Transaction accepted." }
    fn error(&self, status: &str) -> String { format!("Error: {}", status) }
}
