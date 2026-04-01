use super::LedgerI18n;

pub struct HungarianLedger;

impl LedgerI18n for HungarianLedger {
    fn faucet_unavailable(&self) -> &'static str { "Faucet nem elérhető ezen a hálózaton." }
    fn account_activated(&self) -> &'static str { "Fiók aktiválva!" }
    fn faucet_error(&self, status: &str) -> String { format!("Faucet hiba: {}", status) }
    fn network_error(&self, error: &str) -> String { format!("Hálózati hiba: {}", error) }
    fn invalid_secret_key(&self) -> &'static str { "Érvénytelen titkos kulcs." }
    fn horizon_unreachable(&self, error: &str) -> String { format!("Horizon nem elérhető: {}", error) }
    fn account_not_found(&self) -> &'static str { "Fiók nem található! Előbb aktiváld!" }
    fn json_error(&self, error: &str) -> String { format!("JSON hiba: {}", error) }
    fn xdr_serial_error(&self, error: &str) -> String { format!("XDR szerializálási hiba: {:?}", error) }
    fn xdr_error(&self, error: &str) -> String { format!("XDR hiba: {:?}", error) }
    fn tx_accepted(&self) -> &'static str { "Tranzakció elfogadva." }
    fn error(&self, status: &str) -> String { format!("Hiba: {}", status) }
}
