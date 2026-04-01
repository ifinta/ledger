use super::LedgerI18n;

pub struct GermanLedger;

impl LedgerI18n for GermanLedger {
    fn faucet_unavailable(&self) -> &'static str { "Faucet in diesem Netzwerk nicht verfügbar." }
    fn account_activated(&self) -> &'static str { "Konto aktiviert!" }
    fn faucet_error(&self, status: &str) -> String { format!("Faucet-Fehler: {}", status) }
    fn network_error(&self, error: &str) -> String { format!("Netzwerkfehler: {}", error) }
    fn invalid_secret_key(&self) -> &'static str { "Ungültiger geheimer Schlüssel." }
    fn horizon_unreachable(&self, error: &str) -> String { format!("Horizon nicht erreichbar: {}", error) }
    fn account_not_found(&self) -> &'static str { "Konto nicht gefunden! Zuerst aktivieren!" }
    fn json_error(&self, error: &str) -> String { format!("JSON-Fehler: {}", error) }
    fn xdr_serial_error(&self, error: &str) -> String { format!("XDR-Serialisierungsfehler: {:?}", error) }
    fn xdr_error(&self, error: &str) -> String { format!("XDR-Fehler: {:?}", error) }
    fn tx_accepted(&self) -> &'static str { "Transaktion akzeptiert." }
    fn error(&self, status: &str) -> String { format!("Fehler: {}", status) }
}
