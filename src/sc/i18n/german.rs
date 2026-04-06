use zsozso_common::ScI18n;

pub struct GermanSc;

impl ScI18n for GermanSc {
    fn rpc_unreachable(&self, error: &str) -> String { format!("Soroban-RPC nicht erreichbar: {}", error) }
    fn simulation_failed(&self, detail: &str) -> String { format!("Transaktionssimulation fehlgeschlagen: {}", detail) }
    fn tx_submission_failed(&self, detail: &str) -> String { format!("Transaktionsübermittlung fehlgeschlagen: {}", detail) }
    fn tx_pending(&self) -> &'static str { "Transaktion ausstehend..." }
    fn tx_success(&self) -> &'static str { "Transaktion erfolgreich." }
    fn tx_failed(&self, detail: &str) -> String { format!("Transaktion fehlgeschlagen: {}", detail) }
    fn tx_not_found(&self) -> &'static str { "Transaktion nicht gefunden." }
    fn invalid_response(&self, detail: &str) -> String { format!("Ungültige RPC-Antwort: {}", detail) }
    fn contract_error(&self, detail: &str) -> String { format!("Vertragsfehler: {}", detail) }
}
