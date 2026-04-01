use super::ScI18n;

pub struct HungarianSc;

impl ScI18n for HungarianSc {
    fn rpc_unreachable(&self, error: &str) -> String { format!("Soroban RPC nem elérhető: {}", error) }
    fn simulation_failed(&self, detail: &str) -> String { format!("Tranzakció szimuláció sikertelen: {}", detail) }
    fn tx_submission_failed(&self, detail: &str) -> String { format!("Tranzakció beküldése sikertelen: {}", detail) }
    fn tx_pending(&self) -> &'static str { "Tranzakció függőben..." }
    fn tx_success(&self) -> &'static str { "Tranzakció sikeres." }
    fn tx_failed(&self, detail: &str) -> String { format!("Tranzakció sikertelen: {}", detail) }
    fn tx_not_found(&self) -> &'static str { "Tranzakció nem található." }
    fn invalid_response(&self, detail: &str) -> String { format!("Érvénytelen RPC válasz: {}", detail) }
    fn contract_error(&self, detail: &str) -> String { format!("Szerződés hiba: {}", detail) }
}
