use super::ScI18n;

pub struct SpanishSc;

impl ScI18n for SpanishSc {
    fn rpc_unreachable(&self, error: &str) -> String { format!("Soroban RPC inalcanzable: {}", error) }
    fn simulation_failed(&self, detail: &str) -> String { format!("Simulación de transacción fallida: {}", detail) }
    fn tx_submission_failed(&self, detail: &str) -> String { format!("Envío de transacción fallido: {}", detail) }
    fn tx_pending(&self) -> &'static str { "Transacción pendiente..." }
    fn tx_success(&self) -> &'static str { "Transacción exitosa." }
    fn tx_failed(&self, detail: &str) -> String { format!("Transacción fallida: {}", detail) }
    fn tx_not_found(&self) -> &'static str { "Transacción no encontrada." }
    fn invalid_response(&self, detail: &str) -> String { format!("Respuesta RPC inválida: {}", detail) }
    fn contract_error(&self, detail: &str) -> String { format!("Error de contrato: {}", detail) }
}
