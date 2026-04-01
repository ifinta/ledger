use super::LedgerI18n;

pub struct SpanishLedger;

impl LedgerI18n for SpanishLedger {
    fn faucet_unavailable(&self) -> &'static str { "Faucet no disponible en esta red." }
    fn account_activated(&self) -> &'static str { "¡Cuenta activada!" }
    fn faucet_error(&self, status: &str) -> String { format!("Error del faucet: {}", status) }
    fn network_error(&self, error: &str) -> String { format!("Error de red: {}", error) }
    fn invalid_secret_key(&self) -> &'static str { "Clave secreta inválida." }
    fn horizon_unreachable(&self, error: &str) -> String { format!("Horizon inalcanzable: {}", error) }
    fn account_not_found(&self) -> &'static str { "¡Cuenta no encontrada! ¡Actívela primero!" }
    fn json_error(&self, error: &str) -> String { format!("Error JSON: {}", error) }
    fn xdr_serial_error(&self, error: &str) -> String { format!("Error de serialización XDR: {:?}", error) }
    fn xdr_error(&self, error: &str) -> String { format!("Error XDR: {:?}", error) }
    fn tx_accepted(&self) -> &'static str { "Transacción aceptada." }
    fn error(&self, status: &str) -> String { format!("Error: {}", status) }
}
