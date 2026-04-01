use super::LedgerI18n;

pub struct FrenchLedger;

impl LedgerI18n for FrenchLedger {
    fn faucet_unavailable(&self) -> &'static str { "Faucet indisponible sur ce réseau." }
    fn account_activated(&self) -> &'static str { "Compte activé !" }
    fn faucet_error(&self, status: &str) -> String { format!("Erreur Faucet : {}", status) }
    fn network_error(&self, error: &str) -> String { format!("Erreur réseau : {}", error) }
    fn invalid_secret_key(&self) -> &'static str { "Clé secrète invalide." }
    fn horizon_unreachable(&self, error: &str) -> String { format!("Horizon injoignable : {}", error) }
    fn account_not_found(&self) -> &'static str { "Compte introuvable ! Activez-le d'abord !" }
    fn json_error(&self, error: &str) -> String { format!("Erreur JSON : {}", error) }
    fn xdr_serial_error(&self, error: &str) -> String { format!("Erreur de sérialisation XDR : {:?}", error) }
    fn xdr_error(&self, error: &str) -> String { format!("Erreur XDR : {:?}", error) }
    fn tx_accepted(&self) -> &'static str { "Transaction acceptée." }
    fn error(&self, status: &str) -> String { format!("Erreur : {}", status) }
}
