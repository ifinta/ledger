use super::ScI18n;

pub struct FrenchSc;

impl ScI18n for FrenchSc {
    fn rpc_unreachable(&self, error: &str) -> String { format!("RPC Soroban injoignable : {}", error) }
    fn simulation_failed(&self, detail: &str) -> String { format!("Échec de la simulation de transaction : {}", detail) }
    fn tx_submission_failed(&self, detail: &str) -> String { format!("Échec de l'envoi de la transaction : {}", detail) }
    fn tx_pending(&self) -> &'static str { "Transaction en attente..." }
    fn tx_success(&self) -> &'static str { "Transaction réussie." }
    fn tx_failed(&self, detail: &str) -> String { format!("Transaction échouée : {}", detail) }
    fn tx_not_found(&self) -> &'static str { "Transaction introuvable." }
    fn invalid_response(&self, detail: &str) -> String { format!("Réponse RPC invalide : {}", detail) }
    fn contract_error(&self, detail: &str) -> String { format!("Erreur du contrat : {}", detail) }
}
