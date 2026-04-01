mod english;
mod french;
mod german;
mod hungarian;
mod spanish;

use crate::i18n::Language;
use english::EnglishLedger;
use french::FrenchLedger;
use german::GermanLedger;
use hungarian::HungarianLedger;
use spanish::SpanishLedger;

/// Trait for ledger-related internationalized strings
pub trait LedgerI18n {
    fn faucet_unavailable(&self) -> &'static str;
    fn account_activated(&self) -> &'static str;
    fn faucet_error(&self, status: &str) -> String;
    fn network_error(&self, error: &str) -> String;
    fn invalid_secret_key(&self) -> &'static str;
    fn horizon_unreachable(&self, error: &str) -> String;
    fn account_not_found(&self) -> &'static str;
    fn json_error(&self, error: &str) -> String;
    fn xdr_serial_error(&self, error: &str) -> String;
    fn xdr_error(&self, error: &str) -> String;
    fn tx_accepted(&self) -> &'static str;
    fn error(&self, status: &str) -> String;
}

/// Factory function to get the appropriate LedgerI18n implementation
pub fn ledger_i18n(lang: Language) -> Box<dyn LedgerI18n> {
    match lang {
        Language::English => Box::new(EnglishLedger),
        Language::French => Box::new(FrenchLedger),
        Language::German => Box::new(GermanLedger),
        Language::Hungarian => Box::new(HungarianLedger),
        Language::Spanish => Box::new(SpanishLedger),
    }
}
