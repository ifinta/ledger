mod english;
mod french;
mod german;
mod hungarian;
mod spanish;

use zsozso_common::Language;
pub use zsozso_common::LedgerI18n;
use english::EnglishLedger;
use french::FrenchLedger;
use german::GermanLedger;
use hungarian::HungarianLedger;
use spanish::SpanishLedger;

/// Factory function to get the appropriate LedgerI18n implementation
pub fn ledger_i18n(lang: Language) -> Box<dyn LedgerI18n> {
    match lang {
        Language::English => Box::new(EnglishLedger),
        Language::French => Box::new(FrenchLedger),
        Language::German => Box::new(GermanLedger),
        Language::Hungarian => Box::new(HungarianLedger),
        Language::Spanish => Box::new(SpanishLedger),
        _ => Box::new(EnglishLedger),
    }
}
