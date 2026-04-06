mod english;
mod french;
mod german;
mod hungarian;
mod spanish;

use zsozso_common::Language;
pub use zsozso_common::ScI18n;
use english::EnglishSc;
use french::FrenchSc;
use german::GermanSc;
use hungarian::HungarianSc;
use spanish::SpanishSc;

/// Factory function to get the appropriate ScI18n implementation
pub fn sc_i18n(lang: Language) -> Box<dyn ScI18n> {
    match lang {
        Language::English => Box::new(EnglishSc),
        Language::French => Box::new(FrenchSc),
        Language::German => Box::new(GermanSc),
        Language::Hungarian => Box::new(HungarianSc),
        Language::Spanish => Box::new(SpanishSc),
        _ => Box::new(EnglishSc),
    }
}
