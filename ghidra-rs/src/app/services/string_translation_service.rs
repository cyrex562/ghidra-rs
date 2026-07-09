//! Interface for providing string translating services.
//!
//! Port of `ghidra.app.services.StringTranslationService`. Implementations are usually
//! registered via a `Plugin`'s service-provider registration, and consumers are expected to look
//! up multiple enabled instances through `PluginTool.getServices(Class)`; neither the
//! `Plugin`/`PluginTool` service registry nor its change-listener notifications have a Rust
//! equivalent yet, so the static `getCurrentStringTranslationServices(PluginTool)` helper is
//! ported as [`sort_string_translation_services`], which just sorts a caller-supplied list.
//!
//! The static `createStringTranslationServiceHelpLocation(Class<? extends Plugin>,
//! StringTranslationService)` helper is omitted entirely: it depends on
//! `PluginDescription.getPluginDescription(Class)` reflection lookups that have no Rust
//! equivalent, and the [`HelpLocation`] placeholder trait has no constructor to build one from.

use crate::app::seam_stubs::ProgramLocation;
use crate::framework::seam_stubs::HelpLocation;
use crate::program::model::listing::Program;

/// Options given to [`StringTranslationService::translate`].
///
/// Port of `StringTranslationService.TranslateOptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TranslateOptions {
    /// If true, the translation service instance should try to translate the values without
    /// user interaction.
    pub auto_translate: bool,
}

impl TranslateOptions {
    /// Port of `StringTranslationService.TranslateOptions.NONE`.
    pub const NONE: TranslateOptions = TranslateOptions { auto_translate: false };
}

/// Interface for providing string translating services.
///
/// Port of `ghidra.app.services.StringTranslationService`.
pub trait StringTranslationService {
    /// Returns the name of this translation service. Used when building menus to allow the user
    /// to pick a translation service.
    fn translation_service_name(&self) -> String;

    /// Returns the help location that describes where to direct the user for help when they hit
    /// f1, or `None`.
    fn help_location(&self) -> Option<Box<dyn HelpLocation>> {
        None
    }

    /// Requests this translation service to translate the specified string data instances.
    ///
    /// The implementation generally should not block when performing this action.
    fn translate(
        &self,
        program: &dyn Program,
        string_locations: &[Box<dyn ProgramLocation>],
        options: TranslateOptions,
    );
}

/// Sorts the given translation services by [`StringTranslationService::translation_service_name`].
///
/// Port of `StringTranslationService.getCurrentStringTranslationServices(PluginTool)`, minus the
/// `PluginTool.getServices(Class)` lookup: callers collect their own currently-enabled service
/// instances (however their Rust service registry works) and pass them here to be sorted.
pub fn sort_string_translation_services(
    mut services: Vec<Box<dyn StringTranslationService>>,
) -> Vec<Box<dyn StringTranslationService>> {
    services.sort_by(|a, b| a.translation_service_name().cmp(&b.translation_service_name()));
    services
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockLocation;
    impl ProgramLocation for MockLocation {}

    struct MockTranslationService {
        name: &'static str,
    }

    impl StringTranslationService for MockTranslationService {
        fn translation_service_name(&self) -> String {
            self.name.to_string()
        }

        fn translate(
            &self,
            _program: &dyn Program,
            _string_locations: &[Box<dyn ProgramLocation>],
            _options: TranslateOptions,
        ) {
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn StringTranslationService> =
            Box::new(MockTranslationService { name: "Mock" });
        assert_eq!(service.translation_service_name(), "Mock");
        assert!(service.help_location().is_none());
        let program = MockProgram;
        let locations: Vec<Box<dyn ProgramLocation>> = vec![Box::new(MockLocation)];
        service.translate(&program, &locations, TranslateOptions::NONE);
    }

    #[test]
    fn translate_options_none_disables_auto_translate() {
        assert!(!TranslateOptions::NONE.auto_translate);
    }

    #[test]
    fn sort_string_translation_services_orders_by_name() {
        let services: Vec<Box<dyn StringTranslationService>> = vec![
            Box::new(MockTranslationService { name: "Zeta" }),
            Box::new(MockTranslationService { name: "Alpha" }),
        ];
        let sorted = sort_string_translation_services(services);
        let names: Vec<String> =
            sorted.iter().map(|s| s.translation_service_name()).collect();
        assert_eq!(names, vec!["Alpha".to_string(), "Zeta".to_string()]);
    }
}
