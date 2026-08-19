//! A service that judges the validity of a string.
//!
//! Port of `ghidra.app.services.StringValidatorService`.

use crate::app::seam_stubs::{Class, PluginTool, StringValidatorQuery};
use crate::app::services::StringValidityScore;

/// A service that judges the validity of a string.
///
/// Port of `ghidra.app.services.StringValidatorService`.
pub trait StringValidatorService: Send + Sync {
    /// Returns the name of the service.
    fn get_validator_service_name(&self) -> String;

    /// Judges a string (specified in the query instance).
    fn get_string_validity_score(&self, query: &dyn StringValidatorQuery) -> StringValidityScore;
}

/// A dummy string validator that marks all strings as invalid.
///
/// Port of `StringValidatorService.DummyStringValidator`.
pub struct DummyStringValidator;

impl StringValidatorService for DummyStringValidator {
    fn get_validator_service_name(&self) -> String {
        "Dummy".to_string()
    }

    fn get_string_validity_score(&self, query: &dyn StringValidatorQuery) -> StringValidityScore {
        StringValidityScore::make_dummy_for(query.string_value())
    }
}

/// Creates a dummy string validator instance.
pub fn dummy_string_validator() -> Box<dyn StringValidatorService> {
    Box::new(DummyStringValidator)
}

/// Returns a sorted list of string validator services.
///
/// Port of `StringValidatorService.getCurrentStringValidatorServices(PluginTool)`. Looks up all
/// registered services via `tool.getServices(StringValidatorService::class)`, then sorts them by
/// name.
pub fn get_current_string_validator_services(
    tool: &dyn PluginTool,
) -> Vec<Box<dyn StringValidatorService>> {
    // Get all services of type StringValidatorService from the tool.
    // Since PluginTool.get_services() returns Vec<Box<dyn Any>>, we need a way to tell it
    // which service type we want. The Java version uses StringValidatorService.class as a
    // type token. We'll create a marker type for this purpose.
    let class_token = StringValidatorServiceClassToken;
    let any_services = tool.get_services(&class_token);

    // In a real port with proper runtime type information, we would downcast here.
    // For now, this is a placeholder that assumes the tool implementation handles this.
    // This will be properly implemented when PluginTool is ported.
    let mut results: Vec<Box<dyn StringValidatorService>> = any_services
        .into_iter()
        .filter_map(|_service| {
            // TODO: Once PluginTool is ported with proper type-driven service lookup,
            // this should downcast the service to StringValidatorService
            None
        })
        .collect();

    // Sort by service name
    results.sort_by(|a, b| {
        a.get_validator_service_name()
            .cmp(&b.get_validator_service_name())
    });

    results
}

/// Marker type used as a class token for service lookups.
/// This will be replaced once PluginTool is properly ported.
pub struct StringValidatorServiceClassToken;

impl Class for StringValidatorServiceClassToken {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockQuery {
        string: String,
    }

    impl StringValidatorQuery for MockQuery {
        fn string_value(&self) -> &str {
            &self.string
        }
    }

    struct MockStringValidatorService {
        name: String,
    }

    impl StringValidatorService for MockStringValidatorService {
        fn get_validator_service_name(&self) -> String {
            self.name.clone()
        }

        fn get_string_validity_score(&self, query: &dyn StringValidatorQuery) -> StringValidityScore {
            StringValidityScore::new(query.string_value(), query.string_value(), 42.0, 50.0)
        }
    }

    #[test]
    fn dummy_validator_returns_dummy_name() {
        let validator = DummyStringValidator;
        assert_eq!(validator.get_validator_service_name(), "Dummy");
    }

    #[test]
    fn dummy_validator_creates_dummy_score() {
        let validator = DummyStringValidator;
        let query = MockQuery {
            string: "test".to_string(),
        };
        let score = validator.get_string_validity_score(&query);
        assert_eq!(score.original_string(), "test");
        assert_eq!(score.transformed_string(), "test");
        assert_eq!(score.score(), 0.0);
        assert_eq!(score.threshold(), 100.0);
    }

    #[test]
    fn dummy_validator_factory() {
        let validator = dummy_string_validator();
        assert_eq!(validator.get_validator_service_name(), "Dummy");
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn StringValidatorService> = Box::new(DummyStringValidator);
        let _ = service;
    }

    #[test]
    fn mock_validator_with_query() {
        let validator = MockStringValidatorService {
            name: "MockValidator".to_string(),
        };
        let query = MockQuery {
            string: "hello".to_string(),
        };
        let score = validator.get_string_validity_score(&query);
        assert_eq!(score.original_string(), "hello");
        assert_eq!(score.score(), 42.0);
        assert_eq!(score.threshold(), 50.0);
    }

    #[test]
    fn validator_name_comparison() {
        let validator1: Box<dyn StringValidatorService> = Box::new(MockStringValidatorService {
            name: "Alpha".to_string(),
        });
        let validator2: Box<dyn StringValidatorService> = Box::new(MockStringValidatorService {
            name: "Beta".to_string(),
        });
        assert!(validator1.get_validator_service_name() < validator2.get_validator_service_name());
    }

    #[test]
    fn empty_string_query() {
        let validator = DummyStringValidator;
        let query = MockQuery {
            string: "".to_string(),
        };
        let score = validator.get_string_validity_score(&query);
        assert_eq!(score.original_string(), "");
        assert_eq!(score.transformed_string(), "");
    }

    #[test]
    fn special_characters_in_query() {
        let validator = DummyStringValidator;
        let query = MockQuery {
            string: "@#$%^&*()".to_string(),
        };
        let score = validator.get_string_validity_score(&query);
        assert_eq!(score.original_string(), "@#$%^&*()");
    }
}
