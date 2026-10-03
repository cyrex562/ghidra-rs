use super::super::seam_stubs::Option;

/// Callback interface for validating a list of options with values.
pub trait OptionValidator: Send + Sync {
    /// Validates the options; returns None if valid, Some(error_message) otherwise.
    /// # Arguments
    /// * `options` - the options to be validated
    /// # Returns
    /// None if the options have valid values, Some(error_message) otherwise
    fn validate_options(&self, options: &[&dyn Option]) -> std::option::Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysValidValidator;

    impl OptionValidator for AlwaysValidValidator {
        fn validate_options(&self, _options: &[&dyn Option]) -> std::option::Option<String> {
            None
        }
    }

    struct AlwaysInvalidValidator;

    impl OptionValidator for AlwaysInvalidValidator {
        fn validate_options(&self, _options: &[&dyn Option]) -> std::option::Option<String> {
            Some("validation failed".to_string())
        }
    }

    #[test]
    fn test_valid_validator() {
        let validator = AlwaysValidValidator;
        assert_eq!(validator.validate_options(&[]), None);
    }

    #[test]
    fn test_invalid_validator() {
        let validator = AlwaysInvalidValidator;
        let result = validator.validate_options(&[]);
        assert_eq!(result, Some("validation failed".to_string()));
    }

    #[test]
    fn test_validator_can_be_boxed() {
        let validator: Box<dyn OptionValidator> = Box::new(AlwaysValidValidator);
        assert_eq!(validator.validate_options(&[]), None);
    }
}
