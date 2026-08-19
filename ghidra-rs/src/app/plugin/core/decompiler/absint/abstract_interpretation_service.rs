//! Abstract interpretation service for external engines.
//!
//! Port of `ghidra.app.plugin.core.decompiler.absint.AbstractInterpretationService`.
//! The Java `@ServiceInfo` annotation (default provider `AbstractInterpretationServicePlugin`)
//! has no Rust equivalent and is omitted.

/// Provides a general service for generating results from an external abstract interpretation engine.
pub trait AbstractInterpretationService {
    /// Returns the name of the currently active query.
    ///
    /// # Returns
    /// A string containing the name of the active query, or an empty string if no query is active.
    fn get_active_query_name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation for testing.
    struct MockAbstractInterpretationService {
        active_query_name: String,
    }

    impl AbstractInterpretationService for MockAbstractInterpretationService {
        fn get_active_query_name(&self) -> String {
            self.active_query_name.clone()
        }
    }

    #[test]
    fn test_get_active_query_name_with_query() {
        let service = MockAbstractInterpretationService {
            active_query_name: "test_query".to_string(),
        };
        assert_eq!(service.get_active_query_name(), "test_query");
    }

    #[test]
    fn test_get_active_query_name_empty() {
        let service = MockAbstractInterpretationService {
            active_query_name: String::new(),
        };
        assert_eq!(service.get_active_query_name(), "");
    }

    #[test]
    fn test_get_active_query_name_multiple_calls() {
        let service = MockAbstractInterpretationService {
            active_query_name: "query1".to_string(),
        };
        assert_eq!(service.get_active_query_name(), "query1");
        assert_eq!(service.get_active_query_name(), "query1");
    }

    #[test]
    fn test_get_active_query_name_with_special_chars() {
        let service = MockAbstractInterpretationService {
            active_query_name: "query_with_123_special-chars".to_string(),
        };
        assert_eq!(
            service.get_active_query_name(),
            "query_with_123_special-chars"
        );
    }

    #[test]
    fn test_get_active_query_name_unicode() {
        let service = MockAbstractInterpretationService {
            active_query_name: "query_αβγ_test".to_string(),
        };
        assert_eq!(service.get_active_query_name(), "query_αβγ_test");
    }
}
