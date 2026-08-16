//! Port of `ghidra.features.bsim.query.protocol.QueryResponseRecord`.
//!
//! A database query response record that can be serialized. Java's `QueryResponseRecord` is an
//! abstract class with a `name` field and several methods, some abstract and some concrete with
//! default implementations. This port splits that into [`QueryResponseRecordBase`] (the shared state
//! and concrete methods) and [`QueryResponseRecord`] (the abstract interface and trait defaults).
//!
//! # Note on Generic Methods
//!
//! The `restore_xml` method is defined as a generic method on concrete implementations, not on the
//! trait itself, to keep the trait object-safe for use with `Box<dyn QueryResponseRecord>`. Concrete
//! implementations can define their own `restore_xml` methods with the appropriate generic bounds.

use crate::feature::bsim::query::LshException;
use std::io::Write;

/// The shared state and concrete behavior of a [`QueryResponseRecord`].
///
/// Port of the `name` field and the concrete methods of
/// `ghidra.features.bsim.query.protocol.QueryResponseRecord`.
#[derive(Debug, Clone)]
pub struct QueryResponseRecordBase {
    name: String,
}

impl QueryResponseRecordBase {
    /// Create a new response record with the given name.
    ///
    /// Java: `QueryResponseRecord(String name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Get the name of this response record.
    ///
    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the description manager for this response (if any).
    ///
    /// Java: `getDescriptionManager()`. Base implementation returns `null`.
    pub fn get_description_manager(&self) -> Option<Box<dyn crate::feature::seam_stubs::DescriptionManager>> {
        None
    }

    /// Get a partial clone of this query suitable for holding local stages via `StagingManager`.
    ///
    /// Java: `getLocalStagingCopy()`. Base implementation returns `null`.
    pub fn get_local_staging_copy(&self) -> Option<Box<dyn QueryResponseRecord>> {
        None
    }

    /// Combine partial results from a subresponse into this global response.
    ///
    /// Java: `mergeResults(QueryResponseRecord)`. Base implementation does nothing.
    pub fn merge_results(&self, _subresponse: &dyn QueryResponseRecord) -> Result<(), LshException> {
        Ok(())
    }

    /// Perform any preferred sorting on the result of a query.
    ///
    /// Java: `sort()`. Base implementation does nothing.
    pub fn sort(&self) {}
}

/// The abstract operations of a query response record, plus concrete convenience methods.
///
/// Port of `ghidra.features.bsim.query.protocol.QueryResponseRecord`. Concrete implementations
/// should embed a [`QueryResponseRecordBase`] and implement the abstract methods (and `base()`,
/// which lets trait default methods reach the embedded state).
///
/// Note: `restore_xml` is not included in this trait (because it uses generic parameters that would
/// make the trait non-object-safe). Concrete implementations define it separately.
pub trait QueryResponseRecord: Send + Sync {
    /// The shared state (the name) every response record carries.
    fn base(&self) -> &QueryResponseRecordBase;

    /// Save this response to XML.
    ///
    /// Java: `saveXml(Writer)`.
    fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()>;

    /// Get the name of this response record.
    ///
    /// Java: `getName()`. Default implementation delegates to the base.
    fn get_name(&self) -> &str {
        self.base().get_name()
    }

    /// Get the description manager for this response (if any).
    ///
    /// Java: `getDescriptionManager()`. Default implementation delegates to the base.
    fn get_description_manager(&self) -> Option<Box<dyn crate::feature::seam_stubs::DescriptionManager>> {
        self.base().get_description_manager()
    }

    /// Get a partial clone of this query suitable for holding local stages via `StagingManager`.
    ///
    /// Java: `getLocalStagingCopy()`. Default implementation delegates to the base.
    fn get_local_staging_copy(&self) -> Option<Box<dyn QueryResponseRecord>> {
        self.base().get_local_staging_copy()
    }

    /// Combine partial results from a subresponse into this global response.
    ///
    /// Java: `mergeResults(QueryResponseRecord)`. Default implementation delegates to the base.
    fn merge_results(&self, subresponse: &dyn QueryResponseRecord) -> Result<(), LshException> {
        self.base().merge_results(subresponse)
    }

    /// Perform any preferred sorting on the result of a query.
    ///
    /// Java: `sort()`. Default implementation delegates to the base.
    fn sort(&self) {
        self.base().sort()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_response_record_base_new() {
        let base = QueryResponseRecordBase::new("test_response");
        assert_eq!(base.get_name(), "test_response");
    }

    #[test]
    fn test_query_response_record_base_get_name() {
        let base = QueryResponseRecordBase::new("my_record");
        assert_eq!(base.get_name(), "my_record");
    }

    #[test]
    fn test_query_response_record_base_description_manager_default() {
        let base = QueryResponseRecordBase::new("test");
        assert!(base.get_description_manager().is_none());
    }

    #[test]
    fn test_query_response_record_base_staging_copy_default() {
        let base = QueryResponseRecordBase::new("test");
        assert!(base.get_local_staging_copy().is_none());
    }

    #[test]
    fn test_query_response_record_base_merge_results() {
        let base = QueryResponseRecordBase::new("test");
        let result = base.merge_results(&MockQueryResponseRecord);
        assert!(result.is_ok());
    }

    #[test]
    fn test_query_response_record_base_sort() {
        let base = QueryResponseRecordBase::new("test");
        base.sort(); // should not panic
    }

    struct MockQueryResponseRecord;

    impl QueryResponseRecord for MockQueryResponseRecord {
        fn base(&self) -> &QueryResponseRecordBase {
            unimplemented!()
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_trait_default_get_name() {
        struct TestRecord {
            base: QueryResponseRecordBase,
        }

        impl QueryResponseRecord for TestRecord {
            fn base(&self) -> &QueryResponseRecordBase {
                &self.base
            }

            fn save_xml(&self, _fwrite: &mut dyn Write) -> std::io::Result<()> {
                Ok(())
            }
        }

        let record = TestRecord {
            base: QueryResponseRecordBase::new("trait_test"),
        };
        assert_eq!(record.get_name(), "trait_test");
    }
}
