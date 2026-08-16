//! Port of `ghidra.features.bsim.query.protocol.ResponseExe`.
//!
//! Response to a request for executables from a `BulkSignatures` call.

use std::io::Write;
use std::sync::Arc;

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{ExecutableRecord, LSHVectorFactory};
use crate::util::seam_stubs::XmlPullParser;

/// Response to a request for executables from a `BulkSignatures` call.
///
/// Java: `ResponseExe extends QueryResponseRecord`.
pub struct ResponseExe {
    /// List of executable records in the response.
    pub records: Vec<Arc<ExecutableRecord>>,

    /// Contains metadata about the executables and functions.
    pub manage: DescriptionManager,

    /// Number of records in the response.
    pub record_count: i32,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl ResponseExe {
    /// Create a new ResponseExe with default settings.
    ///
    /// Java: `ResponseExe()`.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            manage: DescriptionManager::new(),
            record_count: 0,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("responsexe"),
        }
    }

    /// Save this response to XML.
    ///
    /// Java: `saveXml(Writer)`.
    /// Note: Java implementation is empty ("no need to implement").
    pub fn save_xml(&self, _fwrite: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    /// Restore this response from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    /// Note: Java implementation is empty ("no need to implement").
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        Ok(())
    }
}

impl Default for ResponseExe {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseExe {
    fn base(&self) -> &crate::feature::bsim::query::protocol::QueryResponseRecordBase {
        &self.base
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        Self::save_xml(self, fwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_exe_new() {
        let response = ResponseExe::new();
        assert_eq!(response.records.len(), 0);
        assert_eq!(response.record_count, 0);
        assert_eq!(response.base.get_name(), "responsexe");
        assert_eq!(response.manage.num_executables(), 0);
    }

    #[test]
    fn test_response_exe_default() {
        let response = ResponseExe::default();
        assert_eq!(response.records.len(), 0);
        assert_eq!(response.record_count, 0);
        assert_eq!(response.base.get_name(), "responsexe");
    }

    #[test]
    fn test_response_exe_with_values() {
        let mut response = ResponseExe::new();
        response.record_count = 5;
        assert_eq!(response.record_count, 5);
        assert_eq!(response.records.len(), 0);
    }

    #[test]
    fn test_response_exe_save_xml_no_op() {
        let response = ResponseExe::new();
        let mut buffer = Vec::new();
        let result = response.save_xml(&mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer.len(), 0); // Should be empty since saveXml is a no-op
    }

    #[test]
    fn test_response_exe_restore_xml_no_op() {
        struct DummyParser;
        impl XmlPullParser for DummyParser {
            fn start(&self, _name: &str) {}
            fn end(&self) {}
        }

        struct DummyVectorFactory;
        impl LSHVectorFactory for DummyVectorFactory {
            fn build_zero_vector(&self) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn build_vector(
                &self,
                _feature: &[i32],
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_xml(
                &self,
                _parser: &dyn XmlPullParser,
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_sql(
                &self,
                _sql: &str,
            ) -> std::io::Result<Box<dyn crate::feature::seam_stubs::LSHVector>> {
                unimplemented!()
            }
            fn set(
                &self,
                _w_factory: &dyn crate::feature::seam_stubs::WeightFactory,
                _i_lookup: &dyn crate::feature::seam_stubs::IDFLookup,
                _settings: i32,
            ) {
            }
            fn is_loaded(&self) -> bool {
                false
            }
            fn get_significance_scale(&self) -> f64 {
                0.0
            }
            fn get_significance_addend(&self) -> f64 {
                0.0
            }
            fn get_settings(&self) -> i32 {
                0
            }
            fn get_self_significance(
                &self,
                _vector: &dyn crate::feature::seam_stubs::LSHVector,
            ) -> f64 {
                0.0
            }
            fn calculate_significance(
                &self,
                _data: &dyn crate::feature::seam_stubs::VectorCompare,
            ) -> f64 {
                0.0
            }
            fn read_weights(&self, _parser: &dyn XmlPullParser) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut response = ResponseExe::new();
        let result = response.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn test_response_exe_query_response_record_trait() {
        let response = ResponseExe::new();
        let record: &dyn QueryResponseRecord = &response;
        assert_eq!(record.get_name(), "responsexe");
    }
}
