//! Port of `ghidra.features.bsim.query.protocol.QueryExeCount`.
//!
//! Query for counting the number of executable records in the database.

use std::io::Write;

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::ResponseExe;
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// Query for counting the number of executable records in the database.
///
/// Contains all the information required to get a list of all executables in the BSim database
/// that meet a set of filter criteria. The results are stored in the `exeresponse` object.
///
/// Java: `QueryExeCount extends BSimQuery<ResponseExe>`.
pub struct QueryExeCount {
    /// The response object (same as `response` in the parent BSimQuery).
    pub exeresponse: Option<ResponseExe>,

    /// MD5 filter.
    pub filter_md5: Option<String>,

    /// Executable name filter.
    pub filter_exe_name: Option<String>,

    /// Architecture filter.
    pub filter_arch: Option<String>,

    /// Compiler name filter.
    pub filter_compiler_name: Option<String>,

    /// If true, include MD5s that start with `bbbbbbbbaaaaaaa`.
    pub include_fakes: bool,

    name: &'static str,
}

impl QueryExeCount {
    /// Create a query for the count of all executables, not including libraries.
    ///
    /// Java: `QueryExeCount()`.
    pub fn new() -> Self {
        Self {
            exeresponse: None,
            filter_md5: None,
            filter_exe_name: None,
            filter_arch: None,
            filter_compiler_name: None,
            include_fakes: false,
            name: "queryexecount",
        }
    }

    /// Create a query for the count of executables matching the given filters.
    ///
    /// Java: `QueryExeCount(String, String, String, String, boolean)`.
    pub fn with_filters(
        filter_md5: Option<String>,
        filter_exe_name: Option<String>,
        filter_arch: Option<String>,
        filter_compiler_name: Option<String>,
        include_fakes: bool,
    ) -> Self {
        Self {
            exeresponse: None,
            filter_md5,
            filter_exe_name,
            filter_arch,
            filter_compiler_name,
            include_fakes,
            name: "queryexecount",
        }
    }

    /// Get the name of this query.
    ///
    /// Java: `getName()` (inherited from `BSimQuery`).
    pub fn get_name(&self) -> &str {
        self.name
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.exeresponse.is_none() {
            self.exeresponse = Some(ResponseExe::new());
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`. Note: Java implementation is empty ("no need to implement").
    pub fn save_xml(&self, _fwrite: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. Note: Java implementation is empty
    /// ("no need to implement").
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        Ok(())
    }
}

impl Default for QueryExeCount {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_exe_count_new_default_config() {
        let query = QueryExeCount::new();
        assert_eq!(query.get_name(), "queryexecount");
        assert!(query.exeresponse.is_none());
        assert!(query.filter_md5.is_none());
        assert!(query.filter_exe_name.is_none());
        assert!(query.filter_arch.is_none());
        assert!(query.filter_compiler_name.is_none());
        assert!(!query.include_fakes);
    }

    #[test]
    fn test_query_exe_count_default() {
        let query = QueryExeCount::default();
        assert_eq!(query.get_name(), "queryexecount");
        assert!(!query.include_fakes);
    }

    #[test]
    fn test_query_exe_count_with_filters() {
        let query = QueryExeCount::with_filters(
            Some("deadbeef".to_string()),
            Some("libfoo.so".to_string()),
            Some("x86:LE:64".to_string()),
            Some("gcc".to_string()),
            true,
        );
        assert_eq!(query.filter_md5.as_deref(), Some("deadbeef"));
        assert_eq!(query.filter_exe_name.as_deref(), Some("libfoo.so"));
        assert_eq!(query.filter_arch.as_deref(), Some("x86:LE:64"));
        assert_eq!(query.filter_compiler_name.as_deref(), Some("gcc"));
        assert!(query.include_fakes);
        assert!(query.exeresponse.is_none());
    }

    #[test]
    fn test_query_exe_count_build_response_template() {
        let mut query = QueryExeCount::new();
        assert!(query.exeresponse.is_none());
        query.build_response_template();
        assert!(query.exeresponse.is_some());
    }

    #[test]
    fn test_query_exe_count_build_response_template_idempotent() {
        let mut query = QueryExeCount::new();
        query.build_response_template();
        query.exeresponse.as_mut().unwrap().record_count = 42;
        // Calling again must not clobber an existing response.
        query.build_response_template();
        assert_eq!(query.exeresponse.as_ref().unwrap().record_count, 42);
    }

    #[test]
    fn test_query_exe_count_save_xml_no_op() {
        let query = QueryExeCount::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_query_exe_count_restore_xml_no_op() {
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

        let mut query = QueryExeCount::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }
}
