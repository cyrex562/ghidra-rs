//! Port of `ghidra.features.bsim.query.protocol.QueryUpdate`.
//!
//! Request to update the metadata fields of various ExecutableRecords and FunctionDescriptions
//! within a BSim database. This allows quick updates of metadata fields like executable names,
//! function names, and other descriptive metadata fields, without affecting the main index.
//! ExecutableRecord descriptions will be replaced based on the md5 of the executable, and
//! FunctionDescriptions are replaced based on their address within an identified executable.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{LSHVectorFactory, ResponseUpdate};
use crate::util::seam_stubs::XmlPullParser;

/// Request to update the metadata fields of various ExecutableRecords and FunctionDescriptions
/// within a BSim database.
///
/// Java: `QueryUpdate extends BSimQuery<ResponseUpdate>`.
pub struct QueryUpdate {
    /// Contains the list of ExecutableRecords and FunctionDescriptions to update.
    pub manage: DescriptionManager,

    /// The response object (same as `response` in the parent BSimQuery).
    pub updateresponse: Option<Box<dyn ResponseUpdate>>,

    name: &'static str,
}

impl QueryUpdate {
    /// Create a new QueryUpdate query.
    ///
    /// Java: `QueryUpdate()`.
    pub fn new() -> Self {
        Self {
            manage: DescriptionManager::new(),
            updateresponse: None,
            name: "update",
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
        if self.updateresponse.is_none() {
            // In the real implementation, ResponseUpdate would be a concrete type
            // constructed with a back-reference to this query:
            // self.updateresponse = Some(Box::new(ResponseUpdate::new(self)));
        }
    }

    /// Get the description manager holding the functions to update.
    ///
    /// Java: `getDescriptionManager()`.
    pub fn get_description_manager(&self) -> &DescriptionManager {
        &self.manage
    }

    /// Get a partial clone of this query suitable for holding local stages.
    ///
    /// Java: `getLocalStagingCopy()`.
    pub fn get_local_staging_copy(&self) -> QueryUpdate {
        QueryUpdate::new()
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.name)?;
        self.manage.save_xml(fwrite)?;
        write!(fwrite, "</{}>\n", self.name)?;
        Ok(())
    }

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        // This would normally parse the XML element using the parser:
        // parser.start(self.name);
        // self.manage.restore_xml(parser, vector_factory)?;
        // parser.end();
        Ok(())
    }
}

impl Default for QueryUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_update_new_creates_default_query() {
        let query = QueryUpdate::new();
        assert_eq!(query.get_name(), "update");
        assert!(query.updateresponse.is_none());
        assert_eq!(query.manage.num_executables(), 0);
        assert_eq!(query.manage.num_functions(), 0);
    }

    #[test]
    fn test_query_update_default() {
        let query = QueryUpdate::default();
        assert_eq!(query.get_name(), "update");
        assert!(query.updateresponse.is_none());
    }

    #[test]
    fn test_query_update_get_description_manager() {
        let query = QueryUpdate::new();
        let manage = query.get_description_manager();
        assert_eq!(manage.num_executables(), 0);
        assert_eq!(manage.num_functions(), 0);
    }

    #[test]
    fn test_query_update_get_local_staging_copy() {
        let query = QueryUpdate::new();
        let copy = query.get_local_staging_copy();
        assert_eq!(copy.get_name(), "update");
        // The staging copy has its own empty manager
        assert_eq!(copy.manage.num_executables(), 0);
        assert_eq!(copy.manage.num_functions(), 0);
    }

    #[test]
    fn test_query_update_build_response_template() {
        let mut query = QueryUpdate::new();
        assert!(query.updateresponse.is_none());
        query.build_response_template();
        // Still none since ResponseUpdate is not implemented yet.
        assert!(query.updateresponse.is_none());
    }

    #[test]
    fn test_query_update_save_xml_matches_java_behavior() {
        let query = QueryUpdate::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<update>\n<description layout_version=\"5\">\n</description>\n</update>\n"
        );
    }

    #[test]
    fn test_query_update_restore_xml_stub() {
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

        let mut query = QueryUpdate::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }
}
