//! Port of `ghidra.features.bsim.query.protocol.QueryVectorId`.
//!
//! Request vectors from the database by their ids. Allows users to retrieve raw feature
//! vectors without going through functions (FunctionDescription and DescriptionManager).

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{LSHVectorFactory, ResponseVectorId};
use crate::util::seam_stubs::XmlPullParser;

/// Request vectors from the database by their ids.
///
/// Java: `QueryVectorId extends BSimQuery<ResponseVectorId>`.
pub struct QueryVectorId {
    /// The list of ids to query for.
    pub vector_ids: Vec<i64>,

    /// The response object (same as `response` in the parent BSimQuery).
    pub vector_id_response: Option<Box<dyn ResponseVectorId>>,

    name: &'static str,
}

impl QueryVectorId {
    /// Create a new QueryVectorId query.
    ///
    /// Java: `QueryVectorId()`.
    pub fn new() -> Self {
        Self {
            vector_ids: Vec::new(),
            vector_id_response: None,
            name: "queryvectorid",
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
        if self.vector_id_response.is_none() {
            // In the real implementation, ResponseVectorId would be a concrete type
            // constructed and assigned to both response and vector_id_response:
            // self.vector_id_response = Some(Box::new(ResponseVectorId::new()));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.name)?;
        for id in &self.vector_ids {
            write!(fwrite, "  <id>0x{:x}</id>\n", id)?;
        }
        write!(fwrite, "</{}>\n", self.name)?;
        Ok(())
    }

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        self.vector_ids.clear();
        parser.start(self.name);
        // In a full implementation with complete XmlPullParser, we would iterate:
        // while parser.peek().is_start() {
        //     parser.start();
        //     let val = SpecXmlUtils::decodeLong(parser.end().getText());
        //     self.vector_ids.push(val);
        // }
        parser.end();
        Ok(())
    }
}

impl Default for QueryVectorId {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_vector_id_new() {
        let query = QueryVectorId::new();
        assert_eq!(query.get_name(), "queryvectorid");
        assert!(query.vector_ids.is_empty());
        assert!(query.vector_id_response.is_none());
    }

    #[test]
    fn test_query_vector_id_default() {
        let query = QueryVectorId::default();
        assert_eq!(query.get_name(), "queryvectorid");
        assert!(query.vector_ids.is_empty());
    }

    #[test]
    fn test_query_vector_id_with_ids() {
        let mut query = QueryVectorId::new();
        query.vector_ids.push(0x1234567890abcdef);
        query.vector_ids.push(0x7edcba9876543210i64);
        assert_eq!(query.vector_ids.len(), 2);
        assert_eq!(query.vector_ids[0], 0x1234567890abcdef);
        assert_eq!(query.vector_ids[1], 0x7edcba9876543210i64);
    }

    #[test]
    fn test_query_vector_id_build_response_template() {
        let mut query = QueryVectorId::new();
        assert!(query.vector_id_response.is_none());
        query.build_response_template();
        // Still none since ResponseVectorId is not implemented yet.
        assert!(query.vector_id_response.is_none());
    }

    #[test]
    fn test_query_vector_id_save_xml_empty() {
        let query = QueryVectorId::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(xml_str, "<queryvectorid>\n</queryvectorid>\n");
    }

    #[test]
    fn test_query_vector_id_save_xml_with_ids() {
        let mut query = QueryVectorId::new();
        query.vector_ids.push(0x1234567890abcdef);
        query.vector_ids.push(0x7edcba9876543210i64);

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<queryvectorid>\n  <id>0x1234567890abcdef</id>\n  <id>0x7edcba9876543210</id>\n</queryvectorid>\n"
        );
    }

    #[test]
    fn test_query_vector_id_restore_xml_stub() {
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

        let mut query = QueryVectorId::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }
}
