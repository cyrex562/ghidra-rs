//! Port of `ghidra.features.bsim.query.protocol.PrewarmRequest`.
//!
//! Request that the database preload portions of the main vector table so that initial queries
//! return faster from a server that has just been restarted.

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{LSHVectorFactory, ResponsePrewarm};
use crate::util::seam_stubs::XmlPullParser;
use std::io::Write;

/// Request that a BSim database preload portions of the main vector table.
///
/// Java: `PrewarmRequest extends BSimQuery<ResponsePrewarm>`.
pub struct PrewarmRequest {
    /// For the main index -- 0=don't load 1=load into RAM 2=load into cache.
    pub main_index_config: i32,

    /// For the secondary index -- 0=don't load 1=load into RAM 2=load into cache.
    pub secondary_index_config: i32,

    /// For vectors -- 0=don't load 1=load into RAM 2=load into cache.
    pub vector_table_config: i32,

    /// The response object (same as `response` in the parent BSimQuery).
    pub prewarmresponse: Option<Box<dyn ResponsePrewarm>>,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl PrewarmRequest {
    /// Create a new PrewarmRequest with default configuration.
    ///
    /// Java: `PrewarmRequest()`.
    pub fn new() -> Self {
        Self {
            // Load into cache.
            main_index_config: 2,
            // Load into any extra RAM.
            secondary_index_config: 1,
            // Load into any extra RAM.
            vector_table_config: 1,
            prewarmresponse: None,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new(
                "prewarmrequest",
            ),
        }
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.prewarmresponse.is_none() {
            // In the real implementation, ResponsePrewarm would be a concrete type
            // For now, this is a stub that would create a ResponsePrewarm instance
            // self.prewarmresponse = Some(Box::new(ResponsePrewarm::new()));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    ///
    /// Note: this faithfully reproduces a bug in the original Java, where
    /// `SpecXmlUtils.encodeSignedInteger(...)`'s return value is computed but never appended to
    /// the buffer, so `<main>`/`<secondary>`/`<table>` are always written empty.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        let name = self.base.get_name();
        write!(fwrite, "<{}>\n", name)?;
        write!(fwrite, "<main>")?;
        write!(fwrite, "</main>\n")?;
        write!(fwrite, "<secondary>")?;
        write!(fwrite, "</secondary>\n")?;
        write!(fwrite, "<table>")?;
        write!(fwrite, "</table>\n")?;
        write!(fwrite, "</{}>\n", name)?;
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
        // This would normally parse the XML element using the parser
        // For now, this is a stub implementation
        // parser.start(name);
        // parser.start("main");
        // self.main_index_config = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("secondary");
        // self.secondary_index_config = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.start("table");
        // self.vector_table_config = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.end();
        Ok(())
    }
}

impl Default for PrewarmRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for PrewarmRequest {
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
    fn test_prewarm_request_new_default_config() {
        let req = PrewarmRequest::new();
        assert_eq!(req.main_index_config, 2);
        assert_eq!(req.secondary_index_config, 1);
        assert_eq!(req.vector_table_config, 1);
        assert!(req.prewarmresponse.is_none());
        assert_eq!(req.base.get_name(), "prewarmrequest");
    }

    #[test]
    fn test_prewarm_request_default() {
        let req = PrewarmRequest::default();
        assert_eq!(req.main_index_config, 2);
        assert_eq!(req.secondary_index_config, 1);
        assert_eq!(req.vector_table_config, 1);
    }

    #[test]
    fn test_prewarm_request_query_response_record_trait() {
        let req = PrewarmRequest::new();
        let record: &dyn QueryResponseRecord = &req;
        assert_eq!(record.get_name(), "prewarmrequest");
    }

    #[test]
    fn test_prewarm_request_build_response_template() {
        let mut req = PrewarmRequest::new();
        assert!(req.prewarmresponse.is_none());
        req.build_response_template();
        // Still none since ResponsePrewarm is not implemented yet.
        assert!(req.prewarmresponse.is_none());
    }

    #[test]
    fn test_prewarm_request_save_xml_matches_java_behavior() {
        // Matches Java's actual output: `encodeSignedInteger`'s return value is discarded, so the
        // config values never make it into the buffer.
        let req = PrewarmRequest::new();
        let mut buffer = Vec::new();
        let result = req.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<prewarmrequest>\n<main></main>\n<secondary></secondary>\n<table></table>\n</prewarmrequest>\n"
        );
    }
}
