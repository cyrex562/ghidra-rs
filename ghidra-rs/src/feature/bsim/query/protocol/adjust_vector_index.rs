//! Port of `ghidra.features.bsim.query.protocol.AdjustVectorIndex`.
//!
//! A query that requests a BSim database either drop or build its main vector index.

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{ResponseAdjustIndex, LSHVectorFactory};
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;
use std::io::Write;

/// Request that a BSim database either drop or build its main vector index.
///
/// Java: `AdjustVectorIndex extends BSimQuery<ResponseAdjustIndex>`.
pub struct AdjustVectorIndex {
    /// True if vector index should be rebuilt, false if it should be dropped.
    pub do_rebuild: bool,

    /// The response object (same as `response` in the parent BSimQuery).
    pub adjust_response: Option<Box<dyn ResponseAdjustIndex>>,

    base: crate::feature::bsim::query::protocol::QueryResponseRecordBase,
}

impl AdjustVectorIndex {
    /// Create a new AdjustVectorIndex query with default settings.
    ///
    /// Java: `AdjustVectorIndex()`.
    pub fn new() -> Self {
        Self {
            do_rebuild: false,
            adjust_response: None,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("adjustindex"),
        }
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.adjust_response.is_none() {
            // In the real implementation, ResponseAdjustIndex would be a concrete type
            // For now, this is a stub that would create a ResponseAdjustIndex instance
            // self.adjust_response = Some(Box::new(ResponseAdjustIndex::new()));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> std::io::Result<()> {
        fwrite.write_all(b"<")?;
        fwrite.write_all(self.base.get_name().as_bytes())?;
        fwrite.write_all(b" rebuild=\"")?;
        fwrite.write_all(spec_xml_utils::encode_boolean(self.do_rebuild).as_bytes())?;
        fwrite.write_all(b"\"/>\n")?;
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
        // let el = parser.start(self.base.get_name());
        // self.do_rebuild = spec_xml_utils::decode_boolean(el.get_attribute("rebuild").as_deref().unwrap_or(""));
        // parser.end();
        Ok(())
    }
}

impl Default for AdjustVectorIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for AdjustVectorIndex {
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
    fn test_adjust_vector_index_new() {
        let query = AdjustVectorIndex::new();
        assert!(!query.do_rebuild);
        assert!(query.adjust_response.is_none());
        assert_eq!(query.base.get_name(), "adjustindex");
    }

    #[test]
    fn test_adjust_vector_index_default() {
        let query = AdjustVectorIndex::default();
        assert!(!query.do_rebuild);
        assert!(query.adjust_response.is_none());
        assert_eq!(query.base.get_name(), "adjustindex");
    }

    #[test]
    fn test_adjust_vector_index_do_rebuild_true() {
        let mut query = AdjustVectorIndex::new();
        query.do_rebuild = true;
        assert!(query.do_rebuild);
    }

    #[test]
    fn test_adjust_vector_index_query_response_record_trait() {
        let query = AdjustVectorIndex::new();
        let record: &dyn QueryResponseRecord = &query;
        assert_eq!(record.get_name(), "adjustindex");
    }

    #[test]
    fn test_adjust_vector_index_save_xml() {
        let query = AdjustVectorIndex {
            do_rebuild: true,
            adjust_response: None,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("adjustindex"),
        };

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("adjustindex"));
        assert!(xml_str.contains("rebuild=\"true\""));
    }

    #[test]
    fn test_adjust_vector_index_save_xml_false() {
        let query = AdjustVectorIndex {
            do_rebuild: false,
            adjust_response: None,
            base: crate::feature::bsim::query::protocol::QueryResponseRecordBase::new("adjustindex"),
        };

        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("rebuild=\"false\""));
    }
}
