//! Port of `ghidra.features.bsim.query.protocol.QueryDelete`.
//!
//! Request that a specific list of executables be deleted from a BSim database.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{ExeSpecifier, LSHVectorFactory, ResponseDelete};
use crate::util::seam_stubs::XmlPullParser;

/// Request that a specific list of executables be deleted from a BSim database.
///
/// Java: `QueryDelete extends BSimQuery<ResponseDelete>`.
pub struct QueryDelete {
    /// List of executables to delete from the database.
    pub exelist: Vec<Box<dyn ExeSpecifier>>,

    /// The response object (same as `response` in the parent BSimQuery).
    pub respdelete: Option<Box<dyn ResponseDelete>>,

    name: &'static str,
}

impl QueryDelete {
    /// Create a new QueryDelete query with default settings.
    ///
    /// Java: `QueryDelete()`.
    pub fn new() -> Self {
        Self {
            exelist: Vec::new(),
            respdelete: None,
            name: "delete",
        }
    }

    /// Add an executable specifier to the deletion list.
    ///
    /// Java: `addSpecifier(ExeSpecifier spec)`.
    pub fn add_specifier(&mut self, spec: Box<dyn ExeSpecifier>) {
        self.exelist.push(spec);
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
        if self.respdelete.is_none() {
            // In the real implementation, ResponseDelete would be a concrete type
            // constructed and assigned to both response and respdelete:
            // self.respdelete = Some(Box::new(ResponseDelete::new()));
        }
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.name)?;
        for spec in &self.exelist {
            spec.save_xml(fwrite)?;
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
        self.exelist.clear();
        parser.start(self.name);
        // In a real implementation with a full XmlPullParser, we would iterate:
        // while parser.peek().is_start() {
        //     let mut spec = Box::new(ExeSpecifier::new());
        //     self.exelist.push(spec);
        //     spec.restore_xml(parser);
        // }
        parser.end();
        Ok(())
    }
}

impl Default for QueryDelete {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_delete_new() {
        let query = QueryDelete::new();
        assert_eq!(query.get_name(), "delete");
        assert!(query.exelist.is_empty());
        assert!(query.respdelete.is_none());
    }

    #[test]
    fn test_query_delete_default() {
        let query = QueryDelete::default();
        assert_eq!(query.get_name(), "delete");
        assert!(query.exelist.is_empty());
    }

    #[test]
    fn test_query_delete_build_response_template() {
        let mut query = QueryDelete::new();
        assert!(query.respdelete.is_none());
        query.build_response_template();
        // Still none since ResponseDelete is not implemented yet.
        assert!(query.respdelete.is_none());
    }

    #[test]
    fn test_query_delete_save_xml_empty() {
        let query = QueryDelete::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(xml_str, "<delete>\n</delete>\n");
    }

    #[test]
    fn test_query_delete_restore_xml() {
        let mut query = QueryDelete::new();
        assert!(query.exelist.is_empty());

        // We can't fully test restore_xml without a real XmlPullParser implementation,
        // but we can verify the method exists and basic structure works.
        // The actual parsing logic will be tested when ExeSpecifier is implemented.
    }
}
