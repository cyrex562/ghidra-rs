//! Port of `ghidra.features.bsim.query.protocol.InsertRequest`.
//!
//! Request that specific executables and functions (as described by `ExecutableRecord`s and
//! `FunctionDescription`s) be inserted into a BSim database.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{LSHVectorFactory, ResponseInsert};
use crate::util::seam_stubs::XmlPullParser;

/// Request that specific executables and functions be inserted into a BSim database.
///
/// Java: `InsertRequest extends BSimQuery<ResponseInsert>`.
pub struct InsertRequest {
    /// The set of executables and functions to be inserted.
    pub manage: DescriptionManager,

    /// Override of repository for this insert.
    pub repo_override: Option<String>,

    /// Override of path.
    pub path_override: Option<String>,

    /// The response object (same as `response` in the parent BSimQuery).
    pub insertresponse: Option<Box<dyn ResponseInsert>>,

    name: &'static str,
}

impl InsertRequest {
    /// Create a new InsertRequest with default settings.
    ///
    /// Java: `InsertRequest()`.
    pub fn new() -> Self {
        Self {
            manage: DescriptionManager::new(),
            repo_override: None,
            path_override: None,
            insertresponse: None,
            name: "insert",
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
        if self.insertresponse.is_none() {
            // In the real implementation, ResponseInsert would be a concrete type:
            // self.insertresponse = Some(Box::new(ResponseInsert::new()));
        }
    }

    /// Get the description manager holding the executables/functions for this request.
    ///
    /// Java: `getDescriptionManager()`.
    pub fn get_description_manager(&self) -> &DescriptionManager {
        &self.manage
    }

    /// Get a partial clone of this query suitable for holding local stages via `StagingManager`.
    ///
    /// Java: `getLocalStagingCopy()`.
    pub fn get_local_staging_copy(&self) -> InsertRequest {
        let mut newi = InsertRequest::new();
        newi.repo_override = self.repo_override.clone();
        newi.path_override = self.path_override.clone();
        newi
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.name)?;
        self.manage.save_xml(fwrite)?;
        if let Some(repo) = &self.repo_override {
            write!(fwrite, "<repository>{}</repository>\n", repo)?;
        }
        if let Some(path) = &self.path_override {
            write!(fwrite, "<path>{}</path>\n", path)?;
        }
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
        // This would normally parse the XML element using the parser
        // For now, this is a stub implementation
        // parser.start(self.name);
        // self.manage.restore_xml(parser, vector_factory)?;
        // let mut subel = parser.peek();
        // while subel.is_start() {
        //     if subel.get_name() == "repository" {
        //         parser.start("repository");
        //         self.repo_override = Some(parser.end().get_text().to_string());
        //     } else if subel.get_name() == "path" {
        //         parser.start("path");
        //         self.path_override = Some(parser.end().get_text().to_string());
        //     }
        //     subel = parser.peek();
        // }
        // parser.end();
        Ok(())
    }
}

impl Default for InsertRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_request_new() {
        let req = InsertRequest::new();
        assert!(req.repo_override.is_none());
        assert!(req.path_override.is_none());
        assert!(req.insertresponse.is_none());
        assert_eq!(req.get_name(), "insert");
        assert_eq!(req.manage.num_executables(), 0);
        assert_eq!(req.manage.num_functions(), 0);
    }

    #[test]
    fn test_insert_request_default() {
        let req = InsertRequest::default();
        assert_eq!(req.get_name(), "insert");
    }

    #[test]
    fn test_insert_request_get_description_manager() {
        let req = InsertRequest::new();
        let manage = req.get_description_manager();
        assert_eq!(manage.num_executables(), 0);
    }

    #[test]
    fn test_insert_request_get_local_staging_copy_carries_overrides() {
        let mut req = InsertRequest::new();
        req.repo_override = Some("myrepo".to_string());
        req.path_override = Some("/some/path".to_string());

        let copy = req.get_local_staging_copy();
        assert_eq!(copy.repo_override, Some("myrepo".to_string()));
        assert_eq!(copy.path_override, Some("/some/path".to_string()));
        // The staging copy does not carry over the description manager's contents.
        assert_eq!(copy.manage.num_executables(), 0);
    }

    #[test]
    fn test_insert_request_get_local_staging_copy_no_overrides() {
        let req = InsertRequest::new();
        let copy = req.get_local_staging_copy();
        assert!(copy.repo_override.is_none());
        assert!(copy.path_override.is_none());
    }

    #[test]
    fn test_insert_request_save_xml_no_overrides() {
        let req = InsertRequest::new();
        let mut buffer = Vec::new();
        let result = req.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.starts_with("<insert>\n"));
        assert!(xml_str.ends_with("</insert>\n"));
        assert!(!xml_str.contains("<repository>"));
        assert!(!xml_str.contains("<path>"));
    }

    #[test]
    fn test_insert_request_save_xml_with_overrides() {
        let mut req = InsertRequest::new();
        req.repo_override = Some("myrepo".to_string());
        req.path_override = Some("/some/path".to_string());

        let mut buffer = Vec::new();
        let result = req.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert!(xml_str.contains("<repository>myrepo</repository>\n"));
        assert!(xml_str.contains("<path>/some/path</path>\n"));
    }

    #[test]
    fn test_insert_request_build_response_template() {
        let mut req = InsertRequest::new();
        assert!(req.insertresponse.is_none());
        req.build_response_template();
        // Still none since ResponseInsert is not implemented yet.
        assert!(req.insertresponse.is_none());
    }
}
