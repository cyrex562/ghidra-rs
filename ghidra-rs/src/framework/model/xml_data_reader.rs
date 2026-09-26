use std::io;

use thiserror::Error;

use crate::framework::seam_stubs::PluginTool;
use crate::util::exception::{DuplicateNameException, InvalidNameException, NotFoundException, NotOwnerException};
use crate::util::task::TaskMonitor;
use crate::util::xml::xml_parse_exception::XmlParseException;

/// Combines the checked exceptions declared on `XmlDataReader.addXMLObject(PluginTool, String,
/// String, boolean, TaskMonitor)`. `org.xml.sax.SAXException` is mapped to
/// [`XmlParseException`], the crate's existing equivalent for XML parsing errors, and
/// `java.io.IOException` to [`io::Error`].
#[derive(Error, Debug)]
pub enum AddXmlObjectError {
    #[error(transparent)]
    NotFound(#[from] NotFoundException),
    #[error(transparent)]
    XmlParse(#[from] XmlParseException),
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    NotOwner(#[from] NotOwnerException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Defines the method for creating an object from an XML file in a jar input stream.
///
/// Port of `ghidra.framework.model.XmlDataReader`.
pub trait XmlDataReader {
    /// Reads the XML file indicated by the base path and relative path name. It creates an
    /// object(s) from this, that is used by the project.
    ///
    /// * `tool` - the tool that provides access to the service registry.
    /// * `base_path` - the prefix part of the path for the XML file.
    /// * `rel_path_name` - a pathname for the file relative to `base_path`.
    /// * `remove_file` - on success this should remove the original file.
    /// * `monitor` - a monitor for providing progress information to the user.
    ///
    /// Returns `true` if an object associated with the file was added to the project, `false`
    /// if the file couldn't be processed.
    fn add_xml_object(
        &mut self,
        tool: &dyn PluginTool,
        base_path: &str,
        rel_path_name: &str,
        remove_file: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, AddXmlObjectError>;

    /// Returns a string summarizing the results of the XML data read, or `None` if there was
    /// nothing to report.
    fn get_summary(&self) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct RecordingXmlDataReader {
        objects_added: Vec<String>,
        fail_next: bool,
    }

    impl XmlDataReader for RecordingXmlDataReader {
        fn add_xml_object(
            &mut self,
            _tool: &dyn PluginTool,
            base_path: &str,
            rel_path_name: &str,
            remove_file: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<bool, AddXmlObjectError> {
            if monitor.is_cancelled() {
                return Err(AddXmlObjectError::Io(io::Error::other("cancelled")));
            }
            if self.fail_next {
                return Err(AddXmlObjectError::XmlParse(XmlParseException::new(format!(
                    "malformed xml at {base_path}/{rel_path_name}"
                ))));
            }
            self.objects_added.push(format!("{base_path}/{rel_path_name}"));
            if remove_file {
                self.objects_added.push(format!("removed:{rel_path_name}"));
            }
            Ok(true)
        }

        fn get_summary(&self) -> Option<String> {
            if self.objects_added.is_empty() {
                None
            } else {
                Some(format!("added {} object(s)", self.objects_added.len()))
            }
        }
    }

    #[test]
    fn adds_object_and_reports_summary() {
        let mut reader = RecordingXmlDataReader { objects_added: Vec::new(), fail_next: false };
        let tool = MockPluginTool;
        let monitor = DummyMonitor;

        assert!(reader.get_summary().is_none());

        let added = reader
            .add_xml_object(&tool, "/base", "data.xml", true, &monitor)
            .expect("add_xml_object should succeed");

        assert!(added);
        assert_eq!(reader.objects_added, vec!["/base/data.xml", "removed:data.xml"]);
        assert_eq!(reader.get_summary(), Some("added 2 object(s)".to_string()));
    }

    #[test]
    fn propagates_xml_parse_error() {
        let mut reader = RecordingXmlDataReader { objects_added: Vec::new(), fail_next: true };
        let tool = MockPluginTool;
        let monitor = DummyMonitor;

        let err = reader
            .add_xml_object(&tool, "/base", "bad.xml", false, &monitor)
            .expect_err("add_xml_object should fail");

        assert!(matches!(err, AddXmlObjectError::XmlParse(_)));
        assert!(reader.objects_added.is_empty());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut reader: Box<dyn XmlDataReader> =
            Box::new(RecordingXmlDataReader { objects_added: Vec::new(), fail_next: false });
        let tool = MockPluginTool;
        let monitor = DummyMonitor;

        let added = reader.add_xml_object(&tool, "/base", "data.xml", false, &monitor).unwrap();
        assert!(added);
    }
}
