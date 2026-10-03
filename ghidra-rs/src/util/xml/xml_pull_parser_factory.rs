//! Port of `ghidra.xml.XmlPullParserFactory`: free functions creating an [`XmlPullParser`].
//!
//! Java's factory returns a `ThreadedXmlPullParserImpl` (capacity 1000). Its Rust port reports
//! parse failures by panicking from `has_next` -- the pull-parser contract has no error channel
//! there, and Java callers such as `BasicCompilerSpec` rely on catching the resulting
//! `RuntimeException`. So these functions return a
//! [`NonThreadedXmlPullParserImpl`] configured exactly like the threaded parser (a `<!DOCTYPE>`
//! is accepted, the external subset and external entities are never loaded): the same documents
//! parse to the same element stream, and every failure is returned as an `Err` from `create_*`.
//! The trade-off is that the whole document is parsed before the first element is returned.
//!
//! [`XmlPullParser`]: super::xml_pull_parser::XmlPullParser

use std::io::Read;
use std::path::Path;

use crate::app::util::xml::xml_error_handler::{SaxErrorHandler, XmlError};
use crate::generic::jar::resource_file::ResourceFile;

use super::non_threaded_xml_pull_parser_impl::NonThreadedXmlPullParserImpl;
use super::xml_exception::XmlException;
use super::xml_tracer::XmlTracer;

/// Port of `setCreateTracingParsers(XmlTracer)`, which Java leaves unimplemented: it always
/// fails with the same message (Java throws `UnsupportedOperationException`).
pub(crate) fn set_create_tracing_parsers(_xml_tracer: &dyn XmlTracer) -> Result<(), XmlException> {
    Err(XmlException::with_message(
        "XmlTracer not supported right now...instrument ThreadedXmlPullParserImpl to continue...",
    ))
}

/// Port of `create(InputStream, String, ErrorHandler, boolean)`: a parser over `input`, named
/// `input_name`. `validate` must be `false` (DTD validation is not supported).
pub(crate) fn create_from_reader<R: Read>(
    mut input: R,
    input_name: &str,
    err_handler: Option<&dyn SaxErrorHandler>,
    validate: bool,
) -> Result<NonThreadedXmlPullParserImpl, XmlError> {
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).map_err(|e| XmlError::new(e.to_string()))?;
    NonThreadedXmlPullParserImpl::new_allowing_doctype(&bytes, input_name, err_handler, validate)
}

/// Port of `create(File, ErrorHandler, boolean)`: the parser is named after the file's name.
pub(crate) fn create_from_file(
    file: &Path,
    err_handler: Option<&dyn SaxErrorHandler>,
    validate: bool,
) -> Result<NonThreadedXmlPullParserImpl, XmlError> {
    create_from_resource_file(&ResourceFile::new(file.to_path_buf()), err_handler, validate)
}

/// Port of `create(ResourceFile, ErrorHandler, boolean)`: the parser is named after the file's
/// name.
pub(crate) fn create_from_resource_file(
    file: &ResourceFile,
    err_handler: Option<&dyn SaxErrorHandler>,
    validate: bool,
) -> Result<NonThreadedXmlPullParserImpl, XmlError> {
    let input = file.get_input_stream().map_err(|e| XmlError::new(e.to_string()))?;
    create_from_reader(input, &file.name(), err_handler, validate)
}

/// Port of `create(String, String, ErrorHandler, boolean)`: a parser over the string `input`,
/// named `input_name`.
pub(crate) fn create_from_str(
    input: &str,
    input_name: &str,
    err_handler: Option<&dyn SaxErrorHandler>,
    validate: bool,
) -> Result<NonThreadedXmlPullParserImpl, XmlError> {
    NonThreadedXmlPullParserImpl::new_allowing_doctype(
        input.as_bytes(),
        input_name,
        err_handler,
        validate,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::xml::xml_error_handler::XmlErrorHandler;
    use crate::util::xml::xml_element::XmlElement;
    use crate::util::xml::xml_pull_parser::XmlPullParser;
    use crate::util::xml::xml_tracer::XmlLocator;

    const CSPEC: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<compiler_spec>\n\
  <data_organization>\n\
    <pointer_size value=\"4\"/>\n\
  </data_organization>\n\
  <default_proto>\n\
    <prototype name=\"__cdecl\" extrapop=\"4\" stackshift=\"4\">\n\
      <input><pentry minsize=\"1\" maxsize=\"500\" align=\"4\"><addr offset=\"4\" space=\"stack\"/></pentry></input>\n\
      <output><pentry minsize=\"1\" maxsize=\"4\"><register name=\"EAX\"/></pentry></output>\n\
    </prototype>\n\
  </default_proto>\n\
</compiler_spec>\n";

    #[test]
    fn create_from_str_walks_cspec() {
        let mut p = create_from_str(CSPEC, "x86.cspec", None, false).unwrap();
        assert_eq!(p.get_name(), "x86.cspec");
        let root = p.start(&["compiler_spec"]).unwrap();
        assert_eq!(p.discard_sub_tree_named("data_organization").unwrap(), 4);
        p.start(&["default_proto"]).unwrap();
        let proto = p.start(&["prototype"]).unwrap();
        assert_eq!(proto.get_attribute("name").as_deref(), Some("__cdecl"));
        assert_eq!(proto.get_attribute("extrapop").as_deref(), Some("4"));
        p.start(&["input"]).unwrap();
        let pentry = p.start(&["pentry"]).unwrap();
        assert_eq!(pentry.get_attribute("maxsize").as_deref(), Some("500"));
        let addr = p.start(&["addr"]).unwrap();
        assert_eq!(addr.get_attribute("space").as_deref(), Some("stack"));
        p.end_matching(&addr).unwrap();
        p.end_matching(&pentry).unwrap();
        p.end().unwrap(); // input
        assert!(p.soft_start(&["input"]).is_none());
        assert_eq!(p.discard_sub_tree_named("output").unwrap(), 6);
        p.end_matching(&proto).unwrap();
        p.end().unwrap(); // default_proto
        p.end_matching(&root).unwrap();
        assert!(!p.has_next());
    }

    #[test]
    fn create_accepts_doctype_like_threaded_parser() {
        let xml = "<?xml version=\"1.0\"?>\n<!DOCTYPE PROGRAM SYSTEM \"program_dtd.dtd\">\n\
                   <?program_dtd version=\"1\"?>\n<PROGRAM NAME=\"a\"/>";
        let p = create_from_reader(xml.as_bytes(), "prog.xml", None, false).unwrap();
        assert_eq!(p.get_processing_instruction("program_dtd", "version").as_deref(), Some("1"));
        assert!(p.peek().is_start_with("PROGRAM"));
    }

    #[test]
    fn create_reports_parse_errors_as_values() {
        let err = create_from_str("<a><b></a>", "bad", Some(&XmlErrorHandler::new()), false)
            .unwrap_err();
        assert!(err.message().starts_with("Fatal error on line 1:"), "{}", err.message());
        assert!(create_from_str("<a/>", "t", None, true).is_err());
    }

    #[test]
    fn create_from_file_and_resource_file() {
        let dir = std::env::temp_dir().join(format!("xppf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x86.cspec");
        std::fs::write(&path, CSPEC).unwrap();
        let from_file = create_from_file(&path, None, false).unwrap();
        let from_resource =
            create_from_resource_file(&ResourceFile::new(path.clone()), None, false).unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        assert_eq!(from_file.get_name(), "x86.cspec");
        assert_eq!(from_resource.get_name(), "x86.cspec");
        assert!(from_file.peek().is_start_with("compiler_spec"));
        assert!(create_from_file(&dir.join("missing.cspec"), None, false).is_err());
    }

    #[test]
    fn tracing_parsers_are_unsupported() {
        struct NoTrace;
        impl XmlTracer for NoTrace {
            fn trace(&self, _: Option<&XmlLocator>, _: &str, _: Option<&dyn std::error::Error>) {}
        }
        let err = set_create_tracing_parsers(&NoTrace).unwrap_err();
        assert!(err.message().starts_with("XmlTracer not supported right now"));
    }
}
