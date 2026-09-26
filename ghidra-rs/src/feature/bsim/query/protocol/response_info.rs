//! Port of `ghidra.features.bsim.query.protocol.ResponseInfo`.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DatabaseInformation;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to a request for database metadata.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseInfo`.
pub struct ResponseInfo {
    /// The database metadata, or `None` before it has been populated.
    pub info: Option<DatabaseInformation>,

    base: QueryResponseRecordBase,
}

impl ResponseInfo {
    /// Java: `ResponseInfo()`.
    pub fn new() -> Self {
        Self { info: None, base: QueryResponseRecordBase::new("responseinfo") }
    }

    /// Serializes this response as a `<responseinfo>` element wrapping `info`'s own `<info>`
    /// element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a real Java bug: `info` starts
    /// out `null` (see [`new`](Self::new)) and `saveXml` calls `info.saveXml(fwrite)`
    /// unconditionally, with no null check -- so calling this before `info` is populated throws
    /// a `NullPointerException` in the real Ghidra code, and panics here for the same reason
    /// (see [`tests::save_xml_panics_when_info_is_unset`]).
    pub fn save_xml(&self, mut fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        self.info
            .as_ref()
            .expect(
                "Java: ResponseInfo.saveXml calls info.saveXml(fwrite) unconditionally; info is \
                 null until explicitly populated, so this throws a NullPointerException in the \
                 real Ghidra code too",
            )
            .save_xml(&mut fwrite)?;
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseInfo` from a `<responseinfo>` element wrapping an `<info>`
    /// element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let mut info = DatabaseInformation::new();
        parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        info.restore_xml(parser).map_err(xml_err)?;
        parser.end().map_err(xml_err)?;
        self.info = Some(info);
        Ok(())
    }
}

impl Default for ResponseInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseInfo {
    fn base(&self) -> &QueryResponseRecordBase {
        &self.base
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        Self::save_xml(self, fwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl XmlPullParser for VecParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "VecParser"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            true
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> Self::Element {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> Self::Element {
            let el = self.elements[self.pos].clone();
            self.pos += 1;
            el
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn new_starts_with_no_info() {
        let r = ResponseInfo::new();
        assert!(r.info.is_none());
        assert_eq!(r.base.get_name(), "responseinfo");
    }

    #[test]
    fn save_xml_panics_when_info_is_unset() {
        // Faithful reproduction of Java's NullPointerException: `info.saveXml(fwrite)` is called
        // unconditionally on a field that starts out null.
        let r = ResponseInfo::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_delegates_to_info_when_set() {
        let mut r = ResponseInfo::new();
        r.info = Some(DatabaseInformation::new());
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.starts_with("<responseinfo>\n<info>\n"));
        assert!(xml.ends_with("</info>\n</responseinfo>\n"));
    }

    #[test]
    fn restore_xml_populates_info_from_nested_element() {
        let mut parser = VecParser {
            elements: vec![
                start("responseinfo"),
                start("info"),
                start("name"),
                end_with_text("name", "MyDb"),
                start("owner"),
                end_with_text("owner", "MyOwner"),
                start("description"),
                end_with_text("description", "MyDesc"),
                start("major"),
                end_with_text("major", "1"),
                start("minor"),
                end_with_text("minor", "2"),
                start("settings"),
                end_with_text("settings", "0"),
                end_with_text("info", ""),
                end_with_text("responseinfo", ""),
            ],
            pos: 0,
        };
        let mut r = ResponseInfo::new();
        r.restore_xml(&mut parser).unwrap();
        let info = r.info.expect("info should be populated");
        assert_eq!(info.databasename.as_deref(), Some("MyDb"));
        assert_eq!(info.owner.as_deref(), Some("MyOwner"));
    }

    #[test]
    fn restore_xml_rejects_wrong_outer_element() {
        let mut parser = VecParser { elements: vec![start("wrong")], pos: 0 };
        let mut r = ResponseInfo::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
