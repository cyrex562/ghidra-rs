//! Port of `ghidra.features.bsim.query.protocol.ResponseVectorMatch`.
//!
//! Response to a request for functions with specific vector ids. Full `ExecutableRecord`s and
//! `FunctionDescription`s are instantiated in this object's `DescriptionManager`.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to a request for functions with specific vector ids.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseVectorMatch`.
pub struct ResponseVectorMatch {
    /// Set of functions (and executables) matching the vector id request.
    pub manage: DescriptionManager,

    base: QueryResponseRecordBase,
}

impl ResponseVectorMatch {
    /// Java: `ResponseVectorMatch()`.
    pub fn new() -> Self {
        Self { manage: DescriptionManager::new(), base: QueryResponseRecordBase::new("responsevectormatch") }
    }

    /// Java: `getDescriptionManager()`, overridden to return `manage` instead of the
    /// `QueryResponseRecord` base's default `null`.
    pub fn get_description_manager(&self) -> &DescriptionManager {
        &self.manage
    }

    /// Serializes this response as a `<responsevectormatch>` element wrapping `manage`'s own
    /// `<description>` element.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, mut fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        self.manage.save_xml(&mut fwrite)?;
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseVectorMatch` from a `<responsevectormatch>` element wrapping a
    /// `<description>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        vector_factory: &LSHVectorFactory,
    ) -> Result<(), LshException> {
        use crate::util::xml::xml_exception::XmlException;
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        self.manage.restore_xml(parser, vector_factory)?;
        parser.end().map_err(xml_err)?;
        Ok(())
    }
}

impl Default for ResponseVectorMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseVectorMatch {
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

    fn start(name: &str, attrs: &[(&str, &str)]) -> XmlElementImpl {
        XmlElementImpl::new(
            true,
            false,
            name,
            0,
            attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            None,
            0,
            0,
        )
        .unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn new_starts_with_empty_manager() {
        let r = ResponseVectorMatch::new();
        assert_eq!(r.manage.num_executables(), 0);
        assert_eq!(r.base.get_name(), "responsevectormatch");
    }

    #[test]
    fn get_description_manager_returns_manage() {
        let r = ResponseVectorMatch::new();
        assert_eq!(r.get_description_manager().num_executables(), 0);
    }

    #[test]
    fn save_xml_wraps_description_manager_output() {
        let r = ResponseVectorMatch::new();
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.starts_with("<responsevectormatch>\n<description"));
        assert!(xml.ends_with("</description>\n</responsevectormatch>\n"));
    }

    #[test]
    fn restore_xml_round_trips_empty_manager() {
        let mut r = ResponseVectorMatch::new();
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();

        let mut parser = VecParser {
            elements: vec![
                start("responsevectormatch", &[]),
                start("description", &[("layout_version", "5")]),
                end_with_text("description", ""),
                end_with_text("responsevectormatch", ""),
            ],
            pos: 0,
        };
        assert!(xml.contains("layout_version=\"5\""));

        let mut restored = ResponseVectorMatch::new();
        restored.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap();
        assert_eq!(restored.manage.num_executables(), 0);
    }

    #[test]
    fn restore_xml_rejects_wrong_outer_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        let mut r = ResponseVectorMatch::new();
        assert!(r.restore_xml(&mut parser, &LSHVectorFactory::default()).is_err());
    }
}
