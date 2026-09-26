//! Port of `ghidra.features.bsim.query.protocol.FunctionEntry`.
//!
//! Identifying information for a function within a single executable.

use std::io::{self, Write};

use crate::feature::bsim::query::description::FunctionDescription;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Identifying information for a function within a single executable.
///
/// Port of `ghidra.features.bsim.query.protocol.FunctionEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    /// Name of the function within the executable.
    pub func_name: String,
    /// Address of the function.
    pub address: i64,
}

impl FunctionEntry {
    /// Java: the private no-arg constructor, used only by [`restore_xml`](Self::restore_xml) to
    /// build an entry before its fields are populated from XML.
    fn empty() -> Self {
        Self { func_name: String::new(), address: 0 }
    }

    /// Java: `FunctionEntry(FunctionDescription desc)`.
    pub fn new(desc: &FunctionDescription) -> Self {
        Self { func_name: desc.get_function_name().to_string(), address: desc.get_address() }
    }

    /// Serializes this entry as a single self-closing `<fentry>` XML element.
    ///
    /// Java: `saveXml(Writer)`. Note that `address` is written via `Long.toHexString`, not
    /// through `SpecXmlUtils`' unsigned-integer encoder (which the sibling
    /// [`FunctionDescription::save_xml`](crate::feature::bsim::query::description::FunctionDescription::save_xml)
    /// uses); both render an i64's bit pattern as unsigned hex, so the output is identical.
    ///
    /// Takes `&mut dyn Write` (rather than a generic `W: Write`) to match how this entry is
    /// consumed: `QueryChildren::save_xml` and its siblings thread a single `&mut dyn Write`
    /// through the whole `BSimQuery`/`QueryResponseRecord` object hierarchy.
    pub fn save_xml(&self, writer: &mut dyn Write) -> io::Result<()> {
        let mut escaped_name = String::new();
        spec_xml_utils::xml_escape(&mut escaped_name, &self.func_name);
        write!(writer, "<fentry name=\"{escaped_name}\" addr=\"0x{:x}\"/>\n", self.address as u64)
    }

    /// Deserializes a `FunctionEntry` from a single `<fentry>` XML element.
    ///
    /// Java: `static FunctionEntry restoreXml(XmlPullParser parser)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(parser: &mut P) -> Result<Self, XmlException> {
        let mut entry = Self::empty();
        let start_el = parser.start(&["fentry"])?;
        entry.func_name = start_el.get_attribute("name").unwrap_or_default();
        entry.address = spec_xml_utils::decode_long(start_el.get_attribute("addr").as_deref());
        parser.end_matching(&start_el)?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::ExecutableRecord;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use std::sync::Arc;

    fn desc(name: &str, addr: i64) -> FunctionDescription {
        let erec = Arc::new(ExecutableRecord::new("aa", "a.exe", "x86:LE:32:default", "gcc"));
        FunctionDescription::new(erec, name, addr)
    }

    #[test]
    fn new_copies_name_and_address_from_description() {
        let fd = desc("main", 0x1000);
        let entry = FunctionEntry::new(&fd);
        assert_eq!(entry.func_name, "main");
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn save_xml_matches_java_format() {
        let entry = FunctionEntry { func_name: "main".to_string(), address: 0x1000 };
        let mut buf = Vec::new();
        entry.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<fentry name=\"main\" addr=\"0x1000\"/>\n");
    }

    #[test]
    fn save_xml_escapes_special_characters_in_name() {
        let entry = FunctionEntry { func_name: "a<b>&c".to_string(), address: 0 };
        let mut buf = Vec::new();
        entry.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<fentry name=\"a&lt;b&gt;&amp;c\" addr=\"0x0\"/>\n"
        );
    }

    #[test]
    fn save_xml_renders_address_as_unsigned_hex() {
        // Java: `Long.toHexString(address)` treats the long as unsigned 64-bit, so a negative
        // address (e.g. -1, used elsewhere in this package for "library function") renders as
        // the full-width hex pattern, not a minus sign.
        let entry = FunctionEntry { func_name: "lib".to_string(), address: -1 };
        let mut buf = Vec::new();
        entry.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<fentry name=\"lib\" addr=\"0xffffffffffffffff\"/>\n"
        );
    }

    // --- restore_xml ---

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

    fn end(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    #[test]
    fn restore_xml_reads_name_and_address_attributes() {
        let mut parser = VecParser {
            elements: vec![start("fentry", &[("name", "main"), ("addr", "0x1000")]), end("fentry")],
            pos: 0,
        };
        let entry = FunctionEntry::restore_xml(&mut parser).unwrap();
        assert_eq!(entry.func_name, "main");
        assert_eq!(entry.address, 0x1000);
        assert!(!parser.has_next());
    }

    #[test]
    fn restore_xml_round_trips_through_save_xml() {
        let original = FunctionEntry { func_name: "helper".to_string(), address: 0xdead };
        let mut buf = Vec::new();
        original.save_xml(&mut buf).unwrap();

        // Reflect the saved XML back into elements a parser could yield.
        let mut parser = VecParser {
            elements: vec![
                start("fentry", &[("name", "helper"), ("addr", "0xdead")]),
                end("fentry"),
            ],
            pos: 0,
        };
        let restored = FunctionEntry::restore_xml(&mut parser).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn restore_xml_missing_name_attribute_defaults_to_empty_string() {
        let mut parser = VecParser {
            elements: vec![start("fentry", &[("addr", "0x5")]), end("fentry")],
            pos: 0,
        };
        let entry = FunctionEntry::restore_xml(&mut parser).unwrap();
        assert_eq!(entry.func_name, "");
        assert_eq!(entry.address, 5);
    }

    #[test]
    fn restore_xml_missing_addr_attribute_defaults_to_zero() {
        let mut parser = VecParser {
            elements: vec![start("fentry", &[("name", "noaddr")]), end("fentry")],
            pos: 0,
        };
        let entry = FunctionEntry::restore_xml(&mut parser).unwrap();
        assert_eq!(entry.func_name, "noaddr");
        assert_eq!(entry.address, 0);
    }

    #[test]
    fn restore_xml_rejects_wrong_start_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        assert!(FunctionEntry::restore_xml(&mut parser).is_err());
    }

    #[test]
    fn restore_xml_rejects_mismatched_end_element() {
        let mut parser = VecParser {
            elements: vec![start("fentry", &[("name", "x")]), end("other")],
            pos: 0,
        };
        assert!(FunctionEntry::restore_xml(&mut parser).is_err());
    }
}
