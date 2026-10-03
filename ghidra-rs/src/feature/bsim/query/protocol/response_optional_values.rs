//! Port of `ghidra.features.bsim.query.protocol.ResponseOptionalValues`.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to a query for a set of optional-table values, keyed positionally.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseOptionalValues`.
///
/// Java models `resultArray` as `Object[]`: real callers (e.g. `TableScoreCaching`) store
/// `Float` values in it and cast them back out, while `saveXml` only ever calls `.toString()` on
/// each element and `restoreXml` only ever produces `String`s -- a `FIXME` on the Java class
/// itself notes "XML serialization assumes String-based resultArray which is incorrect". This
/// port models the field as `Vec<String>` directly, which mirrors that real (buggy) behavior:
/// any type information a caller's `Object[]` carried is unconditionally lost the moment a
/// `ResponseOptionalValues` round-trips through XML.
pub struct ResponseOptionalValues {
    /// Array of values corresponding to queried keys. `None` mirrors Java's `resultArray == null`.
    pub result_array: Option<Vec<String>>,
    /// `false` if the query failed because the table doesn't exist.
    pub table_exists: bool,

    base: QueryResponseRecordBase,
}

impl ResponseOptionalValues {
    /// Java: `ResponseOptionalValues()`.
    pub fn new() -> Self {
        Self {
            result_array: None,
            table_exists: true,
            base: QueryResponseRecordBase::new("responseoptionalvalues"),
        }
    }

    /// Serializes this response as a `<responseoptionalvalues>` element containing an optional
    /// `<exists>` element followed by one `<val>` element per result value.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        if !self.table_exists {
            write!(fwrite, "<exists>false</exists>\n")?;
        }
        if let Some(values) = &self.result_array {
            for value in values {
                write!(fwrite, "<val>")?;
                let mut escaped = String::new();
                spec_xml_utils::xml_escape(&mut escaped, value);
                write!(fwrite, "{escaped}")?;
                write!(fwrite, "</val>\n")?;
            }
        }
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseOptionalValues` from a `<responseoptionalvalues>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        self.table_exists = true;
        self.result_array = None;
        let mut res_values = Vec::new();
        parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        if parser.peek().get_name() == "exists" {
            parser.start(&["exists"]).map_err(xml_err)?;
            self.table_exists = spec_xml_utils::decode_boolean(parser.end().map_err(xml_err)?.get_text());
        }
        while parser.peek().is_start() {
            parser.start(&[]).map_err(xml_err)?;
            let value = parser.end().map_err(xml_err)?.get_text().to_string();
            res_values.push(value);
        }
        parser.end().map_err(xml_err)?;
        if !res_values.is_empty() {
            self.result_array = Some(res_values);
        }
        Ok(())
    }
}

impl Default for ResponseOptionalValues {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseOptionalValues {
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
    fn new_defaults() {
        let r = ResponseOptionalValues::new();
        assert!(r.result_array.is_none());
        assert!(r.table_exists);
    }

    #[test]
    fn save_xml_omits_exists_element_when_table_exists() {
        let r = ResponseOptionalValues::new();
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert_eq!(xml, "<responseoptionalvalues>\n</responseoptionalvalues>\n");
    }

    #[test]
    fn save_xml_writes_exists_false_when_table_missing() {
        let mut r = ResponseOptionalValues::new();
        r.table_exists = false;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("<exists>false</exists>\n"));
    }

    #[test]
    fn save_xml_writes_each_value_and_escapes_special_chars() {
        let mut r = ResponseOptionalValues::new();
        r.result_array = Some(vec!["1.5".to_string(), "a<b>".to_string()]);
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.contains("<val>1.5</val>\n"));
        assert!(xml.contains("<val>a&lt;b&gt;</val>\n"));
    }

    #[test]
    fn restore_xml_reads_exists_and_values() {
        let mut parser = VecParser {
            elements: vec![
                start("responseoptionalvalues"),
                start("exists"),
                end_with_text("exists", "false"),
                start("val"),
                end_with_text("val", "3.25"),
                start("val"),
                end_with_text("val", "7"),
                end_with_text("responseoptionalvalues", ""),
            ],
            pos: 0,
        };
        let mut r = ResponseOptionalValues::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(!r.table_exists);
        assert_eq!(r.result_array, Some(vec!["3.25".to_string(), "7".to_string()]));
    }

    #[test]
    fn restore_xml_no_exists_element_defaults_table_exists_true() {
        let mut parser = VecParser {
            elements: vec![
                start("responseoptionalvalues"),
                start("val"),
                end_with_text("val", "x"),
                end_with_text("responseoptionalvalues", ""),
            ],
            pos: 0,
        };
        let mut r = ResponseOptionalValues::new();
        r.table_exists = false;
        r.restore_xml(&mut parser).unwrap();
        assert!(r.table_exists);
        assert_eq!(r.result_array, Some(vec!["x".to_string()]));
    }

    #[test]
    fn restore_xml_no_values_leaves_result_array_none() {
        let mut parser =
            VecParser { elements: vec![start("responseoptionalvalues"), end_with_text("responseoptionalvalues", "")], pos: 0 };
        let mut r = ResponseOptionalValues::new();
        r.result_array = Some(vec!["stale".to_string()]);
        r.restore_xml(&mut parser).unwrap();
        assert!(r.result_array.is_none());
    }

    #[test]
    fn restore_xml_round_trips_values() {
        let mut original = ResponseOptionalValues::new();
        original.result_array = Some(vec!["a".to_string(), "b".to_string()]);
        let mut buf = Vec::new();
        original.save_xml(&mut buf).unwrap();

        let mut parser = VecParser {
            elements: vec![
                start("responseoptionalvalues"),
                start("val"),
                end_with_text("val", "a"),
                start("val"),
                end_with_text("val", "b"),
                end_with_text("responseoptionalvalues", ""),
            ],
            pos: 0,
        };
        let mut restored = ResponseOptionalValues::new();
        restored.restore_xml(&mut parser).unwrap();
        assert_eq!(restored.result_array, original.result_array);
    }

    #[test]
    fn restore_xml_rejects_wrong_outer_element() {
        let mut parser = VecParser { elements: vec![start("wrong")], pos: 0 };
        let mut r = ResponseOptionalValues::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
