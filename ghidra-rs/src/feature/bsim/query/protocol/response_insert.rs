//! Port of `ghidra.features.bsim.query.protocol.ResponseInsert`.
//!
//! A simple response to an insert request into a BSim database, providing separate counts of
//! executables and functions successfully inserted.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecordBase;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A simple response to an `InsertRequest`, counting executables and functions inserted.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseInsert`.
pub struct ResponseInsert {
    /// Number of executables inserted.
    pub numexe: i32,
    /// Number of functions inserted.
    pub numfunc: i32,

    base: QueryResponseRecordBase,
}

impl ResponseInsert {
    /// Java: `ResponseInsert()`.
    pub fn new() -> Self {
        Self { numexe: 0, numfunc: 0, base: QueryResponseRecordBase::new("responseinsert") }
    }

    /// Java: `getName()` (inherited from `QueryResponseRecord`).
    pub fn get_name(&self) -> &str {
        self.base.get_name()
    }

    /// Accumulates the counts from a partial (staged) response into this global response.
    ///
    /// Java: `mergeResults(QueryResponseRecord subresponse)`, which downcasts its parameter to
    /// `ResponseInsert` via an unchecked cast (`(ResponseInsert) subresponse`), risking a
    /// `ClassCastException` at runtime if the wrong type is passed. Taking `&ResponseInsert`
    /// directly here gets the same guarantee statically instead.
    ///
    /// This type deliberately does not implement the [`QueryResponseRecord`](crate::feature::bsim::query::protocol::QueryResponseRecord)
    /// trait: that trait's `merge_results` takes `&self` (a no-op default), and Rust's method
    /// resolution tries `&self` receivers before `&mut self` ones, so an inherent `&mut self`
    /// method of the very same name would be silently shadowed by the trait's no-op default at
    /// every call site where the trait is in scope -- the accumulation below would then never
    /// run. Keeping this as a plain inherent method on the concrete type sidesteps that footgun
    /// entirely.
    pub fn merge_results(&mut self, subresponse: &ResponseInsert) {
        self.numexe += subresponse.numexe;
        self.numfunc += subresponse.numfunc;
    }

    /// Serializes this response as a `<responseinsert>` element with `<numexe>`/`<numfunc>`
    /// children.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        write!(fwrite, " <numexe>{}</numexe>\n", spec_xml_utils::encode_signed_integer(self.numexe as i64))?;
        write!(fwrite, " <numfunc>{}</numfunc>\n", spec_xml_utils::encode_signed_integer(self.numfunc as i64))?;
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseInsert` from a `<responseinsert>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        parser.start(&["numexe"]).map_err(xml_err)?;
        self.numexe = spec_xml_utils::decode_int(Some(parser.end().map_err(xml_err)?.get_text()));
        parser.start(&["numfunc"]).map_err(xml_err)?;
        self.numfunc = spec_xml_utils::decode_int(Some(parser.end().map_err(xml_err)?.get_text()));
        parser.end().map_err(xml_err)?;
        Ok(())
    }
}

impl Default for ResponseInsert {
    fn default() -> Self {
        Self::new()
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
    fn new_defaults_to_zero_counts() {
        let r = ResponseInsert::new();
        assert_eq!(r.numexe, 0);
        assert_eq!(r.numfunc, 0);
    }

    #[test]
    fn merge_results_accumulates_counts() {
        let mut total = ResponseInsert::new();
        total.numexe = 3;
        total.numfunc = 10;

        let mut partial = ResponseInsert::new();
        partial.numexe = 2;
        partial.numfunc = 5;

        total.merge_results(&partial);
        assert_eq!(total.numexe, 5);
        assert_eq!(total.numfunc, 15);

        // Merging again accumulates further (matches Java's `+=` semantics).
        total.merge_results(&partial);
        assert_eq!(total.numexe, 7);
        assert_eq!(total.numfunc, 20);
    }

    #[test]
    fn save_xml_matches_java_format() {
        let mut r = ResponseInsert::new();
        r.numexe = 3;
        r.numfunc = 12;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<responseinsert>\n <numexe>3</numexe>\n <numfunc>12</numfunc>\n</responseinsert>\n"
        );
    }

    #[test]
    fn restore_xml_reads_counts() {
        let mut parser = VecParser {
            elements: vec![
                start("responseinsert"),
                start("numexe"),
                end_with_text("numexe", "4"),
                start("numfunc"),
                end_with_text("numfunc", "9"),
                end_with_text("responseinsert", ""),
            ],
            pos: 0,
        };
        let mut r = ResponseInsert::new();
        r.restore_xml(&mut parser).unwrap();
        assert_eq!(r.numexe, 4);
        assert_eq!(r.numfunc, 9);
    }

    #[test]
    fn restore_xml_round_trips_through_save_xml() {
        let mut original = ResponseInsert::new();
        original.numexe = 6;
        original.numfunc = 21;
        let mut buf = Vec::new();
        original.save_xml(&mut buf).unwrap();

        let mut parser = VecParser {
            elements: vec![
                start("responseinsert"),
                start("numexe"),
                end_with_text("numexe", "6"),
                start("numfunc"),
                end_with_text("numfunc", "21"),
                end_with_text("responseinsert", ""),
            ],
            pos: 0,
        };
        let mut restored = ResponseInsert::new();
        restored.restore_xml(&mut parser).unwrap();
        assert_eq!(restored.numexe, original.numexe);
        assert_eq!(restored.numfunc, original.numfunc);
    }

    #[test]
    fn restore_xml_rejects_wrong_outer_element() {
        let mut parser = VecParser { elements: vec![start("wrong")], pos: 0 };
        let mut r = ResponseInsert::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
