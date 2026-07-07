use std::cmp::Ordering;
use std::io::{self, Write};

use crate::feature::bsim::query::LshException;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A user-defined category associated with an executable.
///
/// Specified by a *type* and then the particular *category* (within the type) that
/// the executable belongs to.
///
/// Port of `ghidra.features.bsim.query.description.CategoryRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryRecord {
    /// The type of category (must not be `None`).
    type_: String,
    /// The type-specific category.
    category: Option<String>,
}

impl CategoryRecord {
    pub fn new(type_: impl Into<String>, category: Option<String>) -> Self {
        Self { type_: type_.into(), category }
    }

    pub fn get_type(&self) -> &str {
        &self.type_
    }

    pub fn get_category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "  <category type=\"{}\">", self.type_)?;
        spec_xml_utils::xml_escape_writer(fwrite, self.category.as_deref().unwrap_or(""))?;
        write!(fwrite, "</category>\n")
    }

    pub(crate) fn restore_xml<P: XmlPullParser>(parser: &mut P) -> Result<Self, LshException> {
        let el = parser.start(&["category"]).map_err(|e| LshException::new(e.to_string()))?;
        let type_ = el.get_attribute("type");
        let category = parser.end().map_err(|e| LshException::new(e.to_string()))?.get_text().to_string();
        match type_ {
            Some(type_) if !category.is_empty() => Ok(Self::new(type_, Some(category))),
            _ => Err(LshException::new("Bad category tag")),
        }
    }

    pub fn enforce_type_characters(val: &str) -> bool {
        if val.is_empty() {
            return false;
        }
        val.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '_' | ':' | '/' | '(' | ')'))
    }
}

impl PartialOrd for CategoryRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CategoryRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        let cmp = self.type_.cmp(&other.type_);
        if cmp != Ordering::Equal {
            return cmp;
        }
        match (&self.category, &other.category) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use crate::util::xml::xml_exception::XmlException;

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl VecParser {
        fn new(elements: Vec<XmlElementImpl>) -> Self {
            Self { elements, pos: 0 }
        }
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

        fn start(&mut self, names: &[&str]) -> Result<Self::Element, XmlException> {
            let elem = self.next();
            if !elem.is_start() {
                return Err(XmlException::with_message("expected start element"));
            }
            if !names.is_empty() && !names.iter().any(|n| *n == elem.get_name()) {
                return Err(XmlException::with_message("unexpected start element name"));
            }
            Ok(elem)
        }

        fn end(&mut self) -> Result<Self::Element, XmlException> {
            let elem = self.next();
            if !elem.is_end() {
                return Err(XmlException::with_message("expected end element"));
            }
            Ok(elem)
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    fn start_with_attr(name: &str, attr: &str, value: &str) -> XmlElementImpl {
        XmlElementImpl::new(
            true,
            false,
            name,
            0,
            vec![(attr.to_string(), value.to_string())],
            None,
            0,
            0,
        )
        .unwrap()
    }

    fn end(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(String::new()), 0, 0).unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0)
            .unwrap()
    }

    // --- accessors ---

    #[test]
    fn test_get_type_and_category() {
        let rec = CategoryRecord::new("Compiler", Some("gcc".to_string()));
        assert_eq!(rec.get_type(), "Compiler");
        assert_eq!(rec.get_category(), Some("gcc"));
    }

    #[test]
    fn test_get_category_none() {
        let rec = CategoryRecord::new("Compiler", None);
        assert_eq!(rec.get_category(), None);
    }

    // --- equality ---

    #[test]
    fn test_equals_same_fields() {
        let a = CategoryRecord::new("t", Some("c".to_string()));
        let b = CategoryRecord::new("t", Some("c".to_string()));
        assert_eq!(a, b);
    }

    #[test]
    fn test_equals_different_category() {
        let a = CategoryRecord::new("t", Some("c1".to_string()));
        let b = CategoryRecord::new("t", Some("c2".to_string()));
        assert_ne!(a, b);
    }

    #[test]
    fn test_equals_different_type() {
        let a = CategoryRecord::new("t1", Some("c".to_string()));
        let b = CategoryRecord::new("t2", Some("c".to_string()));
        assert_ne!(a, b);
    }

    // --- ordering ---

    #[test]
    fn test_compare_type_dominates() {
        let a = CategoryRecord::new("a", Some("z".to_string()));
        let b = CategoryRecord::new("b", Some("a".to_string()));
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_compare_category_when_type_equal() {
        let a = CategoryRecord::new("t", Some("a".to_string()));
        let b = CategoryRecord::new("t", Some("b".to_string()));
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn test_compare_equal() {
        let a = CategoryRecord::new("t", Some("c".to_string()));
        let b = CategoryRecord::new("t", Some("c".to_string()));
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    #[test]
    fn test_compare_none_category_precedes_some() {
        let a = CategoryRecord::new("t", None);
        let b = CategoryRecord::new("t", Some("c".to_string()));
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn test_compare_both_none_category() {
        let a = CategoryRecord::new("t", None);
        let b = CategoryRecord::new("t", None);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    // --- save_xml ---

    #[test]
    fn test_save_xml_writes_expected_format() {
        let rec = CategoryRecord::new("Compiler", Some("gcc".to_string()));
        let mut buf = Vec::new();
        rec.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "  <category type=\"Compiler\">gcc</category>\n"
        );
    }

    #[test]
    fn test_save_xml_escapes_category_text() {
        let rec = CategoryRecord::new("t", Some("a&b".to_string()));
        let mut buf = Vec::new();
        rec.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "  <category type=\"t\">a&amp;b</category>\n");
    }

    // --- restore_xml ---

    #[test]
    fn test_restore_xml_round_trips() {
        let mut parser = VecParser::new(vec![
            start_with_attr("category", "type", "Compiler"),
            end_with_text("category", "gcc"),
        ]);
        let rec = CategoryRecord::restore_xml(&mut parser).unwrap();
        assert_eq!(rec.get_type(), "Compiler");
        assert_eq!(rec.get_category(), Some("gcc"));
    }

    #[test]
    fn test_restore_xml_missing_type_attribute_errors() {
        let mut parser = VecParser::new(vec![start("category"), end_with_text("category", "gcc")]);
        let err = CategoryRecord::restore_xml(&mut parser).unwrap_err();
        assert_eq!(err.message(), "Bad category tag");
    }

    #[test]
    fn test_restore_xml_empty_category_text_errors() {
        let mut parser =
            VecParser::new(vec![start_with_attr("category", "type", "Compiler"), end("category")]);
        let err = CategoryRecord::restore_xml(&mut parser).unwrap_err();
        assert_eq!(err.message(), "Bad category tag");
    }

    #[test]
    fn test_restore_xml_wrong_start_element_errors() {
        let mut parser = VecParser::new(vec![start("wrong"), end("wrong")]);
        assert!(CategoryRecord::restore_xml(&mut parser).is_err());
    }

    // --- enforce_type_characters ---

    #[test]
    fn test_enforce_type_characters_valid() {
        assert!(CategoryRecord::enforce_type_characters("Compiler.Vendor_1 (x86):/a b"));
    }

    #[test]
    fn test_enforce_type_characters_empty_is_invalid() {
        assert!(!CategoryRecord::enforce_type_characters(""));
    }

    #[test]
    fn test_enforce_type_characters_rejects_disallowed_char() {
        assert!(!CategoryRecord::enforce_type_characters("bad,type"));
    }

    #[test]
    fn test_enforce_type_characters_alphanumeric_only() {
        assert!(CategoryRecord::enforce_type_characters("abc123"));
    }
}
