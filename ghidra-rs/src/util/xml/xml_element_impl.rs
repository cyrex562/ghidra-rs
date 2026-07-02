use std::collections::HashMap;
use std::fmt;

use super::xml_element::XmlElement;
use super::xml_exception::XmlException;

/// Concrete [`XmlElement`] produced by pull-parsing an XML document.
///
/// Port of `ghidra.xml.XmlElementImpl`. Attributes are stored in insertion order
/// (mirroring the Java `LinkedHashMap`) using a `Vec<(String, String)>` rather than
/// an external ordered-map crate.
#[derive(Debug, Clone)]
pub(crate) struct XmlElementImpl {
    name: String,
    level: i32,
    attributes: Vec<(String, String)>,
    text: Option<String>,
    is_start: bool,
    is_end: bool,
    is_content: bool,
    column_number: i32,
    line_number: i32,
}

impl XmlElementImpl {
    /// Creates a new `XmlElementImpl`.
    ///
    /// Returns an [`XmlException`] if `is_start` and `is_end` are both `true`; empty
    /// elements must be split into separate start and end elements via
    /// [`Self::split_empty_element`].
    pub(crate) fn new(
        is_start: bool,
        is_end: bool,
        name: impl Into<String>,
        level: i32,
        attributes: Vec<(String, String)>,
        text: Option<String>,
        column_number: i32,
        line_number: i32,
    ) -> Result<Self, XmlException> {
        if is_start && is_end {
            return Err(XmlException::with_message(
                "empty elements must be split into separate start and end elements (see splitEmptyElement)",
            ));
        }
        Ok(Self {
            name: name.into(),
            level,
            attributes,
            text,
            is_start,
            is_end,
            is_content: !is_start && !is_end,
            column_number,
            line_number,
        })
    }

    /// Splits an empty element (both a start and end tag) into a separate start and
    /// end element pair; returns the element unchanged (cloned) otherwise.
    ///
    /// Port of `ghidra.xml.XmlElementImpl.splitEmptyElement`.
    pub(crate) fn split_empty_element(element: &XmlElementImpl) -> Vec<XmlElementImpl> {
        if element.is_start() && element.is_end() {
            vec![
                XmlElementImpl::new(
                    true,
                    false,
                    element.get_name(),
                    element.get_level(),
                    element.attributes.clone(),
                    None,
                    element.get_column_number(),
                    element.get_line_number(),
                )
                .expect("start/end are not both true"),
                XmlElementImpl::new(
                    false,
                    true,
                    element.get_name(),
                    element.get_level(),
                    Vec::new(),
                    Some(String::new()),
                    element.get_column_number(),
                    element.get_line_number(),
                )
                .expect("start/end are not both true"),
            ]
        } else {
            vec![element.clone()]
        }
    }
}

impl XmlElement for XmlElementImpl {
    fn get_level(&self) -> i32 {
        self.level
    }

    fn is_start(&self) -> bool {
        self.is_start
    }

    fn is_end(&self) -> bool {
        self.is_end
    }

    fn is_content(&self) -> bool {
        self.is_content
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_attributes(&self) -> HashMap<String, String> {
        self.attributes.iter().cloned().collect()
    }

    fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
        Box::new(self.attributes.iter().cloned())
    }

    fn has_attribute(&self, key: &str) -> bool {
        self.attributes.iter().any(|(k, _)| k == key)
    }

    fn get_attribute(&self, key: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }

    fn get_text(&self) -> &str {
        self.text.as_deref().unwrap_or("")
    }

    fn get_column_number(&self) -> i32 {
        self.column_number
    }

    fn get_line_number(&self) -> i32 {
        self.line_number
    }

    fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(entry) = self.attributes.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.attributes.push((key, value));
        }
    }

    fn is_start_with(&self, name: &str) -> bool {
        self.is_start && self.name == name
    }
}

impl fmt::Display for XmlElementImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_content {
            match &self.text {
                None => write!(f, "(null)")?,
                Some(text) => write!(f, "{}", text.replace('\n', "\\n"))?,
            }
        } else if self.is_start {
            write!(f, "<{}({})", self.name, self.level)?;
            for (key, value) in &self.attributes {
                write!(f, " {}=\"{}\"", key, value)?;
            }
            write!(f, ">")?;
        } else if self.is_end {
            match &self.text {
                None => write!(f, "(null)")?,
                Some(text) => write!(f, "{}", text.replace('\n', "\\n"))?,
            }
            write!(f, "</{}({})>", self.name, self.level)?;
        }

        write!(f, " @({}:{})", self.line_number, self.column_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(
        name: &str,
        level: i32,
        attributes: Vec<(String, String)>,
    ) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, level, attributes, None, 1, 2).unwrap()
    }

    #[test]
    fn constructor_rejects_start_and_end_both_true() {
        let result = XmlElementImpl::new(true, true, "elem", 0, Vec::new(), None, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn constructor_allows_start_only() {
        let elem = XmlElementImpl::new(true, false, "elem", 0, Vec::new(), None, 0, 0).unwrap();
        assert!(elem.is_start());
        assert!(!elem.is_end());
        assert!(!elem.is_content());
    }

    #[test]
    fn constructor_allows_end_only() {
        let elem = XmlElementImpl::new(false, true, "elem", 0, Vec::new(), None, 0, 0).unwrap();
        assert!(elem.is_end());
        assert!(!elem.is_start());
        assert!(!elem.is_content());
    }

    #[test]
    fn constructor_treats_neither_as_content() {
        let elem = XmlElementImpl::new(false, false, "", 0, Vec::new(), Some("hi".into()), 0, 0)
            .unwrap();
        assert!(elem.is_content());
    }

    #[test]
    fn get_name_and_level() {
        let elem = start("root", 3, Vec::new());
        assert_eq!(elem.get_name(), "root");
        assert_eq!(elem.get_level(), 3);
    }

    #[test]
    fn get_column_and_line_number() {
        let elem = start("root", 0, Vec::new());
        assert_eq!(elem.get_column_number(), 1);
        assert_eq!(elem.get_line_number(), 2);
    }

    #[test]
    fn has_attribute_and_get_attribute() {
        let elem = start("root", 0, vec![("id".to_string(), "42".to_string())]);
        assert!(elem.has_attribute("id"));
        assert_eq!(elem.get_attribute("id"), Some("42".to_string()));
        assert!(!elem.has_attribute("missing"));
        assert_eq!(elem.get_attribute("missing"), None);
    }

    #[test]
    fn get_attributes_returns_all_entries() {
        let elem = start(
            "root",
            0,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ],
        );
        let attrs = elem.get_attributes();
        assert_eq!(attrs.get("a"), Some(&"1".to_string()));
        assert_eq!(attrs.get("b"), Some(&"2".to_string()));
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn get_attribute_iter_preserves_insertion_order() {
        let elem = start(
            "root",
            0,
            vec![
                ("z".to_string(), "1".to_string()),
                ("a".to_string(), "2".to_string()),
            ],
        );
        let pairs: Vec<_> = elem.get_attribute_iter().collect();
        assert_eq!(
            pairs,
            vec![("z".to_string(), "1".to_string()), ("a".to_string(), "2".to_string())]
        );
    }

    #[test]
    fn set_attribute_adds_new_entry() {
        let mut elem = start("root", 0, Vec::new());
        elem.set_attribute("id", "1");
        assert_eq!(elem.get_attribute("id"), Some("1".to_string()));
    }

    #[test]
    fn set_attribute_overwrites_in_place() {
        let mut elem = start(
            "root",
            0,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ],
        );
        elem.set_attribute("a", "99");
        let pairs: Vec<_> = elem.get_attribute_iter().collect();
        assert_eq!(
            pairs,
            vec![("a".to_string(), "99".to_string()), ("b".to_string(), "2".to_string())]
        );
    }

    #[test]
    fn get_text_returns_empty_string_when_none() {
        let elem = start("root", 0, Vec::new());
        assert_eq!(elem.get_text(), "");
    }

    #[test]
    fn get_text_returns_text_content() {
        let elem = XmlElementImpl::new(false, false, "", 0, Vec::new(), Some("hi".into()), 0, 0)
            .unwrap();
        assert_eq!(elem.get_text(), "hi");
    }

    #[test]
    fn is_start_with_matches_name_and_start_flag() {
        let elem = start("myTag", 0, Vec::new());
        assert!(elem.is_start_with("myTag"));
        assert!(!elem.is_start_with("other"));

        let end_elem = XmlElementImpl::new(false, true, "myTag", 0, Vec::new(), None, 0, 0)
            .unwrap();
        assert!(!end_elem.is_start_with("myTag"));
    }

    #[test]
    fn display_start_element_includes_name_level_and_attributes() {
        let elem = start(
            "root",
            2,
            vec![("id".to_string(), "42".to_string())],
        );
        let s = elem.to_string();
        assert_eq!(s, "<root(2) id=\"42\"> @(2:1)");
    }

    #[test]
    fn display_start_element_without_attributes() {
        let elem = start("root", 0, Vec::new());
        let s = elem.to_string();
        assert_eq!(s, "<root(0)> @(2:1)");
    }

    #[test]
    fn display_end_element_with_text() {
        let elem = XmlElementImpl::new(
            false,
            true,
            "root",
            0,
            Vec::new(),
            Some("value".into()),
            5,
            9,
        )
        .unwrap();
        assert_eq!(elem.to_string(), "value</root(0)> @(9:5)");
    }

    #[test]
    fn display_end_element_with_null_text() {
        let elem = XmlElementImpl::new(false, true, "root", 0, Vec::new(), None, 0, 0).unwrap();
        assert_eq!(elem.to_string(), "(null)</root(0)> @(0:0)");
    }

    #[test]
    fn display_content_escapes_newlines() {
        let elem = XmlElementImpl::new(
            false,
            false,
            "",
            0,
            Vec::new(),
            Some("line1\nline2".into()),
            0,
            0,
        )
        .unwrap();
        assert_eq!(elem.to_string(), "line1\\nline2 @(0:0)");
    }

    #[test]
    fn display_content_with_null_text() {
        let elem = XmlElementImpl::new(false, false, "", 0, Vec::new(), None, 0, 0).unwrap();
        assert_eq!(elem.to_string(), "(null) @(0:0)");
    }

    #[test]
    fn split_empty_element_returns_single_element_when_not_empty() {
        let elem = start("root", 0, vec![("id".to_string(), "1".to_string())]);
        let split = XmlElementImpl::split_empty_element(&elem);
        assert_eq!(split.len(), 1);
        assert!(split[0].is_start());
    }
}
