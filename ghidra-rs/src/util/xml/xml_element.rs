use std::collections::HashMap;

/// Trait representing an XML element parsed from an XML document.
///
/// Mirrors the `ghidra.xml.XmlElement` interface. Implementations provide access to
/// element metadata (name, level, line/column numbers), attributes, and text content.
pub trait XmlElement {
    /// Returns the nesting level of this element in the XML document.
    fn get_level(&self) -> i32;

    /// Returns `true` if this element is an opening tag.
    fn is_start(&self) -> bool;

    /// Returns `true` if this element is a closing tag.
    fn is_end(&self) -> bool;

    /// Returns `true` if this element is text content (neither start nor end tag).
    fn is_content(&self) -> bool;

    /// Returns the name of this element, or empty string for text content elements.
    fn get_name(&self) -> &str;

    /// Returns a map of all attributes associated with this element.
    ///
    /// For text content elements, returns an empty map.
    fn get_attributes(&self) -> HashMap<String, String>;

    /// Returns an iterator over the attribute name-value pairs.
    fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_>;

    /// Returns `true` if the element has an attribute with the given key.
    fn has_attribute(&self, key: &str) -> bool;

    /// Returns the value of the attribute with the given key, or `None` if not found.
    fn get_attribute(&self, key: &str) -> Option<String>;

    /// Returns the text content of this element.
    ///
    /// For non-content elements, may return empty or the raw parsed text.
    fn get_text(&self) -> &str;

    /// Returns the column number in the source XML where this element starts.
    fn get_column_number(&self) -> i32;

    /// Returns the line number in the source XML where this element starts.
    fn get_line_number(&self) -> i32;

    /// Sets or updates the attribute with the given key and value.
    fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>);

    /// Returns `true` if this is a start tag with the specified name.
    fn is_start_with(&self, name: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockXmlElement {
        level: i32,
        is_start: bool,
        is_end: bool,
        name: String,
        text: String,
        attributes: HashMap<String, String>,
        column: i32,
        line: i32,
    }

    impl MockXmlElement {
        fn new(
            level: i32,
            is_start: bool,
            is_end: bool,
            name: impl Into<String>,
            text: impl Into<String>,
        ) -> Self {
            Self {
                level,
                is_start,
                is_end,
                name: name.into(),
                text: text.into(),
                attributes: HashMap::new(),
                column: 0,
                line: 0,
            }
        }
    }

    impl XmlElement for MockXmlElement {
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
            !self.is_start && !self.is_end
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_attributes(&self) -> HashMap<String, String> {
            self.attributes.clone()
        }

        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attributes.iter().map(|(k, v)| (k.clone(), v.clone())))
        }

        fn has_attribute(&self, key: &str) -> bool {
            self.attributes.contains_key(key)
        }

        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attributes.get(key).cloned()
        }

        fn get_text(&self) -> &str {
            &self.text
        }

        fn get_column_number(&self) -> i32 {
            self.column
        }

        fn get_line_number(&self) -> i32 {
            self.line
        }

        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attributes.insert(key.into(), value.into());
        }

        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    #[test]
    fn start_element_reports_is_start_true() {
        let elem = MockXmlElement::new(0, true, false, "root", "");
        assert!(elem.is_start());
        assert!(!elem.is_end());
        assert!(!elem.is_content());
    }

    #[test]
    fn end_element_reports_is_end_true() {
        let elem = MockXmlElement::new(0, false, true, "root", "");
        assert!(!elem.is_start());
        assert!(elem.is_end());
        assert!(!elem.is_content());
    }

    #[test]
    fn text_content_reports_is_content_true() {
        let elem = MockXmlElement::new(0, false, false, "", "hello world");
        assert!(!elem.is_start());
        assert!(!elem.is_end());
        assert!(elem.is_content());
    }

    #[test]
    fn get_name_returns_element_name() {
        let elem = MockXmlElement::new(0, true, false, "myTag", "");
        assert_eq!(elem.get_name(), "myTag");
    }

    #[test]
    fn get_text_returns_element_text() {
        let elem = MockXmlElement::new(0, false, false, "", "content");
        assert_eq!(elem.get_text(), "content");
    }

    #[test]
    fn get_level_returns_nesting_depth() {
        let elem = MockXmlElement::new(3, true, false, "nested", "");
        assert_eq!(elem.get_level(), 3);
    }

    #[test]
    fn set_and_get_attribute() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("id", "42");
        assert_eq!(elem.get_attribute("id"), Some("42".to_string()));
        assert!(elem.has_attribute("id"));
    }

    #[test]
    fn has_attribute_returns_false_for_missing() {
        let elem = MockXmlElement::new(0, true, false, "elem", "");
        assert!(!elem.has_attribute("missing"));
        assert_eq!(elem.get_attribute("missing"), None);
    }

    #[test]
    fn get_attributes_returns_empty_map_initially() {
        let elem = MockXmlElement::new(0, true, false, "elem", "");
        let attrs = elem.get_attributes();
        assert!(attrs.is_empty());
    }

    #[test]
    fn get_attributes_returns_cloned_map_with_all_entries() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("id", "1");
        elem.set_attribute("name", "test");
        let attrs = elem.get_attributes();
        assert_eq!(attrs.get("id"), Some(&"1".to_string()));
        assert_eq!(attrs.get("name"), Some(&"test".to_string()));
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn get_attribute_iter_yields_all_pairs() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("a", "1");
        elem.set_attribute("b", "2");
        let pairs: Vec<_> = elem.get_attribute_iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn get_attribute_iter_empty_when_no_attributes() {
        let elem = MockXmlElement::new(0, true, false, "elem", "");
        let pairs: Vec<_> = elem.get_attribute_iter().collect();
        assert!(pairs.is_empty());
    }

    #[test]
    fn is_start_with_true_when_start_and_name_matches() {
        let elem = MockXmlElement::new(0, true, false, "myTag", "");
        assert!(elem.is_start_with("myTag"));
    }

    #[test]
    fn is_start_with_false_when_name_mismatch() {
        let elem = MockXmlElement::new(0, true, false, "myTag", "");
        assert!(!elem.is_start_with("other"));
    }

    #[test]
    fn is_start_with_false_when_not_start_element() {
        let elem = MockXmlElement::new(0, false, true, "myTag", "");
        assert!(!elem.is_start_with("myTag"));
    }

    #[test]
    fn get_column_and_line_numbers() {
        let mut elem = MockXmlElement::new(1, true, false, "elem", "");
        elem.column = 42;
        elem.line = 10;
        assert_eq!(elem.get_column_number(), 42);
        assert_eq!(elem.get_line_number(), 10);
    }

    #[test]
    fn get_attributes_is_independent_clone() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("key", "original");
        let mut attrs = elem.get_attributes();
        attrs.insert("key".to_string(), "modified".to_string());
        assert_eq!(elem.get_attribute("key"), Some("original".to_string()));
        assert_eq!(attrs.get("key"), Some(&"modified".to_string()));
    }

    #[test]
    fn multiple_attributes_all_accessible() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("x", "10");
        elem.set_attribute("y", "20");
        elem.set_attribute("z", "30");
        assert_eq!(elem.get_attribute("x"), Some("10".to_string()));
        assert_eq!(elem.get_attribute("y"), Some("20".to_string()));
        assert_eq!(elem.get_attribute("z"), Some("30".to_string()));
    }

    #[test]
    fn set_attribute_overwrites_existing() {
        let mut elem = MockXmlElement::new(0, true, false, "elem", "");
        elem.set_attribute("id", "old");
        elem.set_attribute("id", "new");
        assert_eq!(elem.get_attribute("id"), Some("new".to_string()));
    }
}
