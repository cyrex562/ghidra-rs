pub mod and_filter;
pub mod assign_action;
pub mod datatype_filter;
pub mod datatype_match_filter;
pub mod homogeneous_aggregate;
pub mod meta_type_filter;
pub mod position_match_filter;
pub(crate) mod primitive_extractor;
pub mod qualifier_filter;
pub mod size_restricted_filter;
pub mod varargs_filter;

pub use and_filter::AndFilter;
pub use assign_action::AssignAction;
pub use datatype_filter::DatatypeFilter;
pub use datatype_match_filter::DatatypeMatchFilter;
pub use homogeneous_aggregate::HomogeneousAggregate;
pub use meta_type_filter::MetaTypeFilter;
pub use position_match_filter::PositionMatchFilter;
pub use qualifier_filter::QualifierFilter;
pub use size_restricted_filter::SizeRestrictedFilter;
pub use varargs_filter::VarargsFilter;

/// Shared XML pull-parser test doubles used by this package's `restore_xml` tests.
///
/// Every `protorules` filter that round-trips through [`XmlPullParser`] needs the same minimal
/// queue-backed parser and element mock; centralizing them here avoids repeating the ~80-line
/// mock (the pattern used ad hoc elsewhere in the crate, e.g.
/// `bit_field_packing_impl::tests::MockElement`/`QueueParser`) in every sibling file.
#[cfg(test)]
pub(crate) mod xml_test_support {
    use std::collections::HashMap;

    use crate::util::xml::xml_element::XmlElement;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    #[derive(Clone)]
    pub(crate) struct MockElement {
        name: String,
        level: i32,
        is_start: bool,
        is_end: bool,
        attrs: HashMap<String, String>,
    }

    impl MockElement {
        pub(crate) fn start(name: &str, level: i32, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: true,
                is_end: false,
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            }
        }

        pub(crate) fn end(name: &str, level: i32) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: false,
                is_end: true,
                attrs: HashMap::new(),
            }
        }
    }

    impl XmlElement for MockElement {
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
            self.attrs.clone()
        }

        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attrs.clone().into_iter())
        }

        fn has_attribute(&self, key: &str) -> bool {
            self.attrs.contains_key(key)
        }

        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attrs.get(key).cloned()
        }

        fn get_text(&self) -> &str {
            ""
        }

        fn get_column_number(&self) -> i32 {
            0
        }

        fn get_line_number(&self) -> i32 {
            0
        }

        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attrs.insert(key.into(), value.into());
        }

        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    pub(crate) struct QueueParser {
        elements: Vec<MockElement>,
        pos: usize,
        pulling_content: bool,
    }

    impl QueueParser {
        pub(crate) fn new(elements: Vec<MockElement>) -> Self {
            Self { elements, pos: 0, pulling_content: false }
        }
    }

    impl XmlPullParser for QueueParser {
        type Element = MockElement;

        fn get_name(&self) -> &str {
            "queue"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            self.pulling_content
        }

        fn set_pulling_content(&mut self, pulling_content: bool) {
            self.pulling_content = pulling_content;
        }

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> MockElement {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> MockElement {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }

        fn dispose(&mut self) {}
    }
}
