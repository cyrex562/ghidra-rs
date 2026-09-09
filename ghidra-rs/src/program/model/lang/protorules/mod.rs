pub mod and_filter;
pub mod assign_action;
pub mod consume_as;
pub mod consume_extra;
pub mod consume_remaining;
pub mod convert_to_pointer;
pub mod datatype_filter;
pub mod datatype_match_filter;
pub mod extra_stack;
pub mod goto_stack;
pub mod hidden_return_assign;
pub mod homogeneous_aggregate;
pub mod meta_type_filter;
pub mod multi_member_assign;
pub mod position_match_filter;
pub(crate) mod primitive_extractor;
pub mod qualifier_filter;
pub mod size_restricted_filter;
pub mod varargs_filter;

pub use and_filter::AndFilter;
pub use assign_action::AssignAction;
pub use consume_as::ConsumeAs;
pub use consume_extra::ConsumeExtra;
pub use consume_remaining::ConsumeRemaining;
pub use convert_to_pointer::ConvertToPointer;
pub use datatype_filter::DatatypeFilter;
pub use datatype_match_filter::DatatypeMatchFilter;
pub use extra_stack::ExtraStack;
pub use goto_stack::GotoStack;
pub use hidden_return_assign::HiddenReturnAssign;
pub use homogeneous_aggregate::HomogeneousAggregate;
pub use meta_type_filter::MetaTypeFilter;
pub use multi_member_assign::MultiMemberAssign;
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

/// Shared [`ParamEntry`]/[`ParamListStandardLike`] test doubles used by this package's
/// `AssignAction` implementor tests.
///
/// `ConsumeAs`, `GotoStack`, `MultiMemberAssign`, `ConsumeRemaining`, `ConsumeExtra`, and
/// `ExtraStack` all need a resource list to drive their `assign_address`/`initializeEntry`
/// logic against; centralizing the mock entry and resource-list types here (the same rationale
/// as [`xml_test_support`] above) avoids repeating them in every sibling file.
#[cfg(test)]
pub(crate) mod param_test_support {
    use std::sync::Arc;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::param_entry::ParamEntry;
    use crate::program::model::lang::storage_class::StorageClass;
    use crate::program::seam_stubs::ParamListStandardLike;

    pub(crate) fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    pub(crate) fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1)
    }

    /// A configurable [`ParamEntry`] test double.
    #[derive(Clone)]
    pub(crate) struct TestEntry {
        pub space: Arc<AddressSpace>,
        pub group: i32,
        pub min_size: i32,
        pub size: i32,
        pub align: i32,
        pub addressbase: i64,
        pub numslots: i32,
        pub ty: StorageClass,
        pub reverse_stack: bool,
        pub big_endian: bool,
    }

    impl Default for TestEntry {
        fn default() -> Self {
            TestEntry {
                space: ram_space(),
                group: 0,
                min_size: 1,
                size: 4,
                align: 4,
                addressbase: 0,
                numslots: 1,
                ty: StorageClass::General,
                reverse_stack: false,
                big_endian: false,
            }
        }
    }

    impl ParamEntry for TestEntry {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
        fn get_group(&self) -> i32 {
            self.group
        }
        fn get_min_size(&self) -> i32 {
            self.min_size
        }
        fn get_size(&self) -> i32 {
            self.size
        }
        fn get_align(&self) -> i32 {
            self.align
        }
        fn get_address_base(&self) -> i64 {
            self.addressbase
        }
        fn get_type(&self) -> StorageClass {
            self.ty
        }
        fn num_slots(&self) -> i32 {
            self.numslots
        }
        fn is_reverse_stack(&self) -> bool {
            self.reverse_stack
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    /// A configurable [`ParamListStandardLike`] test double, backed by an explicit entry list.
    #[derive(Default)]
    pub(crate) struct TestResource {
        pub entries: Vec<Arc<dyn ParamEntry>>,
        pub num_group: i32,
        pub spacebase: Option<Arc<AddressSpace>>,
    }

    impl ParamListStandardLike for TestResource {
        fn num_group(&self) -> i32 {
            self.num_group
        }

        fn spacebase(&self) -> Option<Arc<AddressSpace>> {
            self.spacebase.clone()
        }

        fn get_num_param_entry(&self) -> i32 {
            self.entries.len() as i32
        }

        fn get_entry(&self, index: i32) -> Option<Arc<dyn ParamEntry>> {
            self.entries.get(index as usize).cloned()
        }
    }
}
