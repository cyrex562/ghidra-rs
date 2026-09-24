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
pub mod model_rule;
pub mod multi_member_assign;
pub mod multi_slot_assign;
pub mod multi_slot_dual_assign;
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
pub use model_rule::ModelRule;
pub use multi_member_assign::MultiMemberAssign;
pub use multi_slot_assign::MultiSlotAssign;
pub use multi_slot_dual_assign::MultiSlotDualAssign;
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

/// Shared builders for real [`ParamEntry`]/[`ParamListStandard`] resource lists used by this package's
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
    use crate::program::model::lang::param_entry::{ParamEntry, ParamEntryParts};
    use crate::program::model::lang::param_list_standard::ParamListStandard;
    use crate::program::model::lang::storage_class::StorageClass;

    pub(crate) fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    pub(crate) fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1)
    }

    /// Field values for a real [`ParamEntry`], with defaults for the common case.
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

    impl TestEntry {
        /// The real [`ParamEntry`] with these field values.
        pub(crate) fn build(&self) -> Arc<ParamEntry> {
            Arc::new(ParamEntry::from_parts(ParamEntryParts {
                space: self.space.clone(),
                addressbase: self.addressbase,
                size: self.size,
                minsize: self.min_size,
                alignment: self.align,
                numslots: self.numslots,
                storage_type: self.ty,
                group_set: vec![self.group],
                big_endian: self.big_endian,
                reverse_stack: self.reverse_stack,
                force_left_justify: false,
                grouped: false,
                overlapping: false,
                joinrec: None,
            }))
        }
    }

    /// Field values for a real [`ParamListStandard`] built from explicit entries.
    #[derive(Default)]
    pub(crate) struct TestResource {
        pub entries: Vec<TestEntry>,
        pub num_group: i32,
        pub spacebase: Option<Arc<AddressSpace>>,
    }

    impl TestResource {
        /// The real resource list, with no language.
        pub(crate) fn build(&self) -> ParamListStandard {
            self.build_with_language(None)
        }

        /// The real resource list, associated with `language`.
        pub(crate) fn build_with_language(
            &self,
            language: Option<Arc<dyn crate::program::model::lang::language::Language>>,
        ) -> ParamListStandard {
            ParamListStandard::from_parts(
                self.entries.iter().map(TestEntry::build).collect(),
                self.num_group,
                self.spacebase.clone(),
                false,
                false,
                true,
                language,
            )
        }
    }

    /// A minimal [`Language`] test double that recognizes no formal register at any address, so
    /// [`ParameterPieces::assign_address_from_pieces`](crate::program::seam_stubs::ParameterPieces::assign_address_from_pieces)'s
    /// `merge_sequence` step never coalesces multi-piece "join" storage locations -- the
    /// configuration [`MultiMemberAssign`](super::multi_member_assign::MultiMemberAssign),
    /// [`MultiSlotAssign`](super::multi_slot_assign::MultiSlotAssign), and
    /// [`MultiSlotDualAssign`](super::multi_slot_dual_assign::MultiSlotDualAssign) all need to
    /// exercise their own multi-register "join" logic rather than a coalesced single register.
    ///
    /// [`Language`] has no default-bodied methods, so every implementor needs a full ~40-method
    /// impl; centralized here (see this module's own doc) rather than duplicated per sibling
    /// file.
    pub(crate) struct TestLanguage {
        pub big_endian: bool,
    }

    impl crate::program::model::lang::language::Language for TestLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!()
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<
            Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>,
        > {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!()
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            // No formal register recognized at any address -- forces merge_sequence to treat
            // every merge as "informal" and keep pieces separate.
            None
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!()
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!()
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }
}
