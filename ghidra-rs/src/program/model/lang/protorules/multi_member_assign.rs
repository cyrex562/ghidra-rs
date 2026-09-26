use std::any::Any;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::protorules::assign_action::{AssignAction, FAIL, SUCCESS};
use crate::program::model::lang::protorules::primitive_extractor::PrimitiveExtractor;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{Encoder, Varnode, ATTRIB_STORAGE, ELEM_JOIN_PER_PRIMITIVE};
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
use crate::util::exception::InvalidInputException;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Consume a register per primitive member of an aggregate data-type.
///
/// The data-type is split up into its underlying primitive elements, and each one is assigned a
/// register from the specific resource list. There must be no padding between elements. No
/// packing of elements into a single register occurs.
///
/// Port of `ghidra.program.model.lang.protorules.MultiMemberAssign`.
pub struct MultiMemberAssign {
    /// Resource list from which to consume (`MultiMemberAssign.resourceType`).
    resource_type: StorageClass,
    /// True if resources should be consumed from the stack (`MultiMemberAssign.consumeFromStack`).
    consume_from_stack: bool,
    /// True if resources are consumed starting with most significant bytes
    /// (`MultiMemberAssign.consumeMostSig`).
    consume_most_sig: bool,
}

impl MultiMemberAssign {
    /// Port of the public constructor. Java also passes the owning `ParamListStandard`; here the
    /// resource list is a call-time argument of [`assign_address`](AssignAction::assign_address).
    pub fn new(store: StorageClass, stack: bool, most_sig: bool) -> Self {
        MultiMemberAssign {
            resource_type: store,
            consume_from_stack: stack,
            consume_most_sig: most_sig,
        }
    }
}

impl AssignAction for MultiMemberAssign {
    fn clone_box(
        &self,
        _new_resource: &ParamListStandard,
    ) -> Result<Box<dyn AssignAction>, InvalidInputException> {
        Ok(Box::new(MultiMemberAssign::new(self.resource_type, self.consume_from_stack, self.consume_most_sig)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equivalent(&self, op: &dyn AssignAction) -> bool {
        let Some(other) = op.as_any().downcast_ref::<MultiMemberAssign>() else {
            return false;
        };
        self.resource_type == other.resource_type
            && self.consume_from_stack == other.consume_from_stack
            && self.consume_most_sig == other.consume_most_sig
    }

    fn assign_address(
        &self,
        resource: &ParamListStandard,
        dt: &Arc<dyn DataType>,
        _proto: &PrototypePieces,
        _pos: i32,
        _dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        let mut tmp_status = status.to_vec();
        let mut pieces: Vec<Varnode> = Vec::new();
        let primitives = PrimitiveExtractor::new(dt.as_ref(), false, 0, 16);
        if !primitives.is_valid()
            || primitives.size() == 0
            || primitives.contains_unknown()
            || !primitives.is_aligned()
            || primitives.contains_holes()
        {
            return FAIL;
        }
        for cur_type in primitives.into_arc_types() {
            let mut param = ParameterPieces::default();
            if resource.assign_address_fallback(
                self.resource_type,
                &cur_type,
                !self.consume_from_stack,
                &mut tmp_status,
                &mut param,
            ) == FAIL
            {
                return FAIL;
            }
            let Some(addr) = param.address else {
                // assign_address_fallback only returns other than FAIL with param.address set.
                return FAIL;
            };
            pieces.push(Varnode::new(addr, cur_type.get_length()));
        }

        // Commit resource usage for all the pieces
        status.copy_from_slice(&tmp_status);
        res.data_type = Some(dt.clone());
        let Some(language) = resource.get_language() else {
            // A restored ParamListStandard always has its Language; only one assembled with
            // `from_parts` and no language lacks it.
            return FAIL;
        };
        res.assign_address_from_pieces(pieces, self.consume_most_sig, false, language.as_ref());
        SUCCESS
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_JOIN_PER_PRIMITIVE)?;
        if self.resource_type != StorageClass::General {
            encoder.write_string(ATTRIB_STORAGE, &self.resource_type.to_string())?;
        }
        encoder.close_element(ELEM_JOIN_PER_PRIMITIVE)?;
        Ok(())
    }

    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _resource: &ParamListStandard,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        let elem = parser
            .start(&[ELEM_JOIN_PER_PRIMITIVE.name])
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        if let Some(attrib_string) = elem.get_attribute(ATTRIB_STORAGE.name) {
            self.resource_type = StorageClass::from_str(&attrib_string)?;
        }
        parser
            .end()
            .map_err(|e| XmlParseException::new(e.message().to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::array::Array;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::protorules::param_test_support::{TestEntry, TestResource};
    use crate::program::model::lang::protorules::xml_test_support::{MockElement, QueueParser};
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::pcode::{AttributeId, ElementId};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[derive(Clone)]
    struct MockPrimitive {
        length: i32,
    }
    impl DataType for MockPrimitive {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        offset: i32,
        dt_len: i32,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockPrimitive { length: self.dt_len })
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockStruct {
        components: Vec<MockComponent>,
    }
    impl DataType for MockStruct {
        fn get_length(&self) -> i32 {
            self.components.iter().map(|c| c.dt_len).sum()
        }
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for MockStruct {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components.iter().cloned().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
        }
        fn is_packing_enabled(&self) -> bool {
            false
        }
    }
    impl Structure for MockStruct {}

    struct MockArray {
        num_elements: i32,
        elem_len: i32,
    }
    impl DataType for MockArray {
        fn get_length(&self) -> i32 {
            self.num_elements * self.elem_len
        }
        fn is_array(&self) -> bool {
            true
        }
        fn as_array(&self) -> Option<&dyn Array> {
            Some(self)
        }
    }
    impl Array for MockArray {
        fn get_num_elements(&self) -> i32 {
            self.num_elements
        }
        fn get_element_length(&self) -> i32 {
            self.elem_len
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockPrimitive { length: self.elem_len })
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    /// Two "general" registers, each a 4-byte exclusion slot, plus a language that reports every
    /// merged Varnode as NOT a formal register (so `merge_sequence` never coalesces them) --
    /// enough for `MultiMemberAssign` to place a two-`int`-member struct one member per register.
    struct TwoRegLanguage;
    impl Language for TwoRegLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!()
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
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
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
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
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            // No formal register recognized at any address -- forces merge_sequence to treat
            // every merge as "informal" and keep pieces separate.
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
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
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
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
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn two_reg_resource() -> ParamListStandard {
        TestResource {
            entries: vec![
                TestEntry {
                    ty: StorageClass::General,
                    group: 0,
                    addressbase: 0x1000,
                    align: 0, // exclusion (single register) slot
                    space: ram_space(),
                    ..TestEntry::default()
                },
                TestEntry {
                    ty: StorageClass::General,
                    group: 1,
                    addressbase: 0x2000,
                    align: 0,
                    space: ram_space(),
                    ..TestEntry::default()
                },
            ],
            num_group: 2,
            spacebase: None,
        }
        .build_with_language(Some(Arc::new(TwoRegLanguage)))
    }

    #[test]
    fn assign_address_splits_a_two_member_struct_across_two_registers() {
        let action = MultiMemberAssign::new(StorageClass::General, false, true);
        let dt: Arc<dyn DataType> = Arc::new(MockStruct {
            components: vec![
                MockComponent { offset: 0, dt_len: 4 },
                MockComponent { offset: 4, dt_len: 4 },
            ],
        });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_reg_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, SUCCESS);
        assert_eq!(status, [-1, -1]); // both exclusion registers consumed
        let pieces = res.join_pieces.expect("two disjoint registers must produce join pieces");
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].get_address().offset(), 0x1000);
        assert_eq!(pieces[1].get_address().offset(), 0x2000);
    }

    #[test]
    fn assign_address_fails_when_primitive_extraction_is_invalid() {
        // A bare (non-array, non-struct) data-type is not something PrimitiveExtractor can
        // decompose into members at all.
        let action = MultiMemberAssign::new(StorageClass::General, false, true);
        let dt: Arc<dyn DataType> = Arc::new(MockPrimitive { length: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_reg_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
    }

    #[test]
    fn assign_address_fails_when_not_enough_registers_remain() {
        let action = MultiMemberAssign::new(StorageClass::General, false, true);
        // Three int members, but only two registers available.
        let dt: Arc<dyn DataType> = Arc::new(MockArray { num_elements: 3, elem_len: 4 });
        let dt_manager = MockDataTypeManager;
        let proto = PrototypePieces::default();
        let mut status = [0i32; 2];
        let mut res = ParameterPieces::default();

        let code = action.assign_address(&two_reg_resource(), &dt, &proto, 0, &dt_manager, &mut status, &mut res);
        assert_eq!(code, FAIL);
        // No partial commitment: status is untouched on failure (tmpStatus was discarded).
        assert_eq!(status, [0, 0]);
    }

    #[test]
    fn is_equivalent_compares_all_three_configuration_fields() {
        let a = MultiMemberAssign::new(StorageClass::General, false, true);
        let b = MultiMemberAssign::new(StorageClass::General, false, true);
        assert!(a.is_equivalent(&b));

        let diff_stack = MultiMemberAssign::new(StorageClass::General, true, true);
        assert!(!a.is_equivalent(&diff_stack));

        let diff_sig = MultiMemberAssign::new(StorageClass::General, false, false);
        assert!(!a.is_equivalent(&diff_sig));

        let diff_store = MultiMemberAssign::new(StorageClass::Float, false, true);
        assert!(!a.is_equivalent(&diff_store));
    }

    #[test]
    fn clone_box_carries_configuration_and_new_resource() {
        let action = MultiMemberAssign::new(StorageClass::Vector, true, false);
        let cloned = action.clone_box(&two_reg_resource()).expect("clone should succeed");
        assert!(action.is_equivalent(cloned.as_ref()));
    }

    struct RecordingEncoder {
        elements: Vec<&'static str>,
        strings: Vec<(&'static str, String)>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> std::io::Result<()> {
            self.elements.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, _elem_id: ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> std::io::Result<()> {
            self.strings.push((attrib_id.name, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_omits_storage_attribute_for_general() {
        let action = MultiMemberAssign::new(StorageClass::General, false, true);
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.elements, vec!["join_per_primitive"]);
        assert!(enc.strings.is_empty());
    }

    #[test]
    fn encode_writes_storage_attribute_for_non_general() {
        let action = MultiMemberAssign::new(StorageClass::Float, false, true);
        let mut enc = RecordingEncoder { elements: Vec::new(), strings: Vec::new() };
        action.encode(&mut enc).unwrap();
        assert_eq!(enc.strings, vec![("storage", "float".to_string())]);
    }

    #[test]
    fn restore_xml_reads_optional_storage_attribute() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("join_per_primitive", 0, &[("storage", "vector")]),
            MockElement::end("join_per_primitive", 0),
        ]);
        let mut action = MultiMemberAssign::new(StorageClass::General, false, true);
        action.restore_xml(&mut parser, &two_reg_resource()).unwrap();
        assert_eq!(action.resource_type, StorageClass::Vector);
    }

    #[test]
    fn restore_xml_keeps_default_storage_when_attribute_absent() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("join_per_primitive", 0, &[]),
            MockElement::end("join_per_primitive", 0),
        ]);
        let mut action = MultiMemberAssign::new(StorageClass::Ptr, false, true);
        action.restore_xml(&mut parser, &two_reg_resource()).unwrap();
        assert_eq!(action.resource_type, StorageClass::Ptr);
    }
}
