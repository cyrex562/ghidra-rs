//! Shared test fixtures for restoring compiler-spec fragments (`<pentry>`, `<input>`/`<output>`,
//! `<prototype>`, `<data_organization>`) from XML.
//!
//! [`ParamEntry::restore_xml`](super::param_entry::ParamEntry::restore_xml) and the classes built
//! on it resolve `<register name="...">` and `<addr space="...">` tags against a
//! [`CompilerSpec`], which in turn needs a [`Language`] with a real register file. Neither trait
//! has a lightweight concrete implementor in this crate yet (`BasicCompilerSpec` needs a loaded
//! `SleighLanguage`), so this module supplies an x86-64-shaped register file and address-space
//! set, laid out exactly as `x86-64.slaspec` lays them out (RAX at register offset 0, RDI at
//! 0x38, XMM0 at 0x1200, ...), so parsed offsets can be asserted against the real processor.
#![cfg(test)]

use std::collections::HashSet;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::lang::compiler_spec::{CompilerSpec, EvaluationModelType};
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::parameter::Parameter;
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PcodeInjectLibrary;
use crate::util::xml::non_threaded_xml_pull_parser_impl::NonThreadedXmlPullParserImpl;
use crate::util::xml::xml_pull_parser_factory::create_from_str;

/// The `ram` space (id 1), 64-bit.
pub(crate) fn ram_space() -> Arc<AddressSpace> {
    AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1)
}

/// The `register` space (id 2).
pub(crate) fn register_space() -> Arc<AddressSpace> {
    AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2)
}

/// The compiler-spec `stack` space (id 3), 64-bit signed offsets.
pub(crate) fn stack_space() -> Arc<AddressSpace> {
    AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 3)
}

/// The `join` space (id 4).
pub(crate) fn join_space() -> Arc<AddressSpace> {
    AddressSpace::new("join", 64, 1, AddressSpaceType::Join, 4)
}

/// `(name, register-space offset, size in bytes)` for the subset of the x86-64 register file the
/// fixtures reference.
const X86_64_REGISTERS: &[(&str, i64, i32)] = &[
    ("RAX", 0x0, 8),
    ("EAX", 0x0, 4),
    ("RCX", 0x8, 8),
    ("RDX", 0x10, 8),
    ("RBX", 0x18, 8),
    ("RSP", 0x20, 8),
    ("RBP", 0x28, 8),
    ("RSI", 0x30, 8),
    ("RDI", 0x38, 8),
    ("R8", 0x80, 8),
    ("R9", 0x88, 8),
    ("R10", 0x90, 8),
    ("R11", 0x98, 8),
    ("R12", 0xa0, 8),
    ("R13", 0xa8, 8),
    ("R14", 0xb0, 8),
    ("R15", 0xb8, 8),
    ("XMM0_Qa", 0x1200, 8),
    ("XMM0", 0x1200, 16),
    ("XMM1_Qa", 0x1220, 8),
    ("XMM1", 0x1220, 16),
    ("ST0", 0x1106, 10),
];

/// An x86-64-shaped [`Language`]: a register file from [`X86_64_REGISTERS`] and the endianness
/// given at construction. Everything not needed to resolve compiler-spec XML is unimplemented.
#[derive(Clone)]
pub(crate) struct TestCspecLanguage {
    pub big_endian: bool,
}

impl TestCspecLanguage {
    fn make_register(&self, name: &str, offset: i64, size: i32) -> RegisterRef {
        Register::new(
            name,
            name,
            Address::new(register_space(), offset),
            size,
            self.big_endian,
            0,
        )
    }
}

impl Language for TestCspecLanguage {
    fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
        crate::program::model::lang::language_id::LanguageID::new("x86:LE:64:default").unwrap()
    }
    fn get_language_description(
        &self,
    ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_parallel_instruction_helper(
        &self,
    ) -> Option<
        Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>,
    > {
        None
    }
    fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_version(&self) -> i32 {
        1
    }
    fn get_minor_version(&self) -> i32 {
        0
    }
    fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
        unimplemented!("not needed to restore compiler-spec XML")
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
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_number_of_user_defined_op_names(&self) -> i32 {
        0
    }
    fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
        None
    }
    fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
        self.get_registers()
            .into_iter()
            .filter(|r| r.borrow().address() == address)
            .collect()
    }
    fn get_register_in_space(
        &self,
        addrspc: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
    ) -> Option<RegisterRef> {
        self.get_register_at(&Address::new(addrspc.clone(), offset), size)
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        X86_64_REGISTERS
            .iter()
            .map(|(name, off, size)| self.make_register(name, *off, *size))
            .collect()
    }
    fn get_register_names(&self) -> Vec<String> {
        X86_64_REGISTERS.iter().map(|(name, _, _)| name.to_string()).collect()
    }
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        X86_64_REGISTERS
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
            .map(|(n, off, size)| self.make_register(n, *off, *size))
    }
    fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
        if addr.space().space_type() != AddressSpaceType::Register {
            return None;
        }
        X86_64_REGISTERS
            .iter()
            .find(|(_, off, sz)| *off == addr.offset() && *sz == size)
            .map(|(n, off, sz)| self.make_register(n, *off, *sz))
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
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
    fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
        Ok(())
    }
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        Vec::new()
    }
    fn get_compiler_spec_by_id(
        &self,
        _compiler_spec_id: &CompilerSpecID,
    ) -> Result<
        Box<dyn CompilerSpec>,
        crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
    > {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        unimplemented!("not needed to restore compiler-spec XML")
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
    fn get_property_keys(&self) -> HashSet<String> {
        HashSet::new()
    }
    fn has_manual(&self) -> bool {
        false
    }
    fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
        None
    }
    fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
        HashSet::new()
    }
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
        None
    }
    fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
        Vec::new()
    }
    fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_maximum_instruction_length(&self) -> Option<i32> {
        None
    }
}

/// A [`CompilerSpec`] exposing just what compiler-spec XML restore consults: the language's
/// registers, the `ram`/`register`/`stack`/`join` spaces by name, stack growth direction and
/// stack justification.
#[derive(Clone)]
pub(crate) struct TestCompilerSpec {
    pub language: TestCspecLanguage,
    pub stack_grows_negative: bool,
    pub stack_right_justified: bool,
    /// Spaces looked up by name before the built-in ones, letting a test resolve `<addr>` tags
    /// into its own address spaces.
    pub extra_spaces: Vec<Arc<AddressSpace>>,
}

impl TestCompilerSpec {
    /// Little-endian, negative stack growth: the x86-64 configuration.
    pub(crate) fn x86_64() -> Self {
        TestCompilerSpec {
            language: TestCspecLanguage { big_endian: false },
            stack_grows_negative: true,
            stack_right_justified: false,
            extra_spaces: Vec::new(),
        }
    }
}

impl CompilerSpec for TestCompilerSpec {
    fn get_language(&self) -> Box<dyn Language> {
        Box::new(self.language.clone())
    }
    fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_compiler_spec_id(&self) -> CompilerSpecID {
        CompilerSpecID::new(Some("gcc"))
    }
    fn get_stack_pointer(&self) -> Option<RegisterRef> {
        self.language.get_register_by_name("RSP")
    }
    fn is_stack_right_justified(&self) -> bool {
        self.stack_right_justified
    }
    fn get_address_space(&self, space_name: &str) -> Option<Arc<AddressSpace>> {
        if let Some(space) = self.extra_spaces.iter().find(|s| s.name() == space_name) {
            return Some(space.clone());
        }
        match space_name {
            "ram" => Some(ram_space()),
            "register" => Some(register_space()),
            "stack" => Some(stack_space()),
            "join" => Some(join_space()),
            _ => None,
        }
    }
    fn get_stack_space(&self) -> Arc<AddressSpace> {
        stack_space()
    }
    fn get_stack_base_space(&self) -> Arc<AddressSpace> {
        ram_space()
    }
    fn stack_grows_negative(&self) -> bool {
        self.stack_grows_negative
    }
    fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
    fn get_calling_conventions(&self) -> Vec<Arc<PrototypeModel>> {
        Vec::new()
    }
    fn get_calling_convention(&self, _name: &str) -> Option<Arc<PrototypeModel>> {
        None
    }
    fn get_all_models(&self) -> Vec<Arc<PrototypeModel>> {
        Vec::new()
    }
    fn get_default_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
        None
    }
    fn get_decompiler_output_language(&self) -> DecompilerLanguage {
        DecompilerLanguage::CLanguage
    }
    fn get_prototype_evaluation_model(&self, _model_type: EvaluationModelType) -> Arc<PrototypeModel> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn is_global(&self, _addr: &Address) -> bool {
        false
    }
    fn get_data_organization(&self) -> Box<dyn DataOrganization> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn match_convention(&self, _convention_name: &str) -> Arc<PrototypeModel> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Arc<PrototypeModel> {
        unimplemented!("not needed to restore compiler-spec XML")
    }
    fn has_property(&self, _key: &str) -> bool {
        false
    }
    fn does_c_data_type_conversions(&self) -> bool {
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
    fn get_property_keys(&self) -> HashSet<String> {
        HashSet::new()
    }
    fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
        Ok(())
    }
    fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
        false
    }
}

/// A pull parser over `xml`.
pub(crate) fn parser(xml: &str) -> NonThreadedXmlPullParserImpl {
    create_from_str(xml, "test.cspec", None, false).expect("well-formed test XML")
}

/// A primitive [`DataType`](crate::program::model::data::data_type::DataType) of the given shape,
/// for driving parameter assignment.
#[derive(Clone)]
pub(crate) struct TestDataType {
    pub length: i32,
    pub alignment: i32,
    pub float: bool,
    pub pointer: bool,
    pub void: bool,
}

impl crate::program::model::data::data_type::DataType for TestDataType {
    fn get_length(&self) -> i32 {
        self.length
    }
    fn get_alignment(&self) -> i32 {
        self.alignment
    }
    fn is_floating_point(&self) -> bool {
        self.float
    }
    fn is_pointer(&self) -> bool {
        self.pointer
    }
    fn is_void_type(&self) -> bool {
        self.void
    }
    fn is_integer_type(&self) -> bool {
        !self.float && !self.pointer && !self.void
    }
    fn clone_data_type(
        &self,
        _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
    ) -> Box<dyn crate::program::model::data::data_type::DataType> {
        Box::new(self.clone())
    }
}

/// A program whose only capability is its [`TestDataTypeManager`].
pub(crate) struct TestProgram;
impl crate::framework::model::DomainObject for TestProgram {}
impl crate::program::model::listing::program::Program for TestProgram {
    fn get_name(&self) -> String {
        "test".to_string()
    }
    fn get_language_id(&self) -> String {
        "x86:LE:64:default".to_string()
    }
    fn get_data_type_manager(&self) -> Option<Box<dyn crate::program::model::data::data_type_manager::DataTypeManager>> {
        Some(Box::new(TestDataTypeManager))
    }
}

/// An `length`-byte integer type.
pub(crate) fn int_type(length: i32) -> Arc<dyn crate::program::model::data::data_type::DataType> {
    Arc::new(TestDataType { length, alignment: length, float: false, pointer: false, void: false })
}

/// An `length`-byte floating-point type.
pub(crate) fn float_type(length: i32) -> Arc<dyn crate::program::model::data::data_type::DataType> {
    Arc::new(TestDataType { length, alignment: length, float: true, pointer: false, void: false })
}

/// The `void` type.
pub(crate) fn void_type() -> Arc<dyn crate::program::model::data::data_type::DataType> {
    Arc::new(TestDataType { length: 0, alignment: 1, float: false, pointer: false, void: true })
}

/// A data-type manager whose pointers have the requested size (8 bytes by default).
pub(crate) struct TestDataTypeManager;
impl crate::program::model::data::data_type_manager::DataTypeManager for TestDataTypeManager {
    fn get_pointer(
        &self,
        datatype: &dyn crate::program::model::data::data_type::DataType,
    ) -> Box<dyn crate::program::model::data::pointer::Pointer> {
        self.get_pointer_with_size(datatype, -1)
    }
    fn get_pointer_with_size(
        &self,
        _datatype: &dyn crate::program::model::data::data_type::DataType,
        size: i32,
    ) -> Box<dyn crate::program::model::data::pointer::Pointer> {
        Box::new(TestPointer { size: if size <= 0 { 8 } else { size } })
    }
}

/// A pointer of a fixed size, as handed out by [`TestDataTypeManager`].
pub(crate) struct TestPointer {
    pub size: i32,
}
impl crate::program::model::data::data_type::DataType for TestPointer {
    fn get_length(&self) -> i32 {
        self.size
    }
    fn get_alignment(&self) -> i32 {
        self.size
    }
    fn is_pointer(&self) -> bool {
        true
    }
}
impl crate::program::model::data::pointer::Pointer for TestPointer {
    fn get_data_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
        None
    }
    fn new_pointer(
        &self,
        _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
    ) -> Box<dyn crate::program::model::data::pointer::Pointer> {
        Box::new(TestPointer { size: self.size })
    }
    fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
        unimplemented!("not needed for parameter assignment")
    }
}

/// The `<input>` list of the x86-64 System V `__stdcall` prototype from `x86-64-gcc.cspec`,
/// reduced to two float registers.
pub(crate) const SYSV_INPUT: &str = r#"<input>
  <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
  <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM1_Qa"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="RSI"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="RCX"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="R8"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="R9"/></pentry>
  <pentry minsize="1" maxsize="500" align="8"><addr offset="8" space="stack"/></pentry>
</input>"#;

/// The `<output>` list of the x86-64 System V prototype from `x86-64-gcc.cspec`.
pub(crate) const SYSV_OUTPUT: &str = r#"<output>
  <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
  <pentry minsize="1" maxsize="8"><register name="RAX"/></pentry>
  <pentry minsize="9" maxsize="16"><addr space="join" piece1="RDX" piece2="RAX"/></pentry>
</output>"#;

/// A model restored from a `<prototype>` element against [`TestCompilerSpec::x86_64`].
pub(crate) fn restore_model(xml: &str) -> PrototypeModel {
    let mut model = PrototypeModel::new();
    model
        .restore_xml(&mut parser(xml), &TestCompilerSpec::x86_64(), None)
        .expect("well-formed test prototype");
    model
}

/// A model named `name` with empty parameter lists.
pub(crate) fn named_model(name: &str) -> PrototypeModel {
    restore_model(&format!(
        r#"<prototype name="{name}" extrapop="unknown" stackshift="0"><input/><output/></prototype>"#
    ))
}
