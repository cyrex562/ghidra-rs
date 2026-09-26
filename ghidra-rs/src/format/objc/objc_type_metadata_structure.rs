//! Port of `ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure`.
//!
//! Java's abstract class stores the fields shared by every Objective-C type metadata structure
//! (the owning [`Program`], the shared [`ObjcState`], a "base address", derived pointer size, and
//! derived 32-bit/ARM flags) and declares one abstract method, `applyTo`. Following the
//! composition-over-inheritance split already established by `objc_method.rs`'s
//! `ObjcMethodBase`/`ObjcMethod` pair: the shared fields/derived flags live in
//! [`ObjcTypeMetadataStructureBase`], and the [`ObjcTypeMetadataStructure`] trait supplies the
//! concrete accessors (mirroring the Java concrete methods) plus the one abstract `apply_to`
//! member. `implements StructConverter` becomes a supertrait bound, exactly matching how Java
//! interface implementation works (no inheritance faking involved).

use std::io;
use std::sync::{Arc, Mutex};

use crate::app::util::bin::struct_converter::StructConverter;
use crate::format::objc::objc_state::ObjcState;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::Namespace;
use crate::util::task::TaskMonitor;

/// Port of `ObjcTypeMetadataStructure.DATA_TYPE_CATEGORY`.
pub const DATA_TYPE_CATEGORY: &str = "/ObjcTypeMetadata";

/// The shared state every [`ObjcTypeMetadataStructure`] implementor carries.
///
/// Java: the `program`, `state`, `base`, `pointerSize`, `is32bit`, and `isArm` fields on the
/// abstract `ObjcTypeMetadataStructure` class, all set once by its constructor.
///
/// [`ObjcState`] is shared (and mutated in place, e.g. via `ObjcState.close()`) across every
/// metadata structure processed during a single analysis pass in Java, where it is simply an
/// object reference; `Arc<Mutex<ObjcState>>` reproduces that shared-mutable-reference semantics
/// in Rust (`ObjcState`'s fields are all `Send + Sync`-safe, matching the rest of this crate's
/// preference for `Arc`/`Mutex` over `Rc`/`RefCell` for program-analysis state).
pub struct ObjcTypeMetadataStructureBase {
    program: Arc<dyn Program>,
    state: Arc<Mutex<ObjcState>>,
    base: i64,
    pointer_size: i32,
    is_32_bit: bool,
    is_arm: bool,
}

impl ObjcTypeMetadataStructureBase {
    /// Java: `ObjcTypeMetadataStructure(Program program, ObjcState state, long base)`.
    ///
    /// Derives `pointerSize` from `program.getDefaultPointerSize()`, `is32bit` from
    /// `pointerSize == 4`, and `isArm` from comparing the program's language's processor against
    /// `Processor.findOrPossiblyCreateProcessor("ARM")`.
    ///
    /// The real Java comparison is `Processor.equals(Object)`, which is structural equality by
    /// processor name (see
    /// [`crate::program::model::lang::processor::Processor`]'s doc comment). The seam-stub
    /// [`Language::get_processor`](crate::program::model::lang::Language::get_processor) that
    /// this crate currently wires up returns a different, placeholder `Processor` type (see
    /// `crate::program::seam_stubs::Processor`) that only exposes a `name()` accessor -- so this
    /// bridges the two by comparing `name()` against the literal `"ARM"` string, which is
    /// equivalent to the real name-based `equals()` check without requiring the two `Processor`
    /// seams to be unified (out of scope for this port).
    pub fn new(program: Arc<dyn Program>, state: Arc<Mutex<ObjcState>>, base: i64) -> Self {
        let pointer_size = program.get_default_pointer_size();
        let is_32_bit = pointer_size == 4;
        let is_arm = program
            .get_language()
            .map(|language| is_arm_processor_name(&language.get_processor().name()))
            .unwrap_or(false);

        Self { program, state, base, pointer_size, is_32_bit, is_arm }
    }

    /// Java: `getProgram()`.
    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// Java: `getBase()`.
    pub fn get_base(&self) -> i64 {
        self.base
    }

    /// Java: `getState()`.
    pub fn get_state(&self) -> &Arc<Mutex<ObjcState>> {
        &self.state
    }

    /// Java: `getPointerSize()`.
    pub fn get_pointer_size(&self) -> i32 {
        self.pointer_size
    }

    /// Java: `is32bit()`.
    pub fn is_32_bit(&self) -> bool {
        self.is_32_bit
    }

    /// Java: `isArm()`.
    pub fn is_arm(&self) -> bool {
        self.is_arm
    }
}

/// Extracted as a pure function so the exact-match ARM-detection rule can be unit tested
/// without needing to construct a full `Program`/`Language` mock chain.
fn is_arm_processor_name(name: &str) -> bool {
    // Java: `processor.equals(Processor.findOrPossiblyCreateProcessor("ARM"))`. Processor
    // equality is by exact (case-sensitive) name, not `equalsIgnoreCase`.
    name == "ARM"
}

/// Implemented by all Objective-C type metadata structures.
///
/// Port of the abstract `ghidra.app.util.bin.format.objc.ObjcTypeMetadataStructure` class.
pub trait ObjcTypeMetadataStructure: StructConverter {
    /// Accessor to the shared state every Objective-C type metadata structure carries.
    fn structure_base(&self) -> &ObjcTypeMetadataStructureBase;

    /// Java: `getProgram()`.
    fn get_program(&self) -> &Arc<dyn Program> {
        self.structure_base().get_program()
    }

    /// Java: `getBase()`.
    fn get_base(&self) -> i64 {
        self.structure_base().get_base()
    }

    /// Java: `getState()`.
    fn get_state(&self) -> &Arc<Mutex<ObjcState>> {
        self.structure_base().get_state()
    }

    /// Java: `getPointerSize()`.
    fn get_pointer_size(&self) -> i32 {
        self.structure_base().get_pointer_size()
    }

    /// Java: `is32bit()`.
    fn is_32_bit(&self) -> bool {
        self.structure_base().is_32_bit()
    }

    /// Java: `isArm()`.
    fn is_arm(&self) -> bool {
        self.structure_base().is_arm()
    }

    /// Applies this structure to the program.
    ///
    /// `namespace` is an optional namespace to apply to (Java: `Namespace namespace`, which may
    /// be `null`). `monitor` is a cancellable monitor.
    ///
    /// # Errors
    /// Returns `Err` if an error occurred while applying the structure (Java: `throws Exception`).
    ///
    /// Java: `applyTo(Namespace namespace, TaskMonitor monitor)` (abstract).
    fn apply_to(&self, namespace: Option<&dyn Namespace>, monitor: &dyn TaskMonitor)
        -> io::Result<()>;

    /// Java: `toString()`, which returns `"%s at 0x%x".formatted(getClass().getSimpleName(),
    /// base)`. Rust has no direct equivalent of `getClass().getSimpleName()`'s reflection, so
    /// this uses `std::any::type_name::<Self>()` (stripped to its unqualified tail), matching the
    /// same convention already established by
    /// [`AbstractParsableItem::emit`](crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem::emit).
    fn to_display_string(&self) -> String {
        let full = std::any::type_name::<Self>();
        let simple = full.rsplit("::").next().unwrap_or(full);
        format!("{simple} at 0x{:x}", self.structure_base().get_base())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::struct_converter::ToDataTypeError;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type::DataType;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockProgram {
        pointer_size: i32,
        // Not stored as `Option<Arc<dyn Language>>`: `Language` isn't `Send + Sync`, and
        // `Program: Send + Sync` requires every field of an implementor to be too. Instead the
        // `Arc<dyn Language>` is constructed on demand inside `get_language()` below, so it never
        // needs to be part of `MockProgram`'s own auto-derived Send/Sync footprint.
        processor_name: Option<String>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_language(&self) -> Option<Arc<dyn crate::program::model::lang::Language>> {
            self.processor_name.clone().map(|processor_name| {
                Arc::new(MockLanguage { processor_name })
                    as Arc<dyn crate::program::model::lang::Language>
            })
        }
        fn get_default_pointer_size(&self) -> i32 {
            self.pointer_size
        }
    }

    struct MockSeamProcessor(String);
    impl crate::program::seam_stubs::Processor for MockSeamProcessor {
        fn name(&self) -> String {
            self.0.clone()
        }
    }

    /// Minimal `Language` mock exposing only a configurable processor name; every other method
    /// either has a harmless default or is `unimplemented!()` since `ObjcTypeMetadataStructureBase
    /// ::new` only ever calls `get_processor()`.
    struct MockLanguage {
        processor_name: String,
    }

    impl crate::program::model::lang::Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            crate::program::model::lang::LanguageID::new("mock:LE:32:default").unwrap()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("not needed for this test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            Box::new(MockSeamProcessor(self.processor_name.clone()))
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not needed for this test")
        }
        fn get_default_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for this test")
        }
        fn get_default_data_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for this test")
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
            unimplemented!("not needed for this test")
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
            _addrspc: &Arc<crate::program::model::address::AddressSpace>,
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
        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
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
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not needed for this test")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not needed for this test")
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
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }

    fn mock_program(pointer_size: i32, processor_name: Option<&str>) -> Arc<dyn Program> {
        Arc::new(MockProgram { pointer_size, processor_name: processor_name.map(str::to_string) })
    }

    /// A trivial concrete implementor exercising the trait's default accessor methods and
    /// `apply_to`/`to_data_type`.
    struct TestStructure {
        base: ObjcTypeMetadataStructureBase,
        applied: AtomicBool,
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    impl StructConverter for TestStructure {
        fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl ObjcTypeMetadataStructure for TestStructure {
        fn structure_base(&self) -> &ObjcTypeMetadataStructureBase {
            &self.base
        }

        fn apply_to(
            &self,
            _namespace: Option<&dyn Namespace>,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<()> {
            self.applied.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn make_state() -> Arc<Mutex<ObjcState>> {
        Arc::new(Mutex::new(ObjcState {
            been_applied: HashSet::new(),
            method_map: std::collections::HashMap::new(),
            thumb_code_locations: HashSet::new(),
            class_index_map: std::collections::HashMap::new(),
            variable_map: std::collections::HashMap::new(),
            lib_objc_optimization: None,
            encodings: Box::new(StubEncodings),
        }))
    }

    struct StubEncodings;
    impl crate::format::seam_stubs::Objc1TypeEncodings for StubEncodings {
        fn to_string(&self) -> String {
            "stub".to_string()
        }
        fn process_method_signature(
            &self,
            _program: &dyn Program,
            _method_address: &crate::program::model::address::Address,
            _mangled_signature: &str,
            _method_type: &crate::format::objc::objc_method_type::ObjcMethodType,
        ) {
        }
        fn to_function_signature(
            &self,
            _method_name: &str,
            _mangled_signature: &str,
        ) -> Box<dyn crate::format::seam_stubs::FunctionSignature> {
            unimplemented!("not needed for this test")
        }
        fn process_instance_variable_signature(
            &self,
            _program: &dyn Program,
            _instance_variable_address: &crate::program::model::address::Address,
            _mangled_type: &str,
            _instance_variable_size: i32,
        ) {
        }
    }

    #[test]
    fn is_arm_processor_name_matches_only_exact_arm() {
        assert!(is_arm_processor_name("ARM"));
        assert!(!is_arm_processor_name("arm"));
        assert!(!is_arm_processor_name("x86"));
        assert!(!is_arm_processor_name(""));
    }

    #[test]
    fn constructor_derives_32bit_and_arm_flags_from_program() {
        let program = mock_program(4, Some("ARM"));
        let base = ObjcTypeMetadataStructureBase::new(program, make_state(), 0x1000);
        assert_eq!(base.get_pointer_size(), 4);
        assert!(base.is_32_bit());
        assert!(base.is_arm());
        assert_eq!(base.get_base(), 0x1000);
    }

    #[test]
    fn constructor_detects_64bit_non_arm_program() {
        let program = mock_program(8, Some("x86"));
        let base = ObjcTypeMetadataStructureBase::new(program, make_state(), 0x2000);
        assert_eq!(base.get_pointer_size(), 8);
        assert!(!base.is_32_bit());
        assert!(!base.is_arm());
    }

    #[test]
    fn constructor_treats_missing_language_as_not_arm() {
        // Program::get_language() defaults to None; ObjcTypeMetadataStructureBase must not
        // panic, and must report is_arm() == false rather than propagating the missing language.
        let program = mock_program(4, None);
        let base = ObjcTypeMetadataStructureBase::new(program, make_state(), 0);
        assert!(!base.is_arm());
    }

    #[test]
    fn accessors_delegate_through_trait_default_methods() {
        let program = mock_program(4, Some("ARM"));
        let structure = TestStructure {
            base: ObjcTypeMetadataStructureBase::new(program, make_state(), 0x4000),
            applied: AtomicBool::new(false),
        };

        assert_eq!(structure.get_base(), 0x4000);
        assert_eq!(structure.get_pointer_size(), 4);
        assert!(structure.is_32_bit());
        assert!(structure.is_arm());
        assert!(Arc::ptr_eq(structure.get_program(), structure.structure_base().get_program()));
    }

    #[test]
    fn apply_to_invokes_the_concrete_implementation() {
        let program = mock_program(4, None);
        let structure = TestStructure {
            base: ObjcTypeMetadataStructureBase::new(program, make_state(), 0),
            applied: AtomicBool::new(false),
        };

        assert!(!structure.applied.load(Ordering::SeqCst));
        structure.apply_to(None, &crate::util::task::DummyMonitor).unwrap();
        assert!(structure.applied.load(Ordering::SeqCst));
    }

    #[test]
    fn to_display_string_matches_java_format() {
        let program = mock_program(4, None);
        let structure = TestStructure {
            base: ObjcTypeMetadataStructureBase::new(program, make_state(), 0xdead),
            applied: AtomicBool::new(false),
        };

        // Java: "%s at 0x%x".formatted(getClass().getSimpleName(), base)
        assert_eq!(structure.to_display_string(), "TestStructure at 0xdead");
    }

    #[test]
    fn to_data_type_delegates_to_struct_converter_impl() {
        let program = mock_program(4, None);
        let structure = TestStructure {
            base: ObjcTypeMetadataStructureBase::new(program, make_state(), 0),
            applied: AtomicBool::new(false),
        };
        assert!(structure.to_data_type().is_ok());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let program = mock_program(4, Some("ARM"));
        let structure: Box<dyn ObjcTypeMetadataStructure> = Box::new(TestStructure {
            base: ObjcTypeMetadataStructureBase::new(program, make_state(), 0x10),
            applied: AtomicBool::new(false),
        });
        assert!(structure.is_arm());
        assert_eq!(structure.get_base(), 0x10);
    }
}
