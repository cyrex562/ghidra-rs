//! Shared state and behavior for Sleigh userop definitions.
//!
//! Corresponds to `ghidra.pcode.exec.AbstractSleighPcodeUseropDefinition`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::sleigh_pcode_userop_definition::{
    BodyFunc, BuilderStage1, BuilderStage2, SignatureDef, SleighPcodeUseropDefinition, OUT_SYMBOL_NAME,
};
use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropLibrary};
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::seam_stubs::{
    FixedSleighPcodeUseropDefinition, OverloadedSleighPcodeUseropDefinition, PcodeProgram,
};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// The shared state and concrete (non-abstract) behavior of a Sleigh userop definition.
///
/// Java's `AbstractSleighPcodeUseropDefinition<T>` is an abstract class: it carries the
/// `language`/`name`/`cacheByArgs` fields and implements every method of
/// `SleighPcodeUseropDefinition` except `getBody`/`programFor`, which it leaves abstract for its
/// two subclasses ([`FixedSleighPcodeUseropDefinition`](crate::pcode::seam_stubs::FixedSleighPcodeUseropDefinition)
/// and [`OverloadedSleighPcodeUseropDefinition`](crate::pcode::seam_stubs::OverloadedSleighPcodeUseropDefinition),
/// not yet ported -- see `seam_stubs`). Rust has no field inheritance, so this struct holds the
/// shared fields plus the concrete logic; a concrete definition embeds it and implements
/// [`SleighPcodeUseropDefinition`] (equivalently, [`AbstractSleighPcodeUseropDefinition`], its
/// marker supertrait) for the two methods that remain abstract.
pub struct AbstractSleighPcodeUseropDefinitionBase {
    language: Arc<SleighLanguage>,
    name: String,
    /// Cache of compiled programs keyed by argument list (output at index 0, or `None`, then
    /// inputs). Java's `Map<List<Varnode>, PcodeProgram>`; `Varnode` has no `Hash` impl in this
    /// port, so this is a linear association list rather than a `HashMap`.
    ///
    /// Unused by this base itself -- only by the (not yet ported) subclasses that implement
    /// `program_for` -- but carried here since Java declares it on the abstract class.
    #[allow(dead_code)]
    cache_by_args: Vec<(Vec<Option<Varnode>>, Box<dyn PcodeProgram>)>,
}

impl AbstractSleighPcodeUseropDefinitionBase {
    /// Port of the protected constructor `AbstractSleighPcodeUseropDefinition(SleighLanguage, String)`.
    pub fn new(language: Arc<SleighLanguage>, name: impl Into<String>) -> Self {
        Self {
            language,
            name: name.into(),
            cache_by_args: Vec::new(),
        }
    }

    /// The Sleigh language this userop is defined for.
    pub fn language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }

    /// Port of `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Port of `isFunctional()`: Sleigh userops are never purely functional.
    pub fn is_functional(&self) -> bool {
        false
    }

    /// Port of `hasSideEffects()`: Sleigh userops are assumed to have side effects.
    pub fn has_side_effects(&self) -> bool {
        true
    }

    /// Port of `modifiesContext()`.
    ///
    /// We could scan the p-code ops for any that write to the contextreg; however, at the
    /// moment, that is highly unconventional and perhaps even considered an error. If that
    /// becomes more common, or even recommended, then we can detect it and behave accordingly
    /// during interpretation (whether for execution or translation).
    pub fn modifies_context(&self) -> bool {
        false
    }

    /// Port of `canInlinePcode()`.
    pub fn can_inline_pcode(&self) -> bool {
        true
    }

    /// Port of `getJavaMethod()`. Rust has no analog of `java.lang.reflect.Method`; this always
    /// returns `None`, matching Java always returning `null` here.
    pub fn get_java_method(&self) -> Option<()> {
        None
    }

    /// Port of `getDefiningLibrary()`: a plain Sleigh userop is not defined by a Java library.
    pub fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
        None
    }

    /// Port of `execute(PcodeExecutor<T>, PcodeUseropLibrary<T>, PcodeOp, Varnode, List<Varnode>)`.
    ///
    /// A free function generic over the concrete definition, rather than a method on this base,
    /// since it must dispatch to the abstract `program_for` -- which this base does not
    /// implement -- to build the program it hands to the executor. `op` is accepted (matching
    /// the Java signature) but unused, exactly as in the original.
    ///
    /// `T` is the executor's value type (Java's `<T>` on the enclosing class). The library is
    /// taken by concrete type so it can be handed both to `program_for`, which wants the erased
    /// wildcard form, and to the executor, which wants the typed form.
    pub fn execute<T: 'static, D: SleighPcodeUseropDefinition + ?Sized, L: PcodeUseropLibrary<T>>(
        definition: &D,
        executor: &PcodeExecutor<T>,
        library: &L,
        _op: &PcodeOp,
        out_arg: Option<Varnode>,
        in_args: &[Option<Varnode>],
    ) {
        let mut args = Vec::with_capacity(in_args.len() + 1);
        args.push(out_arg);
        args.extend_from_slice(in_args);
        let program = definition.program_for(&args, library);
        // Java lets the frame go and any `PcodeExecutionException` propagate out of this `void`
        // method; the nearest Rust equivalent is to panic, since the userop signature has no way
        // to report the failure.
        if let Err(e) = executor.execute(program.as_ref(), library) {
            panic!("Sleigh userop execution failed: {}", e.message());
        }
    }
}

/// The abstract operations a concrete Sleigh userop definition must still supply.
///
/// Port of the effectively-abstract part of `ghidra.pcode.exec.AbstractSleighPcodeUseropDefinition`:
/// every other method has a conventional implementation on
/// [`AbstractSleighPcodeUseropDefinitionBase`] (mirroring the Java class's bodies). The two
/// methods Java leaves abstract, `getBody`/`programFor`, are already declared by
/// [`SleighPcodeUseropDefinition`] (the interface this class implements), so this trait is a
/// marker supertrait rather than redeclaring them.
pub trait AbstractSleighPcodeUseropDefinition: SleighPcodeUseropDefinition {}

/// A builder for a particular userop.
///
/// Port of `AbstractSleighPcodeUseropDefinition.Builder`. Implements the already-ported
/// [`BuilderStage1`]/[`BuilderStage2`] traits from [`SleighPcodeUseropDefinition::Factory`].
pub struct Builder {
    language: Arc<SleighLanguage>,
    name: String,
    definitions: HashMap<i32, SignatureDef>,
    params: Vec<String>,
    body: Vec<Box<dyn BodyFunc>>,
}

impl Builder {
    /// Port of `new Builder(Factory, String)`. Java's constructor takes the enclosing `Factory`
    /// only to reach `factory.language`, so this takes the language directly.
    pub fn new(language: Arc<SleighLanguage>, name: impl Into<String>) -> Box<Self> {
        Box::new(Self {
            language,
            name: name.into(),
            definitions: HashMap::new(),
            params: vec![OUT_SYMBOL_NAME.to_string()],
            body: Vec::new(),
        })
    }

    /// Finalize the current signature into `definitions`, then reset `params`/`body` for the
    /// next one.
    ///
    /// Port of the body of `Builder.overload()`, kept as a private inherent method (rather than
    /// solely on the `BuilderStage2::overload` trait method) so `build()` can call it directly
    /// without losing the concrete type through `Box<dyn BuilderStage1>` erasure -- mirroring how
    /// Java's `build()` calls `overload()` as a plain instance method, not through the interface.
    fn finish_signature(&mut self) {
        let params = std::mem::replace(&mut self.params, vec![OUT_SYMBOL_NAME.to_string()]);
        let body = std::mem::take(&mut self.body);
        let key = params.len() as i32;
        let def = SignatureDef { signature: params, body };
        let exists = self.definitions.insert(key, def);
        if exists.is_some() {
            panic!("Definition for this signature already exists");
        }
    }
}

impl BuilderStage2 for Builder {
    fn body(mut self: Box<Self>, additional_body: Box<dyn BodyFunc>) -> Box<dyn BuilderStage2> {
        self.body.push(additional_body);
        self
    }

    fn overload(mut self: Box<Self>) -> Box<dyn BuilderStage1> {
        self.finish_signature();
        self
    }

    fn build(mut self: Box<Self>) -> Box<dyn SleighPcodeUseropDefinition> {
        self.finish_signature();
        if self.definitions.len() == 1 {
            let definition = self.definitions.into_values().next().unwrap();
            Box::new(FixedSleighPcodeUseropDefinition::new(self.language, self.name, definition))
        } else {
            Box::new(OverloadedSleighPcodeUseropDefinition::new(self.language, self.name, self.definitions))
        }
    }
}

impl BuilderStage1 for Builder {
    fn params(mut self: Box<Self>, additional_params: Vec<String>) -> Box<dyn BuilderStage1> {
        self.params.extend(additional_params);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::pcode::PackedDecode;

    /// Builds a minimal but real `SleighLanguage`, by feeding a hand-assembled packed-binary
    /// `<sleigh>` document through the crate's real `PackedDecode`. Identical to the fixture used
    /// by `abstract_assembly_tree_resolver`'s own `test_language`; `SleighLanguage`'s fields are
    /// private outside its module, so a literal construction isn't available here.
    fn test_language() -> Arc<SleighLanguage> {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>
        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap())
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    fn varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(test_address(offset), size)
    }

    #[test]
    fn base_reports_java_constant_flags() {
        let base = AbstractSleighPcodeUseropDefinitionBase::new(test_language(), "myop");
        assert_eq!(base.get_name(), "myop");
        assert!(!base.is_functional());
        assert!(base.has_side_effects());
        assert!(!base.modifies_context());
        assert!(base.can_inline_pcode());
        assert!(base.get_java_method().is_none());
        assert!(base.get_defining_library().is_none());
    }

    #[test]
    fn builder_single_signature_produces_fixed_definition() {
        let builder = Builder::new(test_language(), "myop");
        let built = builder.build();
        // A single signature (just the implicit OUT_SYMBOL_NAME param) collapses to Fixed.
        assert_eq!(built.get_body(&[None]), "");
    }

    #[test]
    #[should_panic(expected = "Definition for this signature already exists")]
    fn builder_overload_rejects_duplicate_signature() {
        let builder = Builder::new(test_language(), "myop");
        let stage1 = builder.overload();
        stage1.overload();
    }

    #[test]
    fn execute_builds_program_and_dispatches_to_executor() {
        use std::cell::Cell;

        struct RecordingProgram;
        impl PcodeProgram for RecordingProgram {
            fn code(&self) -> Vec<PcodeOp> {
                // The executor reads the program's ops to build its frame; seeing that read is
                // how this test observes the dispatch. An empty program executes no ops.
                EXECUTED.with(|e| e.set(true));
                Vec::new()
            }
        }

        struct RecordingDefinition;
        impl SleighPcodeUseropDefinition for RecordingDefinition {
            fn get_body(&self, _args: &[Option<Varnode>]) -> String {
                String::new()
            }
            fn program_for(
                &self,
                args: &[Option<Varnode>],
                _library: &dyn ErasedPcodeUseropLibrary,
            ) -> Box<dyn PcodeProgram> {
                // The output goes at index 0, followed by the inputs (empty here), matching
                // Java's `args.add(outArg); args.addAll(inArgs);`.
                assert_eq!(args.len(), 1);
                assert!(args[0].is_some());
                Box::new(RecordingProgram)
            }
        }

        thread_local! {
            static EXECUTED: Cell<bool> = Cell::new(false);
        }

        let definition = RecordingDefinition;
        let executor = PcodeExecutor::new(
            Arc::new(MockLanguage {
                default_space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            }),
            Arc::new(StubArithmetic),
            Arc::new(std::sync::Mutex::new(StubState)),
            crate::pcode::exec::pcode_executor_state_piece::Reason::ExecuteRead,
        );
        let library = nil::<i64>();
        let op = PcodeOp::new(
            crate::program::model::pcode::OpCode::CallOther,
            crate::program::model::pcode::SequenceNumber::new(test_address(0), 0),
            Vec::new(),
            None,
        );

        AbstractSleighPcodeUseropDefinitionBase::execute(
            &definition,
            &executor,
            &library,
            &op,
            Some(varnode(0x1000, 4)),
            &[],
        );

        EXECUTED.with(|e| assert!(e.get()));
    }

    /// A language just complete enough to bind a [`PcodeExecutor`]: it answers the two things the
    /// executor's constructor asks of it -- the program counter (none here) and the default space
    /// -- and nothing else. Paths are spelled out rather than imported, to keep the double local.
    struct MockLanguage {
        default_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            Box::new(crate::program::model::address::DefaultAddressFactory::new(vec![Arc::clone(
                &self.default_space,
            )]))
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
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
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
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
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
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
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
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
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
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
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// Arithmetic and state doubles: the recorded program has no ops, so neither is ever touched.
    struct StubArithmetic;

    impl crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<i64> for StubArithmetic {
        fn get_endian(&self) -> Option<crate::program::model::lang::endian::Endian> {
            Some(crate::program::model::lang::endian::Endian::Little)
        }
        fn unary_op(
            &self,
            _opcode: crate::program::model::pcode::OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn binary_op(
            &self,
            _opcode: crate::program::model::pcode::OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, _value: &[u8]) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn to_concrete(
            &self,
            _value: &i64,
            _purpose: crate::pcode::exec::pcode_arithmetic::Purpose,
        ) -> Result<Vec<u8>, crate::pcode::exec::concretion_error::ConcretionError> {
            unimplemented!("not exercised by these tests")
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct StubState;

    impl crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece for StubState {}

    impl crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<i64, i64>
        for StubState
    {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(
            &self,
        ) -> Arc<dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }
        fn get_arithmetic(
            &self,
        ) -> Arc<dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<i64>> {
            Arc::new(StubArithmetic)
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_internal_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            Vec::new()
        }
        fn get_concrete_buffer(
            &self,
            _address: &Address,
            _purpose: crate::pcode::exec::pcode_arithmetic::Purpose,
        ) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {}
    }

    impl crate::pcode::exec::pcode_executor_state::PcodeExecutorState<i64> for StubState {}
}
