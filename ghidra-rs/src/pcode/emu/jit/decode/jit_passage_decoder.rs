//! Port of `ghidra.pcode.emu.jit.decode.JitPassageDecoder`.
//!
//! The decoder of a [`JitPassage`] to support JIT-accelerated p-code emulation.
//!
//! When the emulator encounters an address (and contextreg value) that it has not previously
//! translated, it must decode a passage seeded at that required entry point. It must then
//! translate the passage, collect all the resulting entry points, and finally invoke the
//! passage's compiled `run` method for the required entry point.
//!
//! # Decoding a Passage
//!
//! Decode starts with a single seed, which is the entry point required by the emulator. Decode
//! occurs one stride at a time, disassembling linearly until an instruction has no fall-through,
//! an existing entry point is encountered, or a user injection fails to specify control flow. As
//! the stride decoder processes each instruction, it interprets its p-code to collect branch
//! targets, which seed further strides. This algorithm is implemented by the (not yet ported)
//! `DecoderForOnePassage`; this class keeps the configuration and other trappings, and
//! instantiates an actual decoder upon requesting a seed.

use std::sync::{Arc, Mutex};

use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::jit::decode::decoder_userop_library::DecoderUseropLibrary;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread;
use crate::pcode::seam_stubs::{
    AddrCtx, DecodePcodeExecutionException, DecoderForOnePassage, JitPassage, PseudoInstruction,
    RegisterValue,
};
use crate::program::model::address::Address;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::program_context::ProgramContext;

/// The decoder of a passage to support JIT-accelerated p-code emulation.
///
/// Port of `ghidra.pcode.emu.jit.decode.JitPassageDecoder`.
pub struct JitPassageDecoder {
    thread: JitPcodeThread,
    decoder: Arc<Mutex<dyn InstructionDecoder>>,
    #[allow(dead_code)]
    default_context: Option<Arc<dyn ProgramContext>>,
    contextreg: RegisterRef,
    #[allow(dead_code)]
    library: DecoderUseropLibrary,
}

impl JitPassageDecoder {
    /// Construct a passage decoder.
    ///
    /// # Arguments
    /// * `thread` - the thread whose instruction decoder, context, and userop library to use.
    ///
    /// Port of `new JitPassageDecoder(JitPcodeThread)`.
    pub fn new(thread: JitPcodeThread) -> Self {
        let decoder = thread.get_decoder();
        let default_context = thread.get_default_context();
        let contextreg = match &default_context {
            Some(ctx) => ctx.get_base_context_register(),
            None => Register::no_context(),
        };
        let library = DecoderUseropLibrary::new(thread.get_userop_library());
        Self { thread, decoder, default_context, contextreg, library }
    }

    /// Decode a passage starting at the given seed.
    ///
    /// # Arguments
    /// * `seed` - the seed address
    /// * `ctx_in` - the seed contextreg value
    /// * `max_ops` - the maximum-ish number of p-code ops to emit
    ///
    /// See [`decode_passage`](Self::decode_passage).
    ///
    /// Java overloads `decodePassage`; Rust has no overloading, so the `Address`-seeded form gets
    /// a distinct name.
    pub fn decode_passage_at(
        &self,
        seed: &Address,
        ctx_in: Option<Arc<dyn RegisterValue>>,
        max_ops: i32,
    ) -> JitPassage {
        self.decode_passage(AddrCtx::new(ctx_in, seed.clone()), max_ops)
    }

    /// Decode a passage starting at the given seed.
    ///
    /// We provide a `max_ops` parameter so that the configured `maxPassageOps` option can be
    /// overridden. In particular, the bytecode emitter may exceed the maximum size of a Java
    /// method, in which case we must abort, re-decode with fewer ops, and retry.
    ///
    /// # Arguments
    /// * `seed` - the required entry point, where decode will start
    /// * `max_ops` - the maximum-ish number of p-codes to emit
    ///
    /// Port of `decodePassage(AddrCtx, int)`.
    pub fn decode_passage(&self, seed: AddrCtx, max_ops: i32) -> JitPassage {
        let mut for_one = DecoderForOnePassage::new(self, seed, max_ops);
        for_one.decode_passage();
        for_one.finish()
    }

    /// Decode a single instruction.
    ///
    /// # Arguments
    /// * `address` - the address of the instruction
    /// * `ctx` - the input decode context
    ///
    /// # Returns
    /// the decoded instruction, or a `DecodeErrorInstruction` on the specific
    /// [`DecodePcodeExecutionException`] the decoder is expected to raise; any other error
    /// propagates.
    ///
    /// Port of `decodeInstruction(Address, RegisterValue)`.
    #[allow(dead_code)]
    pub(crate) fn decode_instruction(
        &self,
        address: &Address,
        ctx: Option<&dyn RegisterValue>,
    ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
        let mut decoder = self.decoder.lock().expect("decoder mutex poisoned");
        match decoder.decode_instruction(address, ctx) {
            Ok(instruction) => Ok(instruction),
            Err(err) => match err.downcast::<DecodePcodeExecutionException>() {
                Ok(dpe) => {
                    let language = decoder.get_language();
                    Ok(Box::new(JitPassage::decode_error(
                        language,
                        address.clone(),
                        ctx,
                        dpe.message(),
                    )))
                }
                Err(other) => Err(other),
            },
        }
    }

    /// Port of `decoder.thread.hasEntry(AddrCtx)`, as accessed directly by `DecoderForOneStride`
    /// (a package-private field access in Java).
    pub(crate) fn thread_has_entry(&self, at: &AddrCtx) -> bool {
        self.thread.has_entry(at)
    }

    /// Port of `decoder.thread.getInject(Address)`, as accessed directly by `DecoderForOneStride`
    /// (a package-private field access in Java).
    pub(crate) fn thread_get_inject(&self, address: &Address) -> Option<PcodeProgram> {
        self.thread.get_inject(address)
    }

    /// Port of `decoder.thread.getLanguage()`, as accessed directly by `DecoderExecutor` (a
    /// package-private field access in Java). Read off the thread's [`InstructionDecoder`], which
    /// is where the thread itself gets it.
    pub(crate) fn thread_get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
        self.decoder.lock().expect("decoder mutex poisoned").get_language()
    }

    /// Port of `decoder.contextreg`, as accessed directly by `DecoderExecutor` (a package-private
    /// field access in Java).
    pub(crate) fn contextreg(&self) -> &RegisterRef {
        &self.contextreg
    }

    /// Port of `decoder.defaultContext`, as accessed directly by `DecoderExecutor` (a
    /// package-private field access in Java).
    pub(crate) fn default_context(&self) -> Option<&Arc<dyn ProgramContext>> {
        self.default_context.as_ref()
    }

    /// Port of `decoder.library`, as accessed directly by `DecoderExecutor` (a package-private
    /// field access in Java, reached via `DecoderForOnePassage.library()`, which returns exactly
    /// this object).
    pub(crate) fn library(&self) -> &DecoderUseropLibrary {
        &self.library
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::address::{AddressRange, AddressRangeIterator, AddressSetView};

    struct MockPseudoInstruction;
    impl PseudoInstruction for MockPseudoInstruction {}

    struct MockUseropLibrary {
        userops: UseropMap<Vec<u8>>,
    }
    impl ErasedPcodeUseropLibrary for MockUseropLibrary {}
    impl PcodeUseropLibrary<Vec<u8>> for MockUseropLibrary {
        fn get_userops(&self) -> &UseropMap<Vec<u8>> {
            &self.userops
        }
    }
    fn mock_userop_library() -> Arc<dyn PcodeUseropLibrary<Vec<u8>>> {
        Arc::new(MockUseropLibrary { userops: UseropMap::new() })
    }

    /// A decoder whose next result is programmed by the test, mirroring
    /// [`crate::pcode::emu::instruction_decoder`]'s own test mocks.
    struct ScriptedDecoder {
        next: Option<Result<Box<dyn PseudoInstruction>, String>>,
    }
    impl InstructionDecoder for ScriptedDecoder {
        fn get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            mock_language()
        }

        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            match self.next.take().expect("decode_instruction called more than once") {
                Ok(instr) => Ok(instr),
                Err(message) => Err(Box::new(DecodePcodeExecutionException::new(message))),
            }
        }

        fn branched(&mut self, _address: &Address) {}

        fn get_last_instruction(&self) -> Option<Arc<dyn crate::program::model::listing::Instruction>> {
            None
        }

        fn get_last_length_with_delays(&self) -> i32 {
            0
        }
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_register(name: &str) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(name, name, Address::new(space, 0), 4, false, 0)
    }

    fn thread_with(
        result: Result<Box<dyn PseudoInstruction>, String>,
        default_context: Option<Arc<dyn ProgramContext>>,
    ) -> JitPcodeThread {
        let decoder: Arc<Mutex<dyn InstructionDecoder>> =
            Arc::new(Mutex::new(ScriptedDecoder { next: Some(result) }));
        JitPcodeThread::new(decoder, default_context, mock_userop_library())
    }

    struct MockProgramContext {
        base_context_register: RegisterRef,
    }
    impl ProgramContext for MockProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            false
        }
        fn get_flow_value(
            &self,
            value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            value
        }
        fn get_non_flow_value(
            &self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_value(
            &self,
            _register: &Register,
            _address: &Address,
            _signed: bool,
        ) -> Option<i128> {
            None
        }
        fn get_register_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_non_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn set_value(
            &mut self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
            _value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_value_range_containing(
            &self,
            _register: &Register,
            addr: &Address,
        ) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }
        fn get_default_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn AddressRangeIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn remove(
            &mut self,
            _start: &Address,
            _end: &Address,
            _register: &Register,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn has_value_over_range(
            &self,
            _reg: &Register,
            _value: i128,
            _addr_set: &dyn AddressSetView,
        ) -> bool {
            false
        }
        fn get_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn get_base_context_register(&self) -> RegisterRef {
            self.base_context_register.clone()
        }
        fn get_default_disassembly_context(&self) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_default_disassembly_context(
            &mut self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) {
        }
        fn get_disassembly_context(
            &self,
            _address: &Address,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[test]
    fn constructor_defaults_contextreg_to_no_context_without_default_context() {
        let thread = thread_with(Ok(Box::new(MockPseudoInstruction)), None);
        let decoder = JitPassageDecoder::new(thread);

        // Java: `defaultContext == null ? Register.NO_CONTEXT : ...`
        assert_eq!(decoder.contextreg.borrow().name(), "NO_CONTEXT");
    }

    #[test]
    fn constructor_takes_contextreg_from_default_context() {
        let base_context_register = mock_register("contextreg");
        let ctx: Arc<dyn ProgramContext> =
            Arc::new(MockProgramContext { base_context_register: base_context_register.clone() });
        let thread = thread_with(Ok(Box::new(MockPseudoInstruction)), Some(ctx));
        let decoder = JitPassageDecoder::new(thread);

        // Java: `defaultContext.getBaseContextRegister()`
        assert_eq!(decoder.contextreg.borrow().name(), "contextreg");
    }

    #[test]
    fn decode_instruction_passes_through_successful_decode() {
        let thread = thread_with(Ok(Box::new(MockPseudoInstruction)), None);
        let decoder = JitPassageDecoder::new(thread);

        let result = decoder.decode_instruction(&mock_address(0x100), None);
        assert!(result.is_ok());
    }

    #[test]
    fn decode_instruction_converts_decode_pcode_execution_exception_to_decode_error() {
        let thread = thread_with(Err("bad opcode".to_string()), None);
        let decoder = JitPassageDecoder::new(thread);

        // Java: `catch (DecodePcodeExecutionException e) { return
        // JitPassage.decodeError(decoder.getLanguage(), address, ctx, e.getMessage()); }`
        let result = decoder.decode_instruction(&mock_address(0x200), None);
        assert!(result.is_ok());
    }

    #[test]
    fn decode_error_carries_the_exception_message() {
        // Java: `JitPassage.decodeError(language, address, ctx, message)` stores `message`
        // verbatim, later returned by `DecodeErrorInstruction.getMessage()`.
        let instr = JitPassage::decode_error(
            mock_language(),
            mock_address(0x300),
            None,
            "unimplemented opcode",
        );
        assert_eq!(instr.message(), "unimplemented opcode");
    }

    #[test]
    fn addr_ctx_derives_bi_ctx_from_context_value() {
        // Java: `this.biCtx = ctx == null ? BigInteger.ZERO : ctx.getUnsignedValue();`
        let none_ctx = AddrCtx::new(None, mock_address(0x400));
        assert_eq!(none_ctx.bi_ctx, 0);
        assert!(none_ctx.rv_ctx.is_none());

        struct FixedValue(i128);
        impl RegisterValue for FixedValue {
            fn get_unsigned_value(&self) -> i128 {
                self.0
            }
        }
        let some_ctx: Arc<dyn RegisterValue> = Arc::new(FixedValue(42));
        let addr_ctx = AddrCtx::new(Some(some_ctx), mock_address(0x400));
        assert_eq!(addr_ctx.bi_ctx, 42);
        assert!(addr_ctx.rv_ctx.is_some());
    }

    /// A language whose methods are never actually invoked: `DecodeErrorInstruction::new` (what
    /// `JitPassage::decode_error` builds) receives and discards its `language` argument entirely,
    /// as does the real Java constructor's stub here, so every method below is unreachable in
    /// this smoke test.
    fn mock_language() -> Arc<dyn crate::program::model::lang::language::Language> {
        use crate::program::model::address::{AddressFactory, AddressSetView as LangAddressSetView};
        use crate::program::model::lang::compiler_spec::CompilerSpec;
        use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
        use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
        use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
        use crate::program::model::lang::instruction_prototype::InstructionPrototype;
        use crate::program::model::lang::language::{Language, ParseError};
        use crate::program::model::lang::language_description::LanguageDescription;
        use crate::program::model::lang::language_id::LanguageID;
        use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
        use crate::program::model::lang::processor_context::ProcessorContext;
        use crate::program::model::listing::default_program_context::DefaultProgramContext;
        use crate::program::model::mem::MemBuffer;
        use crate::program::seam_stubs::{AddressLabelInfo, Processor};
        use crate::app::plugin::processors::generic::MemoryBlockDefinition;
        use crate::util::task::TaskMonitor;
        use std::collections::HashSet as LangHashSet;

        struct MockLanguage;
        impl Language for MockLanguage {
            fn get_language_id(&self) -> LanguageID {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_language_description(&self) -> Box<dyn LanguageDescription> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_parallel_instruction_helper(
                &self,
            ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_processor(&self) -> Box<dyn Processor> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_version(&self) -> i32 {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_minor_version(&self) -> i32 {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_address_factory(&self) -> Box<dyn AddressFactory> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_space(&self) -> Arc<AddressSpace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_data_space(&self) -> Arc<AddressSpace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn is_big_endian(&self) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_instruction_alignment(&self) -> i32 {
                unimplemented!("not exercised by this smoke test")
            }
            fn supports_pcode(&self) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn is_volatile(&self, _addr: &Address) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn parse(
                &self,
                _buf: &dyn MemBuffer,
                _context: &mut dyn ProcessorContext,
                _in_delay_slot: bool,
            ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_number_of_user_defined_op_names(&self) -> i32 {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_register_in_space(
                &self,
                _addrspc: &Arc<AddressSpace>,
                _offset: i64,
                _size: i32,
            ) -> Option<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_register_names(&self) -> Vec<String> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_program_counter(&self) -> Option<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_context_base_register(&self) -> Option<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_context_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_segmented_space(&self) -> String {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_volatile_addresses(&self) -> Box<dyn LangAddressSetView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {
                unimplemented!("not exercised by this smoke test")
            }
            fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_compatible_compiler_spec_descriptions(
                &self,
            ) -> Vec<Box<dyn CompilerSpecDescription>> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_compiler_spec_by_id(
                &self,
                _compiler_spec_id: &CompilerSpecID,
            ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
                unimplemented!("not exercised by this smoke test")
            }
            fn has_property(&self, _key: &str) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_property(&self, _key: &str) -> Option<String> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_property_keys(&self) -> LangHashSet<String> {
                unimplemented!("not exercised by this smoke test")
            }
            fn has_manual(&self) -> bool {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_manual_entry(
                &self,
                _instruction_mnemonic: &str,
            ) -> Option<crate::util::manual_entry::ManualEntry> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_manual_instruction_mnemonic_keys(&self) -> LangHashSet<String> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_register_addresses(&self) -> Box<dyn LangAddressSetView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_maximum_instruction_length(&self) -> Option<i32> {
                unimplemented!("not exercised by this smoke test")
            }
        }
        Arc::new(MockLanguage)
    }
}
