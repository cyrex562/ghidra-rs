use std::sync::Arc;

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::memstate::memory_bank::MemoryBankImpl;
use crate::pcode::memstate::memory_state::MemoryState;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::program::model::pcode::Varnode;
use crate::pcode::utils::{big_integer_to_bytes, bytes_to_big_integer, bytes_to_long, long_to_bytes};

/// An implementation of [`MemoryState`] which wraps a newer [`PcodeExecutorState`].
///
/// This is a transitional component used internally by `AdaptedEmulator`. It is also used in
/// `ModifiedPcodeThread`, which is part of the newer `PcodeEmulator` system, as a means of
/// incorporating `EmulateInstructionStateModifier`, which is part of the older `EmulatorHelper`
/// system. This class will be removed once both conditions are met:
///
/// 1. An equivalent state modification system is developed for the `PcodeEmulator` system, and
///    each `EmulateInstructionStateModifier` is ported to it.
/// 2. The `AdaptedEmulator` class is removed.
///
/// Corresponds to `ghidra.app.emulator.AdaptedMemoryState`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
///
/// Java's `AdaptedMemoryState` extends `AbstractMemoryState`, whose convenience `setValue`/
/// `getValue`/`getBigInteger` overloads are `final` methods built on the abstract `setChunk`/
/// `getChunk`/`language` field; Rust has no inheritance, so those forwarding methods (and the
/// cached `language`, matching the superclass constructor's `this.language = language`) are
/// implemented directly on this type instead of via a separate `AbstractMemoryState` seam.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct AdaptedMemoryState<T> {
    state: Box<dyn PcodeExecutorState<T>>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    language: Box<dyn Language>,
    reason: Reason,
}

#[allow(deprecated)]
impl<T> AdaptedMemoryState<T> {
    /// Wrap a [`PcodeExecutorState`] as a [`MemoryState`].
    ///
    /// Corresponds to `AdaptedMemoryState(PcodeExecutorState<T>, Reason)`.
    pub fn new(state: Box<dyn PcodeExecutorState<T>>, reason: Reason) -> Self {
        let arithmetic = state.get_arithmetic();
        let language = state.get_language();
        Self {
            state,
            arithmetic,
            language,
            reason,
        }
    }
}

#[allow(deprecated)]
impl<T> MemoryState for AdaptedMemoryState<T> {
    fn set_memory_bank(&mut self, _bank: Box<dyn MemoryBankImpl>) {
        unimplemented!("AdaptedMemoryState.setMemoryBank is not supported")
    }

    fn get_memory_bank(&self, _spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
        unimplemented!("AdaptedMemoryState.getMemoryBank is not supported")
    }

    fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError> {
        let addr = vn.get_address();
        self.set_value(addr.space(), addr.offset(), vn.get_size(), cval)
    }

    fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError> {
        let space = reg.address_space();
        self.set_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
    }

    fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError> {
        let reg = self
            .language
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.set_value_register(&reg, cval)
    }

    fn set_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i64,
    ) -> Result<(), LowlevelError> {
        let bytes = long_to_bytes(cval, size as usize, self.language.is_big_endian());
        self.set_chunk(&bytes, spc, off, size)
    }

    fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError> {
        let addr = vn.get_address();
        self.get_value(addr.space(), addr.offset(), vn.get_size())
    }

    fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError> {
        let space = reg.address_space();
        let offset = reg.address().offset();
        let size = reg.minimum_byte_size();
        self.get_value(&space, offset, size)
    }

    fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError> {
        let reg = self
            .language
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.get_value_register(&reg)
    }

    fn get_value(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32) -> Result<i64, LowlevelError> {
        if spc.space_type() == AddressSpaceType::Constant {
            return Ok(off);
        }
        let mut bytes = vec![0u8; size as usize];
        self.get_chunk(&mut bytes, spc, off, size, false)?;
        Ok(bytes_to_long(&bytes, size as usize, self.language.is_big_endian()))
    }

    fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError> {
        let addr = vn.get_address();
        self.set_big_value(addr.space(), addr.offset(), vn.get_size(), cval)
    }

    fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError> {
        let space = reg.address_space();
        self.set_big_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
    }

    fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError> {
        let reg = self
            .language
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.set_big_value_register(&reg, cval)
    }

    fn set_big_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i128,
    ) -> Result<(), LowlevelError> {
        let bytes = big_integer_to_bytes(cval, size as usize, self.language.is_big_endian());
        self.set_chunk(&bytes, spc, off, size)
    }

    fn get_big_integer_varnode(&mut self, vn: &Varnode, signed: bool) -> Result<i128, LowlevelError> {
        let addr = vn.get_address();
        self.get_big_integer(addr.space(), addr.offset(), vn.get_size(), signed)
    }

    fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError> {
        let space = reg.address_space();
        let offset = reg.address().offset();
        let size = reg.minimum_byte_size();
        self.get_big_integer(&space, offset, size, false)
    }

    fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError> {
        let reg = self
            .language
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.get_big_integer_register(&reg)
    }

    fn get_big_integer(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        signed: bool,
    ) -> Result<i128, LowlevelError> {
        if spc.space_type() == AddressSpaceType::Constant {
            if !signed && off < 0 {
                let bytes = long_to_bytes(off, 8, true);
                return Ok(bytes_to_big_integer(&bytes, 8, true, false));
            }
            return Ok(off as i128);
        }
        let mut bytes = vec![0u8; size as usize];
        self.get_chunk(&mut bytes, spc, off, size, false)?;
        Ok(bytes_to_big_integer(&bytes, size as usize, self.language.is_big_endian(), signed))
    }

    /// Corresponds to `AdaptedMemoryState.getChunk(byte[], AddressSpace, long, int, boolean)`.
    ///
    /// Reads the variable via the wrapped [`PcodeExecutorState`] and concretizes it. Unlike the
    /// paged `MemoryBank` implementations, this never partially reads: `stop_on_uninitialized` is
    /// unused, matching the Java override, which ignores it too.
    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        _stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError> {
        let t = self.state.get_var(spc, off, size, true, self.reason);
        let val = self
            .arithmetic
            .to_concrete(&t, Purpose::Other)
            .map_err(|e| LowlevelError::with_message(e.message().to_string()))?;
        res[..val.len()].copy_from_slice(&val);
        Ok(val.len() as i32)
    }

    /// Corresponds to `AdaptedMemoryState.setChunk(byte[], AddressSpace, long, int)`.
    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        let t = self.arithmetic.from_const_bytes(val);
        self.state.set_var(spc, off, size, true, &t);
        Ok(())
    }

    /// Corresponds to `AdaptedMemoryState.setInitialized(boolean, AddressSpace, long, int)`. Does
    /// nothing, matching the Java override's empty body.
    fn set_initialized(
        &mut self,
        _initialized: bool,
        _spc: &Arc<AddressSpace>,
        _off: i64,
        _size: i32,
    ) -> Result<(), LowlevelError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece,
    };
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSetView, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::OpCode;
    use crate::util::task::TaskMonitor;
    use std::collections::{HashMap, HashSet};

    /// A minimal [`Language`] double: only [`is_big_endian`](Language::is_big_endian) and
    /// [`get_register_by_name`](Language::get_register_by_name) are exercised by
    /// `AdaptedMemoryState`'s convenience methods (mirroring `AbstractMemoryState`'s cached
    /// `language` field); every other member is unreachable from these tests.
    struct TestLanguage {
        is_big_endian: bool,
        registers: HashMap<String, RegisterRef>,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            self.is_big_endian
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &crate::program::model::address::Address) -> Vec<RegisterRef> {
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
            self.registers.values().cloned().collect()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.keys().cloned().collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
        }
        fn get_register_at(&self, _addr: &crate::program::model::address::Address, _size: i32) -> Option<RegisterRef> {
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
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
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// Little-endian `i64` arithmetic: `T = i64` throughout, matching the byte-array-backed
    /// `MapState` below.
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
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

        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A minimal `PcodeExecutorState<i64>` backed by a map from `(space id, offset)` to an
    /// 8-byte-truncated `i64`, standing in for the newer state system `AdaptedMemoryState` wraps.
    #[derive(Default)]
    struct MapState {
        cells: HashMap<(i32, i64), i64>,
        registers: HashMap<String, RegisterRef>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(TestLanguage {
                is_big_endian: false,
                registers: self.registers.clone(),
            })
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }

        fn set_var_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            val: &i64,
        ) {
            self.cells.insert((space.space_id(), *offset), *val);
        }

        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            val: &i64,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }

        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            *self.cells.get(&(space.space_id(), *offset)).unwrap_or(&0)
        }

        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            reason: Reason,
        ) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }

        fn get_concrete_buffer(
            &self,
            _address: &crate::program::model::address::Address,
            _purpose: Purpose,
        ) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }

        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 1)
    }

    fn wrapped() -> AdaptedMemoryState<i64> {
        AdaptedMemoryState::new(Box::new(MapState::default()), Reason::Inspect)
    }

    fn wrapped_with_pc_register() -> AdaptedMemoryState<i64> {
        let space = ram_space();
        let pc = Register::new("pc", "program counter", crate::program::model::address::Address::new(space, 0x30), 8, false, 0);
        let mut registers = HashMap::new();
        registers.insert("pc".to_string(), pc);
        let state = MapState {
            cells: HashMap::new(),
            registers,
        };
        AdaptedMemoryState::new(Box::new(state), Reason::Inspect)
    }

    #[test]
    fn set_value_by_name_then_get_value_by_name_round_trips() {
        // Java: AbstractMemoryState.setValue(String,long)/getValue(String) resolve the register via
        // `language.getRegister(nm)`.
        let mut mem = wrapped_with_pc_register();
        mem.set_value_by_name("pc", 0xdeadbeefu32 as i64).unwrap();
        assert_eq!(mem.get_value_by_name("pc").unwrap(), 0xdeadbeefu32 as i64);
    }

    #[test]
    fn set_value_by_name_unknown_register_is_error() {
        let mut mem = wrapped();
        assert!(mem.set_value_by_name("bogus", 1).is_err());
    }

    #[test]
    fn set_value_then_get_value_round_trips_through_the_wrapped_state() {
        let mut mem = wrapped();
        let space = ram_space();
        mem.set_value(&space, 0x10, 8, 0x01020304).unwrap();
        assert_eq!(mem.get_value(&space, 0x10, 8).unwrap(), 0x01020304);
    }

    #[test]
    fn get_chunk_concretizes_via_the_arithmetic_to_concrete() {
        // Java: getChunk calls state.getVar then arithmetic.toConcrete(t, Purpose.OTHER), copying
        // the concretized bytes into res -- exercised here directly against an 8-byte I64Arithmetic
        // result, matching a full-width read.
        let mut mem = wrapped();
        let space = ram_space();
        mem.set_value(&space, 0, 8, 0x1122334455667788).unwrap();

        let mut res = [0u8; 8];
        let n = mem.get_chunk(&mut res, &space, 0, 8, false).unwrap();
        assert_eq!(n, 8);
        assert_eq!(i64::from_le_bytes(res), 0x1122334455667788);
    }

    #[test]
    fn get_value_on_constant_space_returns_the_offset_without_reading_state() {
        // Java: AbstractMemoryState.getValue short-circuits for the constant space, returning the
        // offset itself rather than consulting getChunk.
        let mut mem = wrapped();
        assert_eq!(mem.get_value(&const_space(), 0x2a, 4).unwrap(), 0x2a);
    }

    #[test]
    fn get_big_integer_on_constant_space_returns_the_offset() {
        let mut mem = wrapped();
        assert_eq!(mem.get_big_integer(&const_space(), 0x2a, 4, false).unwrap(), 0x2a);
    }

    #[test]
    fn set_value_register_then_get_value_register_round_trips() {
        let mut mem = wrapped();
        let space = ram_space();
        let reg = Register::new(
            "r0",
            "general reg 0",
            crate::program::model::address::Address::new(space, 0x20),
            8,
            false,
            0,
        );
        mem.set_value_register(&reg.borrow(), 0x11223344).unwrap();
        assert_eq!(mem.get_value_register(&reg.borrow()).unwrap(), 0x11223344);
    }

    #[test]
    fn set_value_varnode_then_get_value_varnode_round_trips() {
        let mut mem = wrapped();
        let space = ram_space();
        let vn = Varnode::new(crate::program::model::address::Address::new(space, 0x40), 8);
        mem.set_value_varnode(&vn, 0x1234).unwrap();
        assert_eq!(mem.get_value_varnode(&vn).unwrap(), 0x1234);
    }

    #[test]
    fn set_big_value_then_get_big_integer_round_trips() {
        let mut mem = wrapped();
        let space = ram_space();
        mem.set_big_value(&space, 0x50, 8, 0x1122334455667788).unwrap();
        assert_eq!(mem.get_big_integer(&space, 0x50, 8, false).unwrap(), 0x1122334455667788);
    }

    #[test]
    fn set_initialized_does_nothing() {
        // Java: AdaptedMemoryState.setInitialized has an empty body ("Do nothing").
        let mut mem = wrapped();
        let space = ram_space();
        mem.set_value(&space, 0, 8, 0x01020304).unwrap();
        mem.set_initialized(false, &space, 0, 8).unwrap();

        let mut res = [0u8; 8];
        let n = mem.get_chunk(&mut res, &space, 0, 8, true).unwrap();
        assert_eq!(n, 8);
    }

    #[test]
    fn set_memory_bank_is_unsupported() {
        // Java: AdaptedMemoryState.setMemoryBank throws UnsupportedOperationException.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            struct DummyBank;
            impl MemoryBankImpl for DummyBank {
                fn state(&self) -> &crate::pcode::memstate::memory_bank::MemoryBankState {
                    unimplemented!()
                }
                fn get_page(&mut self, _addr: i64) -> &mut crate::pcode::memstate::memory_page::MemoryPage {
                    unimplemented!()
                }
                fn set_page(&mut self, _addr: i64, _val: &[u8], _skip: i32, _size: i32, _buf_offset: i32) {}
                fn set_page_initialized(
                    &mut self,
                    _addr: i64,
                    _initialized: bool,
                    _skip: i32,
                    _size: i32,
                    _buf_offset: i32,
                ) {
                }
            }
            let mut mem = wrapped();
            mem.set_memory_bank(Box::new(DummyBank));
        }));
        assert!(result.is_err());
    }
}
