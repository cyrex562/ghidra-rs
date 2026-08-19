//! A p-code executor state space for storing and retrieving bytes as arrays.
//!
//! Corresponds to `ghidra.pcode.exec.BytesPcodeExecutorStateSpace`.
//!
//! Java's `piece` field (the owning [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePiece),
//! kept only to hand to [`PcodeStateCallbacks`]) is not stored here: doing so would make this
//! struct mutually recursive with that piece, which holds a map of these spaces keyed by address
//! space -- exactly the dependency cycle this file was queued behind. Instead,
//! [`write`](Self::write) and [`read`](Self::read) take the piece as a parameter, supplied by
//! their sole callers ([`AbstractBytesPcodeExecutorStatePieceBase::set_in_space`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePieceBase::set_in_space)
//! and `get_from_space`), which already have it in scope.

use std::rc::Rc;
use std::sync::Arc;

use crate::generic::seam_stubs::SemisparseByteArray;
use crate::generic::ulong_span;
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{AddressRange, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::util::msg::Msg;

/// A p-code executor state space for storing and retrieving bytes as arrays.
///
/// Cheap to [`Clone`]: the clone shares the same backing bytes as the original, mirroring Java's
/// aliasing of a live object reference (e.g. from
/// [`AbstractBytesPcodeExecutorStatePieceBase::get_concrete_buffer`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePieceBase::get_concrete_buffer)).
/// [`fork`](Self::fork) instead makes an independent deep copy, matching Java's `fork()`.
#[derive(Clone)]
pub struct BytesPcodeExecutorStateSpace {
    language: Arc<dyn Language>,
    space: Arc<AddressSpace>,
    bytes: SemisparseByteArray,
}

impl BytesPcodeExecutorStateSpace {
    /// Construct an internal space for the given address space.
    ///
    /// Port of `BytesPcodeExecutorStateSpace(Language, AddressSpace, AbstractBytesPcodeExecutorStatePiece)`;
    /// see the module docs for why the piece is not accepted or stored here.
    pub fn new(language: Arc<dyn Language>, space: Arc<AddressSpace>) -> Self {
        Self::with_bytes(language, space, SemisparseByteArray::new())
    }

    fn with_bytes(language: Arc<dyn Language>, space: Arc<AddressSpace>, bytes: SemisparseByteArray) -> Self {
        Self { language, space, bytes }
    }

    /// The shared bytes handle backing this space, for callers that need to read live data
    /// without holding a full space handle.
    ///
    /// [`StateMemBuffer`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::StateMemBuffer)
    /// is one such caller: it must be `Send + Sync` (required by
    /// [`MemBuffer`](crate::program::model::mem::MemBuffer)), but this type's `language` field
    /// (`Arc<dyn Language>`) is not, so it cannot hold a whole `BytesPcodeExecutorStateSpace`.
    pub(crate) fn shared_bytes(&self) -> SemisparseByteArray {
        self.bytes.clone()
    }

    /// Port of `BytesPcodeExecutorStateSpace.fork(AbstractBytesPcodeExecutorStatePiece)`: an
    /// independent copy sharing this space's language and address space but with its own bytes.
    pub fn fork(&self) -> Self {
        Self::with_bytes(Arc::clone(&self.language), Arc::clone(&self.space), self.bytes.fork())
    }

    /// Write a value at the given offset.
    ///
    /// `piece` is passed to `cb`'s callbacks, standing in for Java's implicit `this.piece`; see
    /// the module docs.
    pub fn write<C: PcodeStateCallbacks>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
        offset: i64,
        val: &[u8],
        src_offset: i32,
        length: i32,
        cb: &C,
    ) {
        self.bytes.put_data(offset as u64, val, src_offset, length);
        cb.data_written(piece, &self.space.address(offset), length, &val.to_vec());
    }

    /// Extension point: Read from backing into this space, when acting as a cache.
    ///
    /// Port of `readUninitializedFromBacking(ULongSpanSet)`, deprecated and unused within this
    /// class itself (only an unported subclass overrides it).
    pub fn read_uninitialized_from_backing(&self, uninitialized: Vec<ulong_span::Impl>) -> Vec<ulong_span::Impl> {
        uninitialized
    }

    /// Read a value from cache (or raw space if not acting as a cache) at the given offset.
    ///
    /// Port of `readBytes(long, int, Reason)`.
    fn read_bytes(&self, offset: i64, size: i32, _reason: Reason) -> Vec<u8> {
        let mut data = vec![0u8; size as usize];
        self.bytes.get_data(offset as u64, &mut data);
        data
    }

    /// Port of `addrRng(ULongSpan)`.
    fn addr_rng(&self, span: &ulong_span::Impl) -> AddressRange {
        AddressRange::new(self.space.address(span.min as i64), self.space.address(span.max as i64))
    }

    /// Port of `spanRng(AddressRange)`.
    fn span_rng(&self, range: &AddressRange) -> ulong_span::Impl {
        ulong_span::span(range.min_address().offset() as u64, range.max_address().offset() as u64)
    }

    /// Port of `addInPlace(AddressSet, ULongSpanSet)`.
    fn add_in_place(&self, mut set: AddressSet, spans: &[ulong_span::Impl]) -> AddressSet {
        for span in spans {
            set.add_range_object(&self.addr_rng(span));
        }
        set
    }

    /// Port of `addrSet(ULongSpanSet)`.
    fn addr_set(&self, spans: &[ulong_span::Impl]) -> AddressSet {
        self.add_in_place(AddressSet::new(), spans)
    }

    /// Port of `spanSet(AddressSetView)`.
    ///
    /// This assumes without assertion that the set is contained in this space. Unused within this
    /// class itself (only an unported subclass calls it); a plain `Vec` stands in for Java's
    /// `ULongSpanSet`, since ranges taken from an `AddressSetView` are already disjoint.
    #[allow(dead_code)]
    fn span_set(&self, set: &dyn AddressSetView) -> Vec<ulong_span::Impl> {
        set.address_ranges().map(|range| self.span_rng(&range)).collect()
    }

    /// Port of `getRegs(AddressSetView)`.
    fn get_regs(&self, set: &AddressSet) -> Vec<RegisterRef> {
        let mut regs: Vec<RegisterRef> = Vec::new();
        for rng in set.address_ranges() {
            match self.language.get_register_at(rng.min_address(), rng.length() as i32) {
                Some(r) => push_unique_register(&mut regs, r),
                None => {
                    for r in self.language.get_registers_at(rng.min_address()) {
                        push_unique_register(&mut regs, r);
                    }
                }
            }
        }
        regs.sort_by(|a, b| a.borrow().cmp(&b.borrow()));
        regs
    }

    /// Port of `warnAddressSet(String, AddressSetView)`.
    fn warn_address_set(&self, message: &str, set: &AddressSet) {
        let regs = self.get_regs(set);
        if regs.is_empty() {
            Msg::warn("BytesPcodeExecutorStateSpace", &format!("{message}: {}", set.print_ranges()));
        } else {
            let names =
                regs.iter().map(|r| r.borrow().name().to_string()).collect::<Vec<_>>().join(", ");
            Msg::warn(
                "BytesPcodeExecutorStateSpace",
                &format!("{message}: {} (registers [{names}])", set.print_ranges()),
            );
        }
    }

    /// Port of `warnUninit(AddressSetView)`.
    fn warn_uninit(&self, uninitialized: &AddressSet) {
        self.warn_address_set("Emulator read from uninitialized state", uninitialized);
    }

    /// Compute the uninitialized span set, considering possible wrap-around.
    ///
    /// Port of `computeUninitialized(long, int)`.
    fn compute_uninitialized(&self, offset: i64, size: i32) -> AddressSet {
        if size == 0 {
            return AddressSet::new();
        }
        let max = offset.wrapping_add(size as i64).wrapping_sub(1);
        let space_max_offset = self.space.max_address().offset();
        if (max as u64) <= (space_max_offset as u64) && (offset as u64) <= (max as u64) {
            return self.addr_set(&self.bytes.get_uninitialized(offset as u64, max as u64));
        }
        let space_min_offset = self.space.min_address().offset();
        let end = space_min_offset.wrapping_add(max).wrapping_sub(space_max_offset).wrapping_sub(1);
        let mut result = AddressSet::new();
        result = self.add_in_place(result, &self.bytes.get_uninitialized(offset as u64, space_max_offset as u64));
        result = self.add_in_place(result, &self.bytes.get_uninitialized(space_min_offset as u64, end as u64));
        result
    }

    /// Read a value from the space at the given offset.
    ///
    /// If this space is not acting as a cache, this simply delegates to
    /// [`read_bytes`](Self::read_bytes). Otherwise, it will first ensure the cache covers the
    /// requested value.
    ///
    /// Port of `read(long, int, Reason, PcodeStateCallbacks)`; `piece` is passed to `cb`'s
    /// callbacks, standing in for Java's implicit `this.piece`, see the module docs.
    pub fn read<C: PcodeStateCallbacks>(
        &self,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> Vec<u8> {
        let uninitialized = self.compute_uninitialized(offset, size);
        if uninitialized.is_empty() {
            return self.read_bytes(offset, size, reason);
        }
        let uninitialized = cb.read_uninitialized(piece, &uninitialized, reason);
        if uninitialized.is_empty() {
            return self.read_bytes(offset, size, reason);
        }

        // The decoder will buffer ahead, so give it as much as we can, but no more than is
        // actually initialized. If it's a (non-decode) read, give it everything, but invoke the
        // warning.
        if reason == Reason::ExecuteDecode {
            let min = self.space.address(offset);
            let mut init = AddressSet::from_start_end(
                min.clone(),
                min.add(size as i64 - 1).expect("read range in bounds"),
            );
            init.delete_set(&uninitialized);
            if !init.is_empty() && init.min_address() == Some(min) {
                let first_len =
                    init.first_range().expect("non-empty set has a first range").length();
                return self.read_bytes(offset, first_len as i32, reason);
            }
        }

        if reason == Reason::ExecuteRead {
            self.warn_uninit(&uninitialized);
        } else if reason == Reason::ExecuteDecode {
            // The callers may be reading ahead, so it's not appropriate to throw an exception
            // here. Instead, communicate there's no more. If the buffer's empty on their end,
            // they'll handle the error as appropriate. If it's in the emulator, the instruction
            // decoder should eventually throw the decode exception.
            return Vec::new();
        }
        self.read_bytes(offset, size, reason)
    }

    /// Port of `getRegisterValues(List<Register>)`.
    pub fn get_register_values(&self, registers: &[RegisterRef]) -> Vec<(RegisterRef, Vec<u8>)> {
        let mut result = Vec::new();
        for reg in registers {
            let (min, num_bytes) = {
                let r = reg.borrow();
                (r.address().offset(), r.num_bytes())
            };
            let max = min + num_bytes as i64;
            if !self.bytes.is_initialized(min as u64, max as u64) {
                continue;
            }
            let mut data = vec![0u8; num_bytes as usize];
            self.bytes.get_data(min as u64, &mut data);
            result.push((Rc::clone(reg), data));
        }
        result
    }

    /// Port of `clear()`.
    pub fn clear(&self) {
        self.bytes.clear();
    }
}

/// Push `r` if no register already in `regs` compares equal, mirroring `Set<Register>.add`.
fn push_unique_register(regs: &mut Vec<RegisterRef>, r: RegisterRef) {
    if !regs.iter().any(|x| *x.borrow() == *r.borrow()) {
        regs.push(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::program::model::address::{Address, AddressFactory, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::OpCode;
    use std::collections::HashSet;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct I8Arithmetic;

    impl PcodeArithmetic<Vec<u8>> for I8Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            let mut out = in1.clone();
            out.resize(sizeout as usize, 0);
            out
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &Vec<u8>,
            _sizein2: i32,
            _in2: &Vec<u8>,
        ) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(
            &self,
            value: &Vec<u8>,
            _purpose: Purpose,
        ) -> Result<Vec<u8>, crate::pcode::exec::concretion_error::ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// A minimal piece, just enough to satisfy `PcodeExecutorStatePiece`'s signature; none of its
    /// members are exercised, since [`NoPcodeStateCallbacks`] ignores the piece it's handed.
    struct TestPiece;

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for TestPiece {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(I8Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(I8Arithmetic)
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece> {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _val: &Vec<u8>) {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_internal_abstract(&mut self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _val: &Vec<u8>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _quantize: bool, _reason: Reason) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_internal_abstract(&self, _space: &Arc<AddressSpace>, _offset: &Vec<u8>, _size: i32, _reason: Reason) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            unimplemented!("not exercised by these tests")
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>> {
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
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![ram_space()]))
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::InstructionPrototype>,
            crate::program::model::lang::ParseError,
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
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::CompilerSpec>, crate::program::model::lang::CompilerSpecNotFoundException>
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
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
            Some(16)
        }
    }

    fn space() -> BytesPcodeExecutorStateSpace {
        BytesPcodeExecutorStateSpace::new(Arc::new(MockLanguage), ram_space())
    }

    #[test]
    fn write_then_read_round_trips() {
        let s = space();
        let piece = TestPiece;
        s.write(&piece, 0x1000, &[1, 2, 3, 4], 0, 4, &NoPcodeStateCallbacks);

        let read = s.read(&piece, 0x1000, 4, Reason::ExecuteRead, &NoPcodeStateCallbacks);
        assert_eq!(read, vec![1, 2, 3, 4]);
    }

    #[test]
    fn read_of_uninitialized_offset_returns_zeroes() {
        let s = space();
        let piece = TestPiece;
        let read = s.read(&piece, 0x2000, 4, Reason::ExecuteRead, &NoPcodeStateCallbacks);
        assert_eq!(read, vec![0, 0, 0, 0]);
    }

    #[test]
    fn decode_read_past_initialized_data_returns_only_the_initialized_prefix() {
        let s = space();
        let piece = TestPiece;
        s.write(&piece, 0x3000, &[9, 9], 0, 2, &NoPcodeStateCallbacks);

        // Bytes [0x3000, 0x3001] are initialized, [0x3002, 0x3003] are not; a decode read across
        // the boundary should return just the initialized prefix, per Java's short-circuit.
        let read = s.read(&piece, 0x3000, 4, Reason::ExecuteDecode, &NoPcodeStateCallbacks);
        assert_eq!(read, vec![9, 9]);
    }

    #[test]
    fn decode_read_of_fully_uninitialized_range_returns_empty() {
        let s = space();
        let piece = TestPiece;
        let read = s.read(&piece, 0x4000, 4, Reason::ExecuteDecode, &NoPcodeStateCallbacks);
        assert!(read.is_empty());
    }

    #[test]
    fn get_register_values_only_reports_fully_initialized_registers() {
        let s = space();
        let piece = TestPiece;
        let addr = ram_space().address(0x10);
        let reg = crate::program::model::lang::register::Register::new("r0", "", addr, 2, false, 0);

        // Uninitialized: not reported.
        assert!(s.get_register_values(&[std::rc::Rc::clone(&reg)]).is_empty());

        // Java checks `isInitialized(min, min + numBytes)`, an inclusive range one byte past the
        // register itself, so writing exactly the register's own 2 bytes is not enough.
        s.write(&piece, 0x10, &[0xaa, 0xbb], 0, 2, &NoPcodeStateCallbacks);
        assert!(s.get_register_values(&[std::rc::Rc::clone(&reg)]).is_empty());

        s.write(&piece, 0x10, &[0xaa, 0xbb, 0xcc], 0, 3, &NoPcodeStateCallbacks);
        let values = s.get_register_values(&[std::rc::Rc::clone(&reg)]);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1, vec![0xaa, 0xbb]);
    }

    #[test]
    fn fork_is_independent_of_the_original() {
        let s = space();
        let piece = TestPiece;
        s.write(&piece, 0x5000, &[1], 0, 1, &NoPcodeStateCallbacks);

        let forked = s.fork();
        forked.write(&piece, 0x5001, &[2], 0, 1, &NoPcodeStateCallbacks);

        assert_eq!(s.read(&piece, 0x5001, 1, Reason::ExecuteRead, &NoPcodeStateCallbacks), vec![0]);
        assert_eq!(forked.read(&piece, 0x5000, 1, Reason::ExecuteRead, &NoPcodeStateCallbacks), vec![1]);
    }

    #[test]
    fn clear_resets_the_space() {
        let s = space();
        let piece = TestPiece;
        s.write(&piece, 0x6000, &[1, 2], 0, 2, &NoPcodeStateCallbacks);
        s.clear();
        assert_eq!(s.read(&piece, 0x6000, 2, Reason::ExecuteRead, &NoPcodeStateCallbacks), vec![0, 0]);
    }
}
