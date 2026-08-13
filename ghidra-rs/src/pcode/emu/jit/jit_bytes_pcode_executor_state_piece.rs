//! The state piece backing the JIT-compiled emulator's byte storage.
//!
//! Corresponds to `ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece` (and its inner class
//! `JitBytesPcodeExecutorStateSpace`).
//!
//! Java's class extends `AbstractBytesPcodeExecutorStatePiece<JitBytesPcodeExecutorStateSpace>`,
//! i.e., it reuses that class's behavior but narrows the internal space type to its own
//! `JitBytesPcodeExecutorStateSpace`, which adds direct byte-array pre-fetching for translated
//! (JIT-generated) code. The ported
//! [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePiece)
//! trait deliberately fixes its internal space type to the plain
//! [`BytesPcodeExecutorStateSpace`], since no subclass of it had been ported yet (see that
//! module's docs); this is the first one, so that trait cannot be reused here. Instead, this piece
//! implements [`AbstractLongOffsetPcodeExecutorStatePiece`] directly (which *is* generic in the
//! internal space type) and reimplements the small amount of `AbstractBytesPcodeExecutorStatePiece`
//! behavior (a lazily-populated `spaceMap`, `getConcreteBuffer`) inline, against its own
//! [`JitBytesPcodeExecutorStateSpace`].
//!
//! As in [`BytesPcodeExecutorStateSpace`], the internal space does not hold a reference back to
//! the owning piece (which would make the two mutually recursive); [`read`](JitBytesPcodeExecutorStateSpace::read)
//! and [`write`](JitBytesPcodeExecutorStateSpace::write) take the piece as a parameter instead,
//! mirroring Java's implicit `this$0` reference through an explicit one.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::{
    new_long_offset_base_for_language, StateMemBuffer,
};
use crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::{
    AbstractLongOffsetPcodeExecutorStatePiece, AbstractLongOffsetPcodeExecutorStatePieceBase,
};
use crate::pcode::exec::bytes_pcode_executor_state_space::BytesPcodeExecutorStateSpace;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::MemBuffer;

/// The size, in bytes, of the block `getDirect` hands back, matching Java's
/// `SemisparseByteArray.BLOCK_SIZE`.
const BLOCK_SIZE: u64 = 0x1000;

/// An object to manage state for a specific [`AddressSpace`], adding direct byte-array
/// pre-fetching for translated passages on top of a plain [`BytesPcodeExecutorStateSpace`].
///
/// Port of the inner class `JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace`.
pub struct JitBytesPcodeExecutorStateSpace<CB>
where
    CB: PcodeStateCallbacks,
{
    inner: BytesPcodeExecutorStateSpace,
    cb: Arc<CB>,
}

impl<CB> Clone for JitBytesPcodeExecutorStateSpace<CB>
where
    CB: PcodeStateCallbacks,
{
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), cb: Arc::clone(&self.cb) }
    }
}

impl<CB> JitBytesPcodeExecutorStateSpace<CB>
where
    CB: PcodeStateCallbacks,
{
    /// Construct a state space.
    ///
    /// Port of `JitBytesPcodeExecutorStateSpace(Language, AddressSpace,
    /// AbstractBytesPcodeExecutorStatePiece<?>)`. `piece` is not retained; see the module docs.
    pub fn new(language: Arc<dyn Language>, space: Arc<AddressSpace>, cb: Arc<CB>) -> Self {
        Self { inner: BytesPcodeExecutorStateSpace::new(language, space), cb }
    }

    /// Pre-fetch the byte array for the block (page) containing the given offset.
    ///
    /// Port of `getDirect(long)`. Java hands back the live backing array of a fixed-size block
    /// (`SemisparseByteArray.BLOCK_SIZE`, `0x1000` bytes), so writes to it are immediately visible
    /// through this space and vice versa. The ported [`BytesPcodeExecutorStateSpace`] backs its
    /// bytes with a sparse per-offset map rather than fixed blocks (see its docs), so there is no
    /// single live array to hand out; this instead returns an owned snapshot of the block's
    /// current contents, zero-filled where uninitialized. No JIT-generated code exists yet to
    /// observe the difference (mutating the returned block does not write back), matching the
    /// divergence already documented for
    /// [`StateMemBuffer`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::StateMemBuffer).
    pub fn get_direct(&self, offset: i64) -> Vec<u8> {
        let block_start = (offset as u64 / BLOCK_SIZE) * BLOCK_SIZE;
        let mut block = vec![0u8; BLOCK_SIZE as usize];
        self.inner.shared_bytes().get_data(block_start, &mut block);
        block
    }

    /// Read a variable from this (pre-fetched) state space, using [`Reason::ExecuteRead`] and
    /// this space's own callbacks.
    ///
    /// Port of `read(long, int)`. `piece` stands in for Java's implicit `this$0`; see the module
    /// docs.
    pub fn read(&self, piece: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>, offset: i64, size: i32) -> Vec<u8> {
        self.inner.read(piece, offset, size, Reason::ExecuteRead, self.cb.as_ref())
    }

    /// Write a variable to this (pre-fetched) state space, using this space's own callbacks.
    ///
    /// Port of `write(long, byte[], int, int)`. `piece` stands in for Java's implicit `this$0`;
    /// see the module docs.
    pub fn write(
        &self,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
        offset: i64,
        val: &[u8],
        src_offset: i32,
        length: i32,
    ) {
        self.inner.write(piece, offset, val, src_offset, length, self.cb.as_ref())
    }
}

/// The state piece for the JIT-compiled emulator.
///
/// Port of `JitBytesPcodeExecutorStatePiece`. Provides access to the internals so that translated
/// passages can pre-fetch certain objects to optimize state accesses.
pub struct JitBytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    long_base: AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>,
    space_map: HashMap<Arc<AddressSpace>, JitBytesPcodeExecutorStateSpace<CB>>,
}

impl<CB> JitBytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    /// Construct a state piece.
    ///
    /// Port of `JitBytesPcodeExecutorStatePiece(Language, PcodeStateCallbacks)`.
    ///
    /// * `language` -- the emulation target language
    /// * `cb` -- callbacks to receive emulation events. Note that many accesses by the JIT are
    ///   direct and so will not generate a callback. DO NOT rely on state callbacks yet.
    pub fn new(language: Arc<dyn Language>, cb: Arc<CB>) -> Self {
        Self { long_base: new_long_offset_base_for_language(language, cb), space_map: HashMap::new() }
    }

    /// Construct a new internal space for the given address space.
    ///
    /// Port of `newSpace(AddressSpace)`.
    fn new_space(&self, space: &Arc<AddressSpace>) -> JitBytesPcodeExecutorStateSpace<CB> {
        JitBytesPcodeExecutorStateSpace::new(
            Arc::clone(self.long_base.language()),
            Arc::clone(space),
            Arc::clone(self.long_base.cb()),
        )
    }
}

impl<CB> ErasedPcodeExecutorStatePiece for JitBytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}

// `AbstractLongOffsetPcodeExecutorStatePieceBase` holds an `Arc<dyn Language>`, and `Language` is
// not declared `Send + Sync`, so this struct does not derive those auto traits on its own. Mirrors
// `BytesPcodeExecutorStatePiece`'s own unsafe impls for the same reason.
unsafe impl<CB> Send for JitBytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}
unsafe impl<CB> Sync for JitBytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}

impl<CB> AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, JitBytesPcodeExecutorStateSpace<CB>, CB>
    for JitBytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    fn base(&self) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB> {
        &self.long_base
    }

    /// Port of `getForSpace(AddressSpace, false)`.
    ///
    /// Overridden in Java to grant public access, since the JIT-generated constructors need to
    /// invoke it; this trait method is already public.
    fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&JitBytesPcodeExecutorStateSpace<CB>> {
        self.space_map.get(space)
    }

    fn set_in_space<C: PcodeStateCallbacks>(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        val: &Vec<u8>,
        cb: &C,
    ) {
        if !self.space_map.contains_key(space) {
            let new_space = self.new_space(space);
            self.space_map.insert(Arc::clone(space), new_space);
        }
        let s = self.space_map.get(space).expect("space was just inserted if it was missing").clone();
        s.inner.write(&*self, offset, val.as_slice(), 0, size, cb);
    }

    fn get_from_space<C: PcodeStateCallbacks>(
        &self,
        space: &JitBytesPcodeExecutorStateSpace<CB>,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> Vec<u8> {
        let read = space.inner.read(self, offset, size, reason, cb);
        if read.len() != size as usize {
            panic!("Incomplete read ({} of {} bytes)", read.len(), size);
        }
        read
    }

    fn get_register_values_from_space(
        &self,
        space: &JitBytesPcodeExecutorStateSpace<CB>,
        registers: &[RegisterRef],
    ) -> Vec<(RegisterRef, Vec<u8>)> {
        space.inner.get_register_values(registers)
    }
}

type Base<CB> = AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>;

impl<CB> PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for JitBytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!("JitBytesPcodeExecutorStatePiece::get_language not implemented")
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.long_base.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.long_base.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        vec![self]
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, quantize: bool, val: &Vec<u8>) {
        Base::set_var_abstract(self, space, offset, size, quantize, val);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, val: &Vec<u8>) {
        Base::set_var_internal_abstract(self, space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &Vec<u8>) {
        Base::set_var(self, space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &Vec<u8>) {
        Base::set_var_internal(self, space, offset, size, val);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, quantize: bool, reason: Reason) -> Vec<u8> {
        Base::get_var_abstract(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &Vec<u8>, size: i32, reason: Reason) -> Vec<u8> {
        Base::get_var_internal_abstract(self, space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> Vec<u8> {
        Base::get_var(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> Vec<u8> {
        Base::get_var_internal(self, space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
        Base::get_register_values(self)
    }

    fn get_concrete_buffer(&self, address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
        Box::new(StateMemBuffer {
            address: address.clone(),
            source: self.get_for_space(address.space()).map(|s| s.inner.shared_bytes()),
            big_endian: self.long_base.language().is_big_endian(),
        })
    }

    /// Port of `clear()`. Java throws `UnsupportedOperationException`; this panics.
    fn clear(&mut self) {
        panic!("UnsupportedOperationException: JitBytesPcodeExecutorStatePiece does not support clear()")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use std::collections::HashSet;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn unique_space() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2)
    }

    struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
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

        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }

        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
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
            Box::new(DefaultAddressFactory::new(vec![ram_space(), unique_space()]))
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
            Box::new(crate::program::model::address::AddressSet::new())
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
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }

    fn piece() -> JitBytesPcodeExecutorStatePiece<NoPcodeStateCallbacks> {
        JitBytesPcodeExecutorStatePiece {
            long_base: crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::new_long_offset_base(
                Arc::new(MockLanguage),
                Arc::new(BytesArithmetic),
                Arc::new(NoPcodeStateCallbacks),
            ),
            space_map: HashMap::new(),
        }
    }

    #[test]
    fn set_var_creates_a_space_lazily_and_get_var_reads_it_back() {
        let mut p = piece();
        let ram = ram_space();

        assert!(p.get_for_space(&ram).is_none());
        p.set_var(&ram, 0x1000, 4, false, &vec![1, 2, 3, 4]);

        assert!(p.get_for_space(&ram).is_some());
        assert_eq!(p.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![1, 2, 3, 4]);
    }

    #[test]
    fn unique_space_writes_land_in_the_languages_unique_space() {
        let mut p = piece();
        let unique = unique_space();
        p.set_var(&unique, 0x10, 2, false, &vec![5, 6]);
        assert!(p.get_for_space(&unique).is_some());
        assert_eq!(p.get_var(&unique, 0x10, 2, false, Reason::ExecuteRead), vec![5, 6]);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn clear_is_unsupported() {
        piece().clear();
    }

    #[test]
    fn get_concrete_buffer_reads_bytes_already_written_to_the_space() {
        let mut p = piece();
        let ram = ram_space();
        p.set_var(&ram, 0x2000, 4, false, &vec![0xde, 0xad, 0xbe, 0xef]);

        let buf = p.get_concrete_buffer(&ram.address(0x2001), Purpose::Load);
        let mut out = [0u8; 3];
        assert_eq!(buf.get_bytes(&mut out, 0), 3);
        assert_eq!(out, [0xad, 0xbe, 0xef]);
    }

    #[test]
    fn space_read_and_write_shortcuts_default_to_execute_read_and_the_spaces_own_callbacks() {
        let mut p = piece();
        let ram = ram_space();
        p.set_var(&ram, 0x3000, 2, false, &vec![7, 8]);

        let space = p.get_for_space(&ram).expect("space created by set_var").clone();
        space.write(&p, 0x3002, &[9, 9], 0, 2);
        assert_eq!(space.read(&p, 0x3000, 4), vec![7, 8, 9, 9]);
    }

    #[test]
    fn get_direct_returns_the_block_containing_written_bytes_at_the_right_offset() {
        let mut p = piece();
        let ram = ram_space();
        // Java's SemisparseByteArray.BLOCK_SIZE is 0x1000; 0x1005 falls in block 1, at offset 5.
        p.set_var(&ram, 0x1005, 2, false, &vec![0xaa, 0xbb]);

        let space = p.get_for_space(&ram).expect("space created by set_var");
        let block = space.get_direct(0x1005);
        assert_eq!(block.len(), BLOCK_SIZE as usize);
        assert_eq!(&block[5..7], &[0xaa, 0xbb]);

        // Any offset within the same block yields the same block start.
        let block_from_start = space.get_direct(0x1000);
        assert_eq!(block_from_start[5..7], block[5..7]);

        // A different block does not see those bytes.
        let other_block = space.get_direct(0x2000);
        assert_eq!(other_block, vec![0u8; BLOCK_SIZE as usize]);
    }
}
