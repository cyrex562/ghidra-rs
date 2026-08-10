//! An abstract p-code executor state piece for storing and retrieving bytes as arrays.
//!
//! Corresponds to `ghidra.pcode.exec.AbstractBytesPcodeExecutorStatePiece`.
//!
//! This class fixes both the address and value domains of
//! [`AbstractLongOffsetPcodeExecutorStatePiece`] to `byte[]`/`Vec<u8>`, and supplies the concrete
//! behavior that class leaves abstract: internal spaces are created lazily, keyed by address
//! space, in a `spaceMap`. Only `newSpace` remains abstract.
//!
//! Following the same split as [`AbstractLongOffsetPcodeExecutorStatePiece`]:
//!
//! * [`AbstractBytesPcodeExecutorStatePieceBase`] holds the `spaceMap` field and the concrete
//!   behavior, as associated functions taking the piece itself (mirroring
//!   [`AbstractLongOffsetPcodeExecutorStatePieceBase`]'s own convention).
//! * [`AbstractBytesPcodeExecutorStatePiece`] declares the one operation Java leaves abstract
//!   (`newSpace`), plus accessors for the embedded base. It extends
//!   [`AbstractLongOffsetPcodeExecutorStatePiece`], whose own abstract operations
//!   (`get_for_space`/`set_in_space`/`get_from_space`/`get_register_values_from_space`) a
//!   concrete leaf implements by forwarding to this base's associated functions of the same
//!   purpose, exactly as this class's Java source does.
//!
//! A concrete leaf embeds both bases, implements this trait and
//! [`AbstractLongOffsetPcodeExecutorStatePiece`], and implements
//! [`PcodeExecutorStatePiece`](crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece)
//! by forwarding to whichever base actually implements each method (most to the long-offset
//! base's associated functions, `get_concrete_buffer` and `clear` to this one's).
//!
//! Java's internal space type `S` is fixed here to the real
//! [`BytesPcodeExecutorStateSpace`] rather than kept generic: Java parameterizes
//! `AbstractBytesPcodeExecutorStatePiece<S extends BytesPcodeExecutorStateSpace>` because it has
//! several concrete subclasses of that space (e.g. for the JIT emulator, and for the legacy
//! `AdaptedEmulator`), but none of those are ported yet, so there is currently only one Rust type
//! that could ever fill `S`. Re-introducing genericity is deferred until one of those subclasses
//! is ported.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::{
    AbstractLongOffsetPcodeExecutorStatePiece, AbstractLongOffsetPcodeExecutorStatePieceBase,
};
use crate::pcode::exec::bytes_pcode_executor_state_space::BytesPcodeExecutorStateSpace;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs::BytesPcodeArithmetic;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};

/// The shared state and concrete behavior of a bytes-addressed executor state piece.
pub struct AbstractBytesPcodeExecutorStatePieceBase {
    space_map: HashMap<Arc<AddressSpace>, BytesPcodeExecutorStateSpace>,
}

impl Default for AbstractBytesPcodeExecutorStatePieceBase {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractBytesPcodeExecutorStatePieceBase {
    /// Construct an empty piece base, Java's `spaceMap = new HashMap<>()` field initializer.
    pub fn new() -> Self {
        Self { space_map: HashMap::new() }
    }

    /// Get the internal space for the given address space, for reading.
    ///
    /// Port of `getForSpace(AddressSpace, false)`.
    pub fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&BytesPcodeExecutorStateSpace> {
        self.space_map.get(space)
    }

    /// Set a value in the given space, creating it (via [`AbstractBytesPcodeExecutorStatePiece::new_space`])
    /// if it does not exist yet.
    ///
    /// Port of `getForSpace(space, true)` followed by `setInSpace(S, long, int, byte[],
    /// PcodeStateCallbacks)`.
    pub fn set_in_space<CB, P, C>(
        piece: &mut P,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        val: &Vec<u8>,
        cb: &C,
    ) where
        CB: PcodeStateCallbacks,
        P: AbstractBytesPcodeExecutorStatePiece<CB>,
        C: PcodeStateCallbacks,
    {
        if !piece.bytes_base().space_map.contains_key(space) {
            let new_space = piece.new_space(space);
            piece.bytes_base_mut().space_map.insert(Arc::clone(space), new_space);
        }
        let s = piece
            .bytes_base()
            .space_map
            .get(space)
            .expect("space was just inserted if it was missing")
            .clone();
        s.write(&*piece, offset, val.as_slice(), 0, size, cb);
    }

    /// Get a value from the given space, panicking on a short read.
    ///
    /// Port of `getFromSpace(S, long, int, Reason, PcodeStateCallbacks)`. Java throws
    /// `AccessPcodeExecutionException` on a short read; this panics. `piece` is passed through to
    /// [`BytesPcodeExecutorStateSpace::read`], standing in for Java's implicit `this.piece`.
    pub fn get_from_space<C: PcodeStateCallbacks>(
        space: &BytesPcodeExecutorStateSpace,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> Vec<u8> {
        let read = space.read(piece, offset, size, reason, cb);
        if read.len() != size as usize {
            panic!("Incomplete read ({} of {} bytes)", read.len(), size);
        }
        read
    }

    /// Scan the given space for register values.
    ///
    /// Port of `getRegisterValuesFromSpace(S, List<Register>)`.
    pub fn get_register_values_from_space(
        space: &BytesPcodeExecutorStateSpace,
        registers: &[RegisterRef],
    ) -> Vec<(RegisterRef, Vec<u8>)> {
        space.get_register_values(registers)
    }

    /// Bind a buffer of concrete bytes at the given address, sourced from whichever internal
    /// space already exists there (without creating one).
    ///
    /// Port of `getConcreteBuffer(Address, PcodeArithmetic.Purpose)`. Java's `StateMemBuffer`
    /// lazily re-resolves a missing space (via `getForSpace`) and consults the state's callbacks
    /// on first read, since it is an inner class holding a live reference to the outer piece and
    /// to `this.piece`. The ported [`StateMemBuffer`] instead reads directly off a cloned bytes
    /// handle (see its docs for why), so a space that does not exist yet at this point reads as
    /// all zero rather than possibly being created on demand, and no uninitialized-read warning
    /// or callback is triggered through this path.
    pub fn get_concrete_buffer<CB, P>(piece: &P, address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer>
    where
        CB: PcodeStateCallbacks,
        P: AbstractBytesPcodeExecutorStatePiece<CB>,
    {
        Box::new(StateMemBuffer {
            address: address.clone(),
            source: piece.get_for_space(address.space()).map(BytesPcodeExecutorStateSpace::shared_bytes),
            big_endian: piece.base().language().is_big_endian(),
        })
    }

    /// Clear every internal space's contents.
    ///
    /// Port of `clear()`: clears each space in turn, but (like Java) does not remove any space
    /// from `spaceMap` itself.
    pub fn clear(&self) {
        for space in self.space_map.values() {
            space.clear();
        }
    }
}

/// Port of the constructor `AbstractBytesPcodeExecutorStatePiece(Language,
/// PcodeArithmetic<byte[]>, PcodeStateCallbacks)`: builds the parent
/// [`AbstractLongOffsetPcodeExecutorStatePieceBase`], using `arithmetic` for both the address and
/// value domains, since this class fixes both to `byte[]`/`Vec<u8>`.
pub fn new_long_offset_base<CB>(
    language: Arc<dyn Language>,
    arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>>,
    cb: Arc<CB>,
) -> AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>
where
    CB: PcodeStateCallbacks,
{
    AbstractLongOffsetPcodeExecutorStatePieceBase::new(language, Arc::clone(&arithmetic), arithmetic, cb)
}

/// Port of the constructor `AbstractBytesPcodeExecutorStatePiece(Language,
/// PcodeStateCallbacks)`: delegates to the three-argument constructor with the language's
/// default bytes arithmetic.
pub fn new_long_offset_base_for_language<CB>(
    language: Arc<dyn Language>,
    cb: Arc<CB>,
) -> AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>
where
    CB: PcodeStateCallbacks,
{
    let arithmetic = BytesPcodeArithmetic::for_language(&language);
    new_long_offset_base(language, arithmetic, cb)
}

/// A memory buffer bound to a given space in this state.
///
/// Port of the inner class `StateMemBuffer`. Unlike Java's version (which holds a live reference
/// to the outer piece and re-resolves the space on every read), this holds only the space's
/// shared bytes handle, cloned once at construction (see
/// [`AbstractBytesPcodeExecutorStatePieceBase::get_concrete_buffer`]). It cannot hold the full
/// [`BytesPcodeExecutorStateSpace`] (whose `language` field is not `Send + Sync`) because
/// [`MemBuffer`] requires `Send + Sync`; consequently it reads bytes directly rather than through
/// [`BytesPcodeExecutorStateSpace::read`], so it triggers no uninitialized-read callback or
/// warning (uninitialized offsets simply read as zero, as they always do at the storage level).
struct StateMemBuffer {
    address: Address,
    source: Option<crate::generic::seam_stubs::SemisparseByteArray>,
    big_endian: bool,
}

impl MemBuffer for StateMemBuffer {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        let mut buf = [0u8; 1];
        if self.get_bytes(&mut buf, offset) == 1 {
            Ok(buf[0])
        } else {
            Err(MemoryAccessException::new("Could not read byte"))
        }
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        let Some(bytes) = &self.source else {
            return 0;
        };
        bytes.get_data((self.address.offset() + offset as i64) as u64, buf);
        buf.len()
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    fn get_memory(&self) -> Option<Arc<dyn crate::program::model::mem::Memory>> {
        None
    }
}

/// The one operation a concrete bytes state piece must supply, plus accessors for the embedded
/// [`AbstractBytesPcodeExecutorStatePieceBase`].
pub trait AbstractBytesPcodeExecutorStatePiece<CB>:
    AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, BytesPcodeExecutorStateSpace, CB>
where
    CB: PcodeStateCallbacks,
{
    /// The embedded shared state of this class.
    fn bytes_base(&self) -> &AbstractBytesPcodeExecutorStatePieceBase;

    /// The embedded shared state of this class, mutably.
    fn bytes_base_mut(&mut self) -> &mut AbstractBytesPcodeExecutorStatePieceBase;

    /// Construct a new internal space for the given address space.
    ///
    /// Port of the abstract `protected abstract S newSpace(AddressSpace space)`.
    fn new_space(&self, space: &Arc<AddressSpace>) -> BytesPcodeExecutorStateSpace;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece};
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn unique_space() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2)
    }

    /// Little-endian byte-array arithmetic, the domain every in-tree subclass of this class uses.
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

    /// A concrete piece in the shape every real subclass takes.
    struct BytesPiece {
        long_base: AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, NoPcodeStateCallbacks>,
        bytes_base: AbstractBytesPcodeExecutorStatePieceBase,
    }

    impl BytesPiece {
        fn new() -> Self {
            Self {
                long_base: new_long_offset_base(Arc::new(MockLanguage), Arc::new(BytesArithmetic), Arc::new(NoPcodeStateCallbacks)),
                bytes_base: AbstractBytesPcodeExecutorStatePieceBase::new(),
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for BytesPiece {}

    impl AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, BytesPcodeExecutorStateSpace, NoPcodeStateCallbacks>
        for BytesPiece
    {
        fn base(&self) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, NoPcodeStateCallbacks> {
            &self.long_base
        }

        fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&BytesPcodeExecutorStateSpace> {
            self.bytes_base.get_for_space(space)
        }

        fn set_in_space<C: PcodeStateCallbacks>(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            val: &Vec<u8>,
            cb: &C,
        ) {
            AbstractBytesPcodeExecutorStatePieceBase::set_in_space(self, space, offset, size, val, cb);
        }

        fn get_from_space<C: PcodeStateCallbacks>(
            &self,
            space: &BytesPcodeExecutorStateSpace,
            offset: i64,
            size: i32,
            reason: Reason,
            cb: &C,
        ) -> Vec<u8> {
            AbstractBytesPcodeExecutorStatePieceBase::get_from_space(space, self, offset, size, reason, cb)
        }

        fn get_register_values_from_space(
            &self,
            space: &BytesPcodeExecutorStateSpace,
            registers: &[RegisterRef],
        ) -> Vec<(RegisterRef, Vec<u8>)> {
            AbstractBytesPcodeExecutorStatePieceBase::get_register_values_from_space(space, registers)
        }
    }

    impl AbstractBytesPcodeExecutorStatePiece<NoPcodeStateCallbacks> for BytesPiece {
        fn bytes_base(&self) -> &AbstractBytesPcodeExecutorStatePieceBase {
            &self.bytes_base
        }

        fn bytes_base_mut(&mut self) -> &mut AbstractBytesPcodeExecutorStatePieceBase {
            &mut self.bytes_base
        }

        fn new_space(&self, space: &Arc<AddressSpace>) -> BytesPcodeExecutorStateSpace {
            BytesPcodeExecutorStateSpace::new(Arc::clone(self.long_base.language()), Arc::clone(space))
        }
    }

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for BytesPiece {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
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

        fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
            AbstractBytesPcodeExecutorStatePieceBase::get_concrete_buffer(self, address, purpose)
        }

        fn clear(&mut self) {
            self.bytes_base.clear();
        }
    }

    /// Shorthand for the parent base, whose associated functions carry the concrete
    /// `set_var`/`get_var` behavior (this class only overrides the pieces documented above).
    type Base = AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, NoPcodeStateCallbacks>;

    fn piece() -> BytesPiece {
        BytesPiece::new()
    }

    #[test]
    fn set_var_creates_a_space_lazily_and_get_var_reads_it_back() {
        let mut piece = piece();
        let ram = ram_space();

        assert!(piece.get_for_space(&ram).is_none());
        piece.set_var(&ram, 0x1000, 4, false, &vec![1, 2, 3, 4]);

        assert!(piece.get_for_space(&ram).is_some());
        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![1, 2, 3, 4]);
    }

    #[test]
    fn get_concrete_buffer_reads_bytes_already_written_to_the_space() {
        let mut piece = piece();
        let ram = ram_space();
        piece.set_var(&ram, 0x2000, 4, false, &vec![0xde, 0xad, 0xbe, 0xef]);

        let buf = piece.get_concrete_buffer(&ram.address(0x2001), Purpose::Load);
        let mut out = [0u8; 3];
        assert_eq!(buf.get_bytes(&mut out, 0), 3);
        assert_eq!(out, [0xad, 0xbe, 0xef]);
    }

    #[test]
    fn get_concrete_buffer_over_a_space_that_does_not_exist_yet_reads_nothing() {
        let piece = piece();
        let buf = piece.get_concrete_buffer(&ram_space().address(0x3000), Purpose::Load);
        let mut out = [0xffu8; 4];
        assert_eq!(buf.get_bytes(&mut out, 0), 0);
    }

    #[test]
    fn clear_resets_every_spaces_contents_but_keeps_the_spaces_present() {
        let mut piece = piece();
        let ram = ram_space();
        piece.set_var(&ram, 0x1000, 2, false, &vec![9, 9]);

        piece.clear();

        assert!(piece.get_for_space(&ram).is_some());
        assert_eq!(piece.get_var(&ram, 0x1000, 2, false, Reason::ExecuteRead), vec![0, 0]);
    }

    #[test]
    fn unique_space_writes_land_in_the_languages_unique_space() {
        let mut piece = piece();
        let unique = unique_space();
        piece.set_var(&unique, 0x10, 2, false, &vec![5, 6]);
        assert!(piece.get_for_space(&unique).is_some());
        assert_eq!(piece.get_var(&unique, 0x10, 2, false, Reason::ExecuteRead), vec![5, 6]);
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
            unimplemented!("not exercised by these tests")
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
}
