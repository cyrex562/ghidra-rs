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
//! Java's internal space type `S` is `ghidra.pcode.exec.BytesPcodeExecutorStateSpace`, not yet
//! ported; [`crate::pcode::seam_stubs::BytesPcodeExecutorStateSpace`] stands in for it. Its
//! `fork` method forward-references this very class, which is why this file was queued behind a
//! dependency cycle; that method is unused here, so the stub omits it and the cycle does not
//! need to be broken any other way.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::{
    AbstractLongOffsetPcodeExecutorStatePiece, AbstractLongOffsetPcodeExecutorStatePieceBase,
};
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs::{BytesPcodeArithmetic, BytesPcodeExecutorStateSpace};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::{Memory, MemBuffer, MemoryAccessException};

/// The shared state and concrete behavior of a bytes-addressed executor state piece.
///
/// `S` is the type of an internal execute state space, associated with an address space; it must
/// implement [`BytesPcodeExecutorStateSpace`].
pub struct AbstractBytesPcodeExecutorStatePieceBase<S> {
    space_map: HashMap<Arc<AddressSpace>, S>,
}

impl<S> Default for AbstractBytesPcodeExecutorStatePieceBase<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> AbstractBytesPcodeExecutorStatePieceBase<S> {
    /// Construct an empty piece base, Java's `spaceMap = new HashMap<>()` field initializer.
    pub fn new() -> Self {
        Self { space_map: HashMap::new() }
    }
}

impl<S> AbstractBytesPcodeExecutorStatePieceBase<S>
where
    S: BytesPcodeExecutorStateSpace,
{
    /// Get the internal space for the given address space, for reading.
    ///
    /// Port of `getForSpace(AddressSpace, false)`.
    pub fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&S> {
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
        P: AbstractBytesPcodeExecutorStatePiece<S, CB>,
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
            .expect("space was just inserted if it was missing");
        s.write(offset, val, 0, size, cb);
    }

    /// Get a value from the given space, panicking on a short read.
    ///
    /// Port of `getFromSpace(S, long, int, Reason, PcodeStateCallbacks)`. Java throws
    /// `AccessPcodeExecutionException` on a short read; this panics.
    pub fn get_from_space<C: PcodeStateCallbacks>(
        space: &S,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> Vec<u8> {
        let read = space.read(offset, size, reason, cb);
        if read.len() != size as usize {
            panic!("Incomplete read ({} of {} bytes)", read.len(), size);
        }
        read
    }

    /// Scan the given space for register values.
    ///
    /// Port of `getRegisterValuesFromSpace(S, List<Register>)`.
    pub fn get_register_values_from_space(
        space: &S,
        registers: &[RegisterRef],
    ) -> Vec<(RegisterRef, Vec<u8>)> {
        space.get_register_values(registers)
    }

    /// Bind a buffer of concrete bytes at the given address, sourced from whichever internal
    /// space already exists there (without creating one).
    ///
    /// Port of `getConcreteBuffer(Address, PcodeArithmetic.Purpose)`. Java's `StateMemBuffer`
    /// lazily re-resolves a missing space (via `getForSpace`) and consults the state's callbacks
    /// on first read, since it is an inner class holding a live reference to the outer piece.
    /// The ported [`PcodeExecutorStatePiece::get_concrete_buffer`](crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece::get_concrete_buffer)
    /// returns an owned `Box<dyn MemBuffer>` that cannot borrow `piece`, so the space is instead
    /// resolved once, here, by cloning the (cheaply-cloneable, internally-mutable) space handle;
    /// a space that does not exist yet at this point reads as all zero rather than possibly
    /// being created on demand.
    pub fn get_concrete_buffer<CB, P>(
        piece: &P,
        address: &Address,
        purpose: Purpose,
    ) -> Box<dyn MemBuffer>
    where
        CB: PcodeStateCallbacks,
        P: AbstractBytesPcodeExecutorStatePiece<S, CB>,
        S: Send + Sync + 'static,
        CB: Send + Sync + 'static,
    {
        Box::new(StateMemBuffer {
            address: address.clone(),
            source: piece.get_for_space(address.space()).cloned(),
            reason: purpose.reason(),
            big_endian: piece.base().language().is_big_endian(),
            cb: Arc::clone(piece.base().cb()),
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
/// Port of the inner class `StateMemBuffer`. See
/// [`AbstractBytesPcodeExecutorStatePieceBase::get_concrete_buffer`] for how this differs from
/// Java's version, which holds a live reference to the outer piece.
struct StateMemBuffer<S, CB> {
    address: Address,
    source: Option<S>,
    reason: Reason,
    big_endian: bool,
    cb: Arc<CB>,
}

impl<S, CB> MemBuffer for StateMemBuffer<S, CB>
where
    S: BytesPcodeExecutorStateSpace + Send + Sync,
    CB: PcodeStateCallbacks + Send + Sync,
{
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
        let Some(source) = &self.source else {
            return 0;
        };
        let data =
            source.read(self.address.offset() + offset as i64, buf.len() as i32, self.reason, self.cb.as_ref());
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        n
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        None
    }
}

/// The one operation a concrete bytes state piece must supply, plus accessors for the embedded
/// [`AbstractBytesPcodeExecutorStatePieceBase`].
///
/// `S` is the type of an internal execute state space, associated with an address space.
pub trait AbstractBytesPcodeExecutorStatePiece<S, CB>:
    AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, S, CB>
where
    S: BytesPcodeExecutorStateSpace,
    CB: PcodeStateCallbacks,
{
    /// The embedded shared state of this class.
    fn bytes_base(&self) -> &AbstractBytesPcodeExecutorStatePieceBase<S>;

    /// The embedded shared state of this class, mutably.
    fn bytes_base_mut(&mut self) -> &mut AbstractBytesPcodeExecutorStatePieceBase<S>;

    /// Construct a new internal space for the given address space.
    ///
    /// Port of the abstract `protected abstract S newSpace(AddressSpace space)`.
    fn new_space(&self, space: &Arc<AddressSpace>) -> S;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::rc::Rc;
    use std::sync::Mutex;

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

    /// An internal space, in the shape every real subclass takes: a byte-addressed map behind a
    /// mutex (for `&self` mutation) that is cheap to clone (an `Arc` handle), so
    /// `get_concrete_buffer` can hand out an independent, still-live view.
    #[derive(Clone, Default)]
    struct TestSpace(Arc<Mutex<HashMap<i64, u8>>>);

    impl BytesPcodeExecutorStateSpace for TestSpace {
        fn write<C: PcodeStateCallbacks>(
            &self,
            offset: i64,
            val: &[u8],
            _src_offset: i32,
            _length: i32,
            _cb: &C,
        ) {
            let mut map = self.0.lock().unwrap();
            for (i, b) in val.iter().enumerate() {
                map.insert(offset + i as i64, *b);
            }
        }

        fn read<C: PcodeStateCallbacks>(&self, offset: i64, size: i32, _reason: Reason, _cb: &C) -> Vec<u8> {
            let map = self.0.lock().unwrap();
            (0..size as i64).map(|i| *map.get(&(offset + i)).unwrap_or(&0)).collect()
        }

        fn get_register_values(&self, registers: &[RegisterRef]) -> Vec<(RegisterRef, Vec<u8>)> {
            registers
                .iter()
                .map(|register| {
                    let (offset, size) = {
                        let reg = register.borrow();
                        (reg.address().offset(), reg.minimum_byte_size())
                    };
                    (Rc::clone(register), self.read(offset, size, Reason::Inspect, &NoPcodeStateCallbacks))
                })
                .collect()
        }

        fn clear(&self) {
            self.0.lock().unwrap().clear();
        }
    }

    /// A space whose `read` always returns fewer bytes than requested, to exercise the
    /// incomplete-read panic.
    #[derive(Clone, Default)]
    struct ShortReadSpace;

    impl BytesPcodeExecutorStateSpace for ShortReadSpace {
        fn write<C: PcodeStateCallbacks>(&self, _offset: i64, _val: &[u8], _src_offset: i32, _length: i32, _cb: &C) {
        }

        fn read<C: PcodeStateCallbacks>(&self, _offset: i64, size: i32, _reason: Reason, _cb: &C) -> Vec<u8> {
            vec![0; (size - 1).max(0) as usize]
        }

        fn get_register_values(&self, _registers: &[RegisterRef]) -> Vec<(RegisterRef, Vec<u8>)> {
            Vec::new()
        }

        fn clear(&self) {}
    }

    /// A concrete piece in the shape every real subclass takes.
    struct BytesPiece<S> {
        long_base: AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, NoPcodeStateCallbacks>,
        bytes_base: AbstractBytesPcodeExecutorStatePieceBase<S>,
    }

    impl<S: BytesPcodeExecutorStateSpace + Default> BytesPiece<S> {
        fn new() -> Self {
            Self {
                long_base: new_long_offset_base(Arc::new(MockLanguage), Arc::new(BytesArithmetic), Arc::new(NoPcodeStateCallbacks)),
                bytes_base: AbstractBytesPcodeExecutorStatePieceBase::new(),
            }
        }
    }

    impl<S: BytesPcodeExecutorStateSpace> ErasedPcodeExecutorStatePiece for BytesPiece<S> {}

    impl<S: BytesPcodeExecutorStateSpace + Default + 'static>
        AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, S, NoPcodeStateCallbacks> for BytesPiece<S>
    {
        fn base(&self) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, NoPcodeStateCallbacks> {
            &self.long_base
        }

        fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&S> {
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
            space: &S,
            offset: i64,
            size: i32,
            reason: Reason,
            cb: &C,
        ) -> Vec<u8> {
            AbstractBytesPcodeExecutorStatePieceBase::get_from_space(space, offset, size, reason, cb)
        }

        fn get_register_values_from_space(&self, space: &S, registers: &[RegisterRef]) -> Vec<(RegisterRef, Vec<u8>)> {
            AbstractBytesPcodeExecutorStatePieceBase::get_register_values_from_space(space, registers)
        }
    }

    impl<S: BytesPcodeExecutorStateSpace + Default + 'static>
        AbstractBytesPcodeExecutorStatePiece<S, NoPcodeStateCallbacks> for BytesPiece<S>
    {
        fn bytes_base(&self) -> &AbstractBytesPcodeExecutorStatePieceBase<S> {
            &self.bytes_base
        }

        fn bytes_base_mut(&mut self) -> &mut AbstractBytesPcodeExecutorStatePieceBase<S> {
            &mut self.bytes_base
        }

        fn new_space(&self, _space: &Arc<AddressSpace>) -> S {
            S::default()
        }
    }

    impl<S: BytesPcodeExecutorStateSpace + Send + Sync + 'static + Default> PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>
        for BytesPiece<S>
    {
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

    fn piece() -> BytesPiece<TestSpace> {
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

    #[test]
    #[should_panic(expected = "Incomplete read (1 of 2 bytes)")]
    fn get_from_space_panics_on_a_short_read() {
        let mut piece = BytesPiece::<ShortReadSpace>::new();
        let ram = ram_space();
        piece.set_var(&ram, 0x1000, 2, false, &vec![1, 2]);
        piece.get_var(&ram, 0x1000, 2, false, Reason::ExecuteRead);
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
