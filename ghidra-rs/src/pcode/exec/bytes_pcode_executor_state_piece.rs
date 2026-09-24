//! A plain concrete state piece for storing and retrieving bytes as arrays.
//!
//! Corresponds to `ghidra.pcode.exec.BytesPcodeExecutorStatePiece`.
//!
//! This is a concrete subclass of [`AbstractBytesPcodeExecutorStatePiece`], providing the
//! default implementation of [`newSpace`](AbstractBytesPcodeExecutorStatePiece::new_space) that
//! simply constructs a new [`BytesPcodeExecutorStateSpace`] for the given address space.
//!
//! Java's only `fork` takes the new callbacks, which this port models as the inherent
//! [`BytesPcodeExecutorStatePiece::fork`]: the trait-level
//! [`PcodeExecutorStatePiece::fork`] is generic over *any* callbacks type, which cannot become
//! this piece's own `CB`, so it keeps the trait's default.

use std::sync::Arc;

use crate::generic::ulong_span::ULongSpan;

use crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::{
    AbstractBytesPcodeExecutorStatePiece, AbstractBytesPcodeExecutorStatePieceBase,
    new_long_offset_base_for_language,
};
use crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::{
    AbstractLongOffsetPcodeExecutorStatePiece, AbstractLongOffsetPcodeExecutorStatePieceBase,
};
use crate::pcode::exec::bytes_pcode_executor_state_space::BytesPcodeExecutorStateSpace;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::MemBuffer;

/// A plain concrete state piece without any backing objects.
///
/// Port of `BytesPcodeExecutorStatePiece(Language, PcodeStateCallbacks)`.
pub struct BytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    long_base: AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>,
    bytes_base: AbstractBytesPcodeExecutorStatePieceBase,
}

impl<CB> BytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    /// Construct a state for the given language.
    ///
    /// Port of `BytesPcodeExecutorStatePiece(Language, PcodeStateCallbacks)`.
    pub fn new(language: Arc<dyn Language>, cb: Arc<CB>) -> Self {
        Self {
            long_base: new_long_offset_base_for_language(language, cb),
            bytes_base: AbstractBytesPcodeExecutorStatePieceBase::new(),
        }
    }

    /// Create a deep copy of this piece, reporting to the given callbacks.
    ///
    /// Port of `fork(PcodeStateCallbacks)`: a new piece for the same language whose every
    /// existing space is a fork of this one's, so writes to either do not affect the other.
    pub fn fork(&self, cb: Arc<CB>) -> Self {
        let mut result = Self::new(Arc::clone(self.long_base.language()), cb);
        result.bytes_base = self.bytes_base.fork();
        result
    }
}

impl<CB> ErasedPcodeExecutorStatePiece for BytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}

impl<CB> seam_stubs::BytesPcodeExecutorStatePiece for BytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}

unsafe impl<CB> Send for BytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}
unsafe impl<CB> Sync for BytesPcodeExecutorStatePiece<CB> where CB: PcodeStateCallbacks {}

impl<CB> AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, BytesPcodeExecutorStateSpace, CB>
    for BytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    fn base(&self) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB> {
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

impl<CB> AbstractBytesPcodeExecutorStatePiece<CB> for BytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
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

impl<CB> PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for BytesPcodeExecutorStatePiece<CB>
where
    CB: PcodeStateCallbacks,
{
    fn get_language(&self) -> Box<dyn Language> {
        Box::new(Arc::clone(self.long_base.language()))
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

    /// Port of the override `getNextEntryInternal(AddressSpace, long)`: the initialized run of
    /// bytes containing `offset`, or else the first one after it (in unsigned order), as its
    /// starting offset and contents; `None` if the space does not exist or has nothing there.
    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, Vec<u8>)> {
        let s = self.bytes_base.get_for_space(space)?;
        let bytes = s.shared_bytes();
        let initialized = bytes.get_initialized(0, u64::MAX);
        let offset = offset as u64;
        let span = initialized
            .iter()
            .find(|span| span.min <= offset && offset <= span.max)
            .or_else(|| initialized.iter().find(|span| span.max >= offset))?;
        let mut data = vec![0u8; span.length() as usize];
        bytes.get_data(span.min, &mut data);
        Some((span.min as i64, data))
    }
}

type Base<CB> = AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing::test_language;
    use crate::pcode::exec::pcode_state_callbacks::{NoPcodeStateCallbacks, NONE};
    use crate::program::model::lang::endian::Endian;

    fn piece() -> BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks> {
        BytesPcodeExecutorStatePiece::new(test_language(), Arc::new(NONE))
    }

    fn space(p: &BytesPcodeExecutorStatePiece<NoPcodeStateCallbacks>, name: &str) -> Arc<AddressSpace> {
        p.get_language()
            .get_address_factory()
            .get_address_spaces()
            .into_iter()
            .find(|s| s.name() == name)
            .unwrap()
    }

    #[test]
    fn arithmetic_is_the_languages_bytes_arithmetic() {
        // Java: super(language, BytesPcodeArithmetic.forLanguage(language), cb); the test
        // language is little-endian.
        let p = piece();
        assert_eq!(p.get_arithmetic().get_endian(), Some(Endian::Little));
        assert_eq!(p.get_address_arithmetic().get_endian(), Some(Endian::Little));
    }

    #[test]
    fn get_language_returns_the_constructor_language() {
        let p = piece();
        assert!(p.get_language().get_address_factory().get_address_spaces().iter().any(|s| s.name() == "ram"));
        assert!(!p.get_language().is_big_endian());
    }

    #[test]
    fn set_then_get_round_trips_and_uninitialized_reads_zero() {
        let mut p = piece();
        let ram = space(&p, "ram");
        p.set_var(&ram, 0x100, 4, false, &vec![1, 2, 3, 4]);
        assert_eq!(p.get_var(&ram, 0x100, 4, false, Reason::Inspect), vec![1, 2, 3, 4]);
        assert_eq!(p.get_var(&ram, 0x102, 2, false, Reason::Inspect), vec![3, 4]);
        assert_eq!(p.get_var(&ram, 0x200, 2, false, Reason::Inspect), vec![0, 0]);
    }

    #[test]
    fn fork_copies_existing_spaces_independently() {
        let mut p = piece();
        let ram = space(&p, "ram");
        p.set_var(&ram, 0x10, 2, false, &vec![0xaa, 0xbb]);

        let mut forked = p.fork(Arc::new(NONE));
        assert_eq!(forked.get_var(&ram, 0x10, 2, false, Reason::Inspect), vec![0xaa, 0xbb]);

        forked.set_var(&ram, 0x10, 1, false, &vec![0x11]);
        p.set_var(&ram, 0x11, 1, false, &vec![0x22]);
        assert_eq!(forked.get_var(&ram, 0x10, 2, false, Reason::Inspect), vec![0x11, 0xbb]);
        assert_eq!(p.get_var(&ram, 0x10, 2, false, Reason::Inspect), vec![0xaa, 0x22]);
    }

    #[test]
    fn get_next_entry_internal_finds_the_containing_or_following_run() {
        let mut p = piece();
        let ram = space(&p, "ram");
        // No space yet: Java returns null.
        assert_eq!(p.get_next_entry_internal(&ram, 0), None);

        p.set_var(&ram, 0x10, 3, false, &vec![1, 2, 3]);
        p.set_var(&ram, 0x40, 2, false, &vec![4, 5]);

        // Containing span: the whole run, from its start.
        assert_eq!(p.get_next_entry_internal(&ram, 0x11), Some((0x10, vec![1, 2, 3])));
        // Between runs: the next one.
        assert_eq!(p.get_next_entry_internal(&ram, 0x20), Some((0x40, vec![4, 5])));
        assert_eq!(p.get_next_entry_internal(&ram, 0), Some((0x10, vec![1, 2, 3])));
        // Past the last run.
        assert_eq!(p.get_next_entry_internal(&ram, 0x42), None);
    }

    #[test]
    fn clear_empties_every_space() {
        let mut p = piece();
        let ram = space(&p, "ram");
        p.set_var(&ram, 0x10, 2, false, &vec![7, 8]);
        p.clear();
        assert_eq!(p.get_var(&ram, 0x10, 2, false, Reason::Inspect), vec![0, 0]);
        assert_eq!(p.get_next_entry_internal(&ram, 0), None);
    }
}
