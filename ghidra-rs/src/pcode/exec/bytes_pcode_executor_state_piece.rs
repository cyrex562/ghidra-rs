//! A plain concrete state piece for storing and retrieving bytes as arrays.
//!
//! Corresponds to `ghidra.pcode.exec.BytesPcodeExecutorStatePiece`.
//!
//! This is a concrete subclass of [`AbstractBytesPcodeExecutorStatePiece`], providing the
//! default implementation of [`newSpace`](AbstractBytesPcodeExecutorStatePiece::new_space) that
//! simply constructs a new [`BytesPcodeExecutorStateSpace`] for the given address space.

use std::sync::Arc;

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

    /// Create a fork of this piece with different callbacks.
    ///
    /// Port of `fork(PcodeStateCallbacks)`. Returns a new instance; spaces are created
    /// on demand when accessed, mirroring lazy initialization.
    pub fn fork(&self, cb: Arc<CB>) -> Self {
        Self::new(Arc::clone(self.long_base.language()), cb)
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
        unimplemented!("BytesPcodeExecutorStatePiece::get_language not implemented")
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

type Base<CB> = AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, CB>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles() {
        // smoke test: just verify the module compiles
    }
}
