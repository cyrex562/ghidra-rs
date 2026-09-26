//! Port of `ghidra.pcode.emu.taint.state.TaintPcodeExecutorStatePiece`.
//!
//! The taint state piece.
//!
//! The framework-provided class from which this derives expects us to implement state for each
//! address space using a separate storage object. We do this by providing [`TaintSpace`], which is
//! where all the taint storage logic is actually located. We then use a map to lazily create and
//! keep each of those spaces.
//!
//! Java extends `AbstractLongOffsetPcodeExecutorStatePiece<byte[], TaintVec, TaintSpace>`; here
//! the piece embeds [`AbstractLongOffsetPcodeExecutorStatePieceBase`] and implements
//! [`AbstractLongOffsetPcodeExecutorStatePiece`], forwarding every `PcodeExecutorStatePiece`
//! read/write method to the base, as that module's docs require.

use std::collections::HashMap;
use std::sync::Arc;

use crate::feature::taint::model::TaintVec;
use crate::pcode::emu::taint::state::taint_space::TaintSpace;
use crate::pcode::emu::taint::taint_pcode_arithmetic::TaintPcodeArithmetic;
use crate::pcode::exec::abstract_long_offset_pcode_executor_state_piece::{
    AbstractLongOffsetPcodeExecutorStatePiece, AbstractLongOffsetPcodeExecutorStatePieceBase,
};
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::MemBuffer;

/// Shorthand for the embedded base, whose associated functions carry the inherited behavior.
type Base<CB> = AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, TaintVec, CB>;

/// The taint state piece.
///
/// Addresses are concrete bytes (`byte[]` in Java), values are [`TaintVec`]s. `CB` is the type of
/// the callbacks receiving emulation events (see [`AbstractLongOffsetPcodeExecutorStatePieceBase`]
/// for why it is a type parameter).
pub struct TaintPcodeExecutorStatePiece<CB: PcodeStateCallbacks> {
    base: Base<CB>,
    /// A lazily-populated map of address space to taint storage. Java: `spaceMap`.
    space_map: HashMap<Arc<AddressSpace>, TaintSpace>,
}

impl<CB: PcodeStateCallbacks> TaintPcodeExecutorStatePiece<CB> {
    /// Create a state piece.
    ///
    /// Port of `TaintPcodeExecutorStatePiece(Language, PcodeArithmetic<byte[]>,
    /// PcodeArithmetic<TaintVec>, PcodeStateCallbacks)`.
    ///
    /// * `language` -- the emulator's language
    /// * `address_arithmetic` -- the arithmetic for the address type
    /// * `arithmetic` -- the arithmetic for the value type
    /// * `cb` -- callbacks to receive emulation events
    pub fn with_arithmetic(
        language: Arc<dyn Language>,
        address_arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>>,
        arithmetic: Arc<dyn PcodeArithmetic<TaintVec>>,
        cb: Arc<CB>,
    ) -> Self {
        Self {
            base: Base::new(language, address_arithmetic, arithmetic, cb),
            space_map: HashMap::new(),
        }
    }

    /// Create the taint piece, using [`TaintPcodeArithmetic::for_language`] for values.
    ///
    /// Port of `TaintPcodeExecutorStatePiece(Language, PcodeArithmetic<byte[]>,
    /// PcodeStateCallbacks)`.
    ///
    /// * `language` -- the language of the emulator
    /// * `address_arithmetic` -- the address arithmetic, likely taken from the concrete piece
    /// * `cb` -- callbacks to receive emulation events
    pub fn new(
        language: Arc<dyn Language>,
        address_arithmetic: Arc<dyn PcodeArithmetic<Vec<u8>>>,
        cb: Arc<CB>,
    ) -> Self {
        let arithmetic = Arc::new(TaintPcodeArithmetic::for_language(language.as_ref()));
        Self::with_arithmetic(language, address_arithmetic, arithmetic, cb)
    }
}

impl<CB: PcodeStateCallbacks> ErasedPcodeExecutorStatePiece for TaintPcodeExecutorStatePiece<CB> {}

impl<CB: PcodeStateCallbacks> AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, TaintVec, TaintSpace, CB>
    for TaintPcodeExecutorStatePiece<CB>
{
    fn base(&self) -> &Base<CB> {
        &self.base
    }

    /// Port of `getForSpace(space, false)`: delegate to the space map.
    fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&TaintSpace> {
        self.space_map.get(space)
    }

    /// Port of `getForSpace(space, true)` (lazily creating the [`TaintSpace`]) followed by
    /// `setInSpace`, which delegates to [`TaintSpace::set`]. The `dataWritten` callback Java's
    /// `TaintSpace.set` issues is issued here, once the write has landed, naming this piece.
    fn set_in_space<C: PcodeStateCallbacks>(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        _size: i32,
        val: &TaintVec,
        cb: &C,
    ) {
        self.space_map
            .entry(Arc::clone(space))
            .or_insert_with(|| TaintSpace::new(Arc::clone(space)))
            .set(offset, val);
        let piece: &dyn PcodeExecutorStatePiece<Vec<u8>, TaintVec> = self;
        cb.data_written(piece, &space.address(offset), val.length as i32, val);
    }

    /// Port of `getFromSpace`: delegate to [`TaintSpace::get`].
    fn get_from_space<C: PcodeStateCallbacks>(
        &self,
        space: &TaintSpace,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> TaintVec {
        space.get(offset, size, reason, cb, self)
    }

    /// Port of `getRegisterValuesFromSpace`: delegate to [`TaintSpace::get_register_values`].
    fn get_register_values_from_space(
        &self,
        space: &TaintSpace,
        registers: &[RegisterRef],
    ) -> Vec<(RegisterRef, TaintVec)> {
        space.get_register_values(registers)
    }
}

impl<CB: PcodeStateCallbacks> PcodeExecutorStatePiece<Vec<u8>, TaintVec>
    for TaintPcodeExecutorStatePiece<CB>
{
    fn get_language(&self) -> Box<dyn Language> {
        Box::new(Arc::clone(self.base.language()))
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.base.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<TaintVec>> {
        self.base.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        vec![self]
    }

    // `fork` keeps the trait default: Java's override throws UnsupportedOperationException.

    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        val: &TaintVec,
    ) {
        Base::set_var_abstract(self, space, offset, size, quantize, val);
    }

    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        val: &TaintVec,
    ) {
        Base::set_var_internal_abstract(self, space, offset, size, val);
    }

    fn set_var(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, val: &TaintVec) {
        Base::set_var(self, space, offset, size, quantize, val);
    }

    fn set_var_internal(&mut self, space: &Arc<AddressSpace>, offset: i64, size: i32, val: &TaintVec) {
        Base::set_var_internal(self, space, offset, size, val);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> TaintVec {
        Base::get_var_abstract(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        reason: Reason,
    ) -> TaintVec {
        Base::get_var_internal_abstract(self, space, offset, size, reason)
    }

    fn get_var(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, quantize: bool, reason: Reason) -> TaintVec {
        Base::get_var(self, space, offset, size, quantize, reason)
    }

    fn get_var_internal(&self, space: &Arc<AddressSpace>, offset: i64, size: i32, reason: Reason) -> TaintVec {
        Base::get_var_internal(self, space, offset, size, reason)
    }

    /// Port of `getNextEntryInternal(AddressSpace, long)`: `None` if the space has no storage yet,
    /// otherwise [`TaintSpace::get_next_entry`].
    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, TaintVec)> {
        self.get_for_space(space)?.get_next_entry(offset, self)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, TaintVec)> {
        Base::get_register_values(self)
    }

    /// Taint cannot be made concrete. Java throws `ConcretionError("Cannot make Taint concrete",
    /// purpose)`; the ported trait method is infallible, so this panics with that error.
    fn get_concrete_buffer(&self, _address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        panic!("{}", ConcretionError::new("Cannot make Taint concrete", purpose));
    }

    /// Port of `clear()`: clear every taint space, keeping the spaces themselves.
    fn clear(&mut self) {
        for space in self.space_map.values_mut() {
            space.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::taint::model::{TaintMark, TaintSet};
    use crate::pcode::emu::taint::state::test_support::{
        new_piece, ram_space, register_space, unique_space, BytesArithmetic, MockLanguage,
        RecordingCallbacks,
    };
    use crate::program::model::lang::endian::Endian;

    fn mark(name: &str) -> TaintSet {
        TaintSet::of([TaintMark::new(name, std::iter::empty::<String>())])
    }

    fn vec_of(names: &[&str]) -> TaintVec {
        let mut v = TaintVec::new(names.len());
        for (i, n) in names.iter().enumerate() {
            v.set(i, mark(n));
        }
        v
    }

    #[test]
    fn set_var_stores_through_a_lazily_created_space_and_reports_data_written() {
        let cb = Arc::new(RecordingCallbacks::default());
        let mut piece = new_piece(Arc::clone(&cb));
        let ram = ram_space();
        assert!(piece.get_for_space(&ram).is_none());

        piece.set_var(&ram, 0x1000, 2, false, &vec_of(&["a", "b"]));

        assert!(piece.get_for_space(&ram).is_some());
        assert_eq!(piece.get_var(&ram, 0x1000, 2, false, Reason::ExecuteRead).to_display(), "[a][b]");
        // Java: TaintSpace.set ends with cb.dataWritten(piece, space.getAddress(offset), length, val).
        assert_eq!(cb.writes.borrow().as_slice(), &[("ram".to_string(), 0x1000, 2)]);
    }

    #[test]
    fn set_var_internal_writes_without_callbacks() {
        let cb = Arc::new(RecordingCallbacks::default());
        let mut piece = new_piece(Arc::clone(&cb));

        piece.set_var_internal(&ram_space(), 0x10, 1, &vec_of(&["a"]));

        assert_eq!(piece.get_var_internal(&ram_space(), 0x10, 1, Reason::Inspect).to_display(), "[a]");
        assert!(cb.writes.borrow().is_empty());
    }

    #[test]
    fn reading_a_space_that_does_not_exist_reads_empty_taint() {
        let cb = Arc::new(RecordingCallbacks::default());
        let piece = new_piece(Arc::clone(&cb));

        // No TaintSpace exists yet: the base asks the callbacks about the whole range once, then
        // falls back to getFromNullSpace, i.e. arithmetic.fromConst(0, size): all empty sets.
        let v = piece.get_var(&ram_space(), 0x1000, 4, false, Reason::ExecuteRead);
        assert_eq!(v.to_display(), "[][][][]");
        assert_eq!(cb.reads.borrow().as_slice(), &[("ram".to_string(), 0x1000, 4)]);
    }

    #[test]
    fn reading_unset_offsets_of_an_existing_space_asks_the_callbacks_byte_by_byte() {
        let cb = Arc::new(RecordingCallbacks::default());
        let mut piece = new_piece(Arc::clone(&cb));
        piece.set_var(&ram_space(), 0x1000, 1, false, &vec_of(&["a"]));

        let v = piece.get_var(&ram_space(), 0x1000, 3, false, Reason::ExecuteRead);

        assert_eq!(v.to_display(), "[a][][]");
        assert_eq!(
            cb.reads.borrow().as_slice(),
            &[("ram".to_string(), 0x1001, 1), ("ram".to_string(), 0x1002, 1)]
        );
    }

    #[test]
    fn unique_space_round_trips() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));

        piece.set_var(&unique_space(), 0x80, 2, false, &vec_of(&["u", "v"]));

        assert_eq!(piece.get_var(&unique_space(), 0x80, 2, false, Reason::ExecuteRead).to_display(), "[u][v]");
    }

    #[test]
    fn abstract_offsets_are_concrete_little_endian_bytes() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));
        let offset = vec![0x00, 0x20, 0x00, 0x00];

        piece.set_var_abstract(&ram_space(), &offset, 1, false, &vec_of(&["x"]));

        assert_eq!(piece.get_var(&ram_space(), 0x2000, 1, false, Reason::Inspect).to_display(), "[x]");
    }

    #[test]
    fn get_next_entry_internal_is_none_until_the_space_exists() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));
        assert!(piece.get_next_entry_internal(&ram_space(), 0).is_none());

        piece.set_var(&ram_space(), 0x40, 2, false, &vec_of(&["a", "b"]));

        let (offset, v) = piece.get_next_entry_internal(&ram_space(), 0).expect("an entry");
        assert_eq!(offset, 0x40);
        assert_eq!(v.to_display(), "[a][b]");
        assert!(piece.get_next_entry_internal(&register_space(), 0).is_none());
    }

    #[test]
    fn clear_empties_every_space_but_keeps_it() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));
        piece.set_var(&ram_space(), 0x40, 1, false, &vec_of(&["a"]));
        piece.set_var(&register_space(), 0x0, 1, false, &vec_of(&["r"]));

        piece.clear();

        assert!(piece.get_for_space(&ram_space()).is_some());
        assert!(piece.get_next_entry_internal(&ram_space(), 0).is_none());
        assert!(piece.get_next_entry_internal(&register_space(), 0).is_none());
        assert_eq!(piece.get_var_internal(&ram_space(), 0x40, 1, Reason::Inspect).to_display(), "[]");
    }

    #[test]
    fn register_values_cover_registers_whose_space_exists() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));
        assert!(piece.get_register_values().is_empty());

        piece.set_var(&register_space(), 0x0, 4, false, &vec_of(&["a", "b", "c", "d"]));
        let values = piece.get_register_values();

        // Both mock registers live in the register space; TaintSpace.getRegisterValues sizes each
        // vector to the register but (as in Java) leaves its sets empty.
        let shown: Vec<(String, String)> =
            values.iter().map(|(r, v)| (r.name().to_string(), v.to_display())).collect();
        assert_eq!(
            shown,
            vec![
                ("R0".to_string(), "[][][][]".to_string()),
                ("R1".to_string(), "[][]".to_string()),
            ]
        );
    }

    #[test]
    fn value_arithmetic_follows_the_language_endianness() {
        let piece = new_piece(Arc::new(RecordingCallbacks::default()));
        assert_eq!(piece.get_arithmetic().get_endian(), Some(Endian::Little));
        assert_eq!(piece.get_arithmetic().get_domain(), "TaintVec");
        assert_eq!(piece.get_address_arithmetic().get_endian(), Some(Endian::Little));
    }

    #[test]
    fn with_arithmetic_uses_the_given_value_arithmetic() {
        let piece = TaintPcodeExecutorStatePiece::with_arithmetic(
            Arc::new(MockLanguage),
            Arc::new(BytesArithmetic),
            Arc::new(TaintPcodeArithmetic::BigEndian),
            Arc::new(RecordingCallbacks::default()),
        );
        assert_eq!(piece.get_arithmetic().get_endian(), Some(Endian::Big));
    }

    #[test]
    fn get_language_returns_the_constructing_language() {
        let piece = new_piece(Arc::new(RecordingCallbacks::default()));
        let language = piece.get_language();
        assert_eq!(language.get_version(), 7);
        assert_eq!(language.get_minor_version(), 3);
        assert_eq!(language.get_register_names(), vec!["R0".to_string(), "R1".to_string()]);
    }

    #[test]
    fn stream_pieces_yields_just_this_piece() {
        let piece = new_piece(Arc::new(RecordingCallbacks::default()));
        assert_eq!(piece.stream_pieces().len(), 1);
    }

    #[test]
    #[should_panic(expected = "Cannot make Taint concrete")]
    fn taint_cannot_be_made_concrete() {
        let piece = new_piece(Arc::new(RecordingCallbacks::default()));
        let _ = piece.get_concrete_buffer(&ram_space().address(0), Purpose::Load);
    }

    #[test]
    #[should_panic(expected = "Value is larger than variable")]
    fn values_larger_than_the_variable_are_rejected() {
        let mut piece = new_piece(Arc::new(RecordingCallbacks::default()));
        piece.set_var(&ram_space(), 0x0, 1, false, &vec_of(&["a", "b"]));
    }
}
