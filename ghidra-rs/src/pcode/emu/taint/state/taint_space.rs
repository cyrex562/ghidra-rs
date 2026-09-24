//! Port of `ghidra.pcode.emu.taint.state.TaintSpace`.
//!
//! The storage space for taint sets in a single address space (possibly the register space).
//!
//! This is the actual implementation of the in-memory storage for taint marks. For a stand-alone
//! emulator, this is the full state. For a trace- or Debugger-integrated emulator, this is a cache
//! of taints loaded from a trace backing this emulator (see `TaintPieceHandler`). Most likely, that
//! trace is the user's current trace.
//!
//! # Deviations from Java
//!
//! Java's `TaintSpace` stores a back-reference to the
//! [`TaintPcodeExecutorStatePiece`](super::TaintPcodeExecutorStatePiece) that owns it, used only
//! to name that piece to the [`PcodeStateCallbacks`]. The piece owns its spaces (in a map), so a
//! stored back-reference would be an ownership cycle. Instead, the piece is passed at call time:
//!
//! * The read paths ([`get_into`](TaintSpace::get_into), [`get`](TaintSpace::get),
//!   [`get_next_entry`](TaintSpace::get_next_entry)) take the piece as a `&dyn
//!   PcodeExecutorStatePiece` argument and hand it to `readUninitialized`, exactly where Java
//!   hands over its field.
//! * The write path cannot: the piece is mutably borrowed while one of its spaces is written.
//!   [`set`](TaintSpace::set) therefore only stores the taints, and the owning piece issues Java's
//!   trailing `cb.dataWritten(piece, space.getAddress(offset), val.length, val)` itself, right
//!   after the write returns -- the same event, in the same order, with the same arguments.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::feature::taint::model::{TaintSet, TaintVec};
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::{rng_set, PcodeStateCallbacks, NONE};
use crate::program::model::address::{AddressSetView, AddressSpace};
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::PcodeOp;
use crate::util::math_utilities::MathUtilities;

/// The storage space for taint sets in a single address space.
///
/// Offsets are keyed as unsigned, as Java's `TreeMap<>(Long::compareUnsigned)` orders them: the
/// maps hold `u64` keys converted from Java's `long` offsets.
#[derive(Debug, Clone)]
pub struct TaintSpace {
    space: Arc<AddressSpace>,
    taints: BTreeMap<u64, TaintSet>,
    ops: BTreeMap<u64, PcodeOp>,
}

impl TaintSpace {
    /// Create an empty taint space for the given address space.
    ///
    /// Port of `TaintSpace(AddressSpace, TaintPcodeExecutorStatePiece)`; see the module docs for
    /// why the piece is not stored.
    pub fn new(space: Arc<AddressSpace>) -> Self {
        Self { space, taints: BTreeMap::new(), ops: BTreeMap::new() }
    }

    /// The address space this storage covers.
    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    /// Mark the variable at offset with the given taint sets.
    ///
    /// This marks possibly several offsets, starting at the given offset. The first taint set in
    /// the vector is used to mark the given offset, then each subsequent set marks each subsequent
    /// offset. This is analogous to the manner in which bytes would be "written" from a source
    /// array into concrete state, starting at a given offset.
    ///
    /// The vector's originating op is recorded at `offset`; a vector without one clears any op
    /// previously recorded there, as Java's `ops.put(offset, null)` does. Empty sets are stored
    /// too, so that dumping to a trace clears emptied taints.
    ///
    /// Port of `set(long, TaintVec, PcodeStateCallbacks)`, minus the trailing `dataWritten`
    /// callback, which the owning piece issues (see the module docs).
    pub fn set(&mut self, offset: i64, val: &TaintVec) {
        let key = offset as u64;
        match val.get_originating_op() {
            Some(op) => {
                self.ops.insert(key, op.clone());
            }
            None => {
                self.ops.remove(&key);
            }
        }
        for i in 0..val.length {
            self.taints.insert(key.wrapping_add(i as u64), val.get(i).clone());
        }
    }

    /// Retrieve the taint sets for the variable at the given offset.
    ///
    /// This retrieves as many taint sets as there are elements in the given buffer vector. The
    /// first element becomes the taint set at the given offset, then each subsequent element
    /// becomes the taint set at each subsequent offset until the vector is filled. This is
    /// analogous to the manner in which bytes would be "read" from concrete state, starting at a
    /// given offset, into a destination array.
    ///
    /// Each offset with no stored set is offered to `cb`'s `readUninitialized` (naming `piece` as
    /// the state being read); if the callback reports it initialized, the store is consulted
    /// again. An offset that is still unset reads as the empty set.
    ///
    /// Port of `getInto(long, TaintVec, Reason, PcodeStateCallbacks)`.
    pub fn get_into<C: PcodeStateCallbacks>(
        &self,
        offset: i64,
        buf: &mut TaintVec,
        reason: Reason,
        cb: &C,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, TaintVec>,
    ) {
        let key = offset as u64;
        for i in 0..buf.length {
            let at = key.wrapping_add(i as u64);
            let mut s = self.taints.get(&at);
            if s.is_none() {
                let set = rng_set(&self.space, at as i64, 1);
                if cb.read_uninitialized(piece, &set, reason).is_empty() {
                    s = self.taints.get(&at);
                }
            }
            buf.set(i, s.cloned().unwrap_or_default());
        }
    }

    /// Retrieve the taint sets for the variable at the given offset.
    ///
    /// This works the same as [`get_into`](Self::get_into), but creates a new vector of the given
    /// size, reads the taint sets, and returns the vector.
    ///
    /// Port of `get(long, int, Reason, PcodeStateCallbacks)`.
    pub fn get<C: PcodeStateCallbacks>(
        &self,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, TaintVec>,
    ) -> TaintVec {
        let mut vec = TaintVec::new(size as usize);
        self.get_into(offset, &mut vec, reason, cb, piece);
        vec
    }

    /// Remove every taint set from this space.
    ///
    /// Port of `clear()`. As in Java, recorded originating ops are left in place.
    pub fn clear(&mut self) {
        self.taints.clear();
    }

    /// Get a taint vector for each of the given registers.
    ///
    /// Port of `getRegisterValues(List<Register>)`. Java's loop looks up each register byte's
    /// taint set but never stores it into the vector, so every register maps to a vector of empty
    /// sets sized to the register; this port preserves that observable behavior. Java returns a
    /// `HashMap` keyed by register; the register handle type here has no hash, so this returns
    /// the pairs in the order given.
    pub fn get_register_values(&self, registers: &[RegisterRef]) -> Vec<(RegisterRef, TaintVec)> {
        registers
            .iter()
            .map(|r| {
                let num_bytes = r.borrow().num_bytes();
                (RegisterRef::clone(r), TaintVec::new(num_bytes as usize))
            })
            .collect()
    }

    /// Get the entry of contiguous taint sets starting at or after the given offset.
    ///
    /// Finds the least stored offset not less (unsigned) than `offset`, extends through the run of
    /// consecutively stored offsets, and reads up to 1024 of them (without callbacks) into a
    /// vector carrying the op recorded at the run's start. Returns `None` if nothing is stored at
    /// or after `offset`.
    ///
    /// `piece` is only named to the (no-op) callbacks, as Java's `getInto(..., NONE)` does.
    ///
    /// Port of `getNextEntry(long)`.
    pub fn get_next_entry(
        &self,
        offset: i64,
        piece: &dyn PcodeExecutorStatePiece<Vec<u8>, TaintVec>,
    ) -> Option<(i64, TaintVec)> {
        let (&start, _) = self.taints.range(offset as u64..).next()?;
        let mut end = start;
        while self.taints.contains_key(&end) {
            end = end.wrapping_add(1);
        }
        let len = MathUtilities::unsigned_min_i32_i64(1024, end.wrapping_sub(start) as i64);
        let mut vec = match self.ops.get(&start) {
            Some(op) => TaintVec::new_with_op(len as usize, op.clone()),
            None => TaintVec::new(len as usize),
        };
        self.get_into(start as i64, &mut vec, Reason::Inspect, &NONE, piece);
        Some((start as i64, vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::taint::model::TaintMark;
    use crate::pcode::emu::taint::state::test_support::{new_piece, ram_space, RecordingCallbacks};
    use crate::pcode::emu::taint::state::TaintPcodeExecutorStatePiece;
    use crate::program::model::address::Address;
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    fn mark(name: &str) -> TaintSet {
        TaintSet::of([TaintMark::new(name, std::iter::empty::<String>())])
    }

    fn op(offset: i64) -> PcodeOp {
        PcodeOp::new(OpCode::Copy, SequenceNumber::new(Address::new(ram_space(), offset), 0), vec![], None)
    }

    /// The piece the callbacks are told about; its own state is irrelevant to these tests.
    fn piece() -> TaintPcodeExecutorStatePiece<RecordingCallbacks> {
        new_piece(Arc::new(RecordingCallbacks::default()))
    }

    #[test]
    fn set_marks_consecutive_offsets_and_get_reads_them_back() {
        let piece = piece();
        let cb = RecordingCallbacks::default();
        let mut space = TaintSpace::new(ram_space());

        space.set(0x100, &TaintVec::of(op(0), vec![mark("a"), mark("b")]));

        let v = space.get(0x100, 2, Reason::ExecuteRead, &cb, &piece);
        assert_eq!(v.to_display(), "[a][b]");
        // Both offsets were stored, so the callbacks were never asked to initialize anything.
        assert!(cb.reads.borrow().is_empty());
    }

    #[test]
    fn get_offers_each_missing_offset_to_read_uninitialized_then_reads_empty() {
        let piece = piece();
        let cb = RecordingCallbacks::default();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x100, &TaintVec::of(op(0), vec![mark("a"), mark("b")]));

        // Java: getInto asks readUninitialized about rngSet(space, offset + i, 1) for each unset
        // element; NONE-like callbacks leave it unset, so it reads as TaintSet.EMPTY.
        let v = space.get(0x100, 4, Reason::ExecuteRead, &cb, &piece);
        assert_eq!(v.to_display(), "[a][b][][]");
        assert_eq!(
            cb.reads.borrow().as_slice(),
            &[("ram".to_string(), 0x102, 1), ("ram".to_string(), 0x103, 1)]
        );
    }

    #[test]
    fn empty_sets_are_stored_so_they_overwrite_earlier_taint() {
        let piece = piece();
        let cb = RecordingCallbacks::default();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x10, &TaintVec::of(op(0), vec![mark("a")]));

        space.set(0x10, &TaintVec::empties(1));

        assert_eq!(space.get(0x10, 1, Reason::Inspect, &cb, &piece).to_display(), "[]");
        // The empty set is stored, not dropped: the offset is not uninitialized.
        assert!(cb.reads.borrow().is_empty());
    }

    #[test]
    fn get_next_entry_returns_the_contiguous_run_with_its_originating_op() {
        let piece = piece();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x10, &TaintVec::of(op(0x4000), vec![mark("a"), mark("b"), mark("c")]));
        space.set(0x20, &TaintVec::of(op(0x5000), vec![mark("d")]));

        let (offset, vec) = space.get_next_entry(0x0, &piece).expect("an entry");
        assert_eq!(offset, 0x10);
        assert_eq!(vec.to_display(), "[a][b][c]");
        assert_eq!(vec.get_originating_op(), Some(&op(0x4000)));

        // Starting inside the first run finds the rest of it, which has no op of its own.
        let (offset, vec) = space.get_next_entry(0x11, &piece).expect("an entry");
        assert_eq!(offset, 0x11);
        assert_eq!(vec.to_display(), "[b][c]");
        assert_eq!(vec.get_originating_op(), None);

        let (offset, vec) = space.get_next_entry(0x13, &piece).expect("an entry");
        assert_eq!(offset, 0x20);
        assert_eq!(vec.to_display(), "[d]");

        assert!(space.get_next_entry(0x21, &piece).is_none());
    }

    #[test]
    fn get_next_entry_orders_offsets_unsigned() {
        let piece = piece();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x10, &TaintVec::of(op(0), vec![mark("low")]));
        space.set(i64::MIN, &TaintVec::of(op(0), vec![mark("high")]));

        // Under Long::compareUnsigned, 0x8000_0000_0000_0000 is the greatest key, not the least.
        let (offset, vec) = space.get_next_entry(0x0, &piece).expect("an entry");
        assert_eq!(offset, 0x10);
        assert_eq!(vec.to_display(), "[low]");
        let (offset, vec) = space.get_next_entry(0x11, &piece).expect("an entry");
        assert_eq!(offset, i64::MIN);
        assert_eq!(vec.to_display(), "[high]");
    }

    #[test]
    fn get_next_entry_caps_a_run_at_1024_elements() {
        let piece = piece();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x0, &TaintVec::copies(mark("x"), 1500));

        let (offset, vec) = space.get_next_entry(0x0, &piece).expect("an entry");
        assert_eq!(offset, 0);
        assert_eq!(vec.length, 1024);
        let (offset, vec) = space.get_next_entry(1024, &piece).expect("an entry");
        assert_eq!(offset, 1024);
        assert_eq!(vec.length, 1500 - 1024);
    }

    #[test]
    fn set_without_an_op_clears_the_op_recorded_at_that_offset() {
        let piece = piece();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x10, &TaintVec::of(op(0x4000), vec![mark("a")]));

        // Java: ops.put(offset, null) replaces the earlier op.
        space.set(0x10, &TaintVec::copies(mark("b"), 1));

        let (_, vec) = space.get_next_entry(0x10, &piece).expect("an entry");
        assert_eq!(vec.to_display(), "[b]");
        assert_eq!(vec.get_originating_op(), None);
    }

    #[test]
    fn clear_removes_every_taint_set() {
        let piece = piece();
        let mut space = TaintSpace::new(ram_space());
        space.set(0x10, &TaintVec::of(op(0), vec![mark("a")]));

        space.clear();

        assert!(space.get_next_entry(0, &piece).is_none());
    }

    #[test]
    fn get_register_values_yields_an_empty_vector_per_register_as_java_does() {
        use crate::program::model::lang::register::Register;
        use crate::pcode::emu::taint::state::test_support::register_space;

        let mut space = TaintSpace::new(register_space());
        space.set(0x0, &TaintVec::copies(mark("r"), 4));
        let r0 = Register::new("R0", "", register_space().address(0), 4, false, Register::TYPE_NONE);
        let r1 = Register::new("R1", "", register_space().address(4), 2, false, Register::TYPE_NONE);

        let values = space.get_register_values(&[r0, r1]);

        // Java's loop looks each byte up but never stores it, so even R0's vector is empty.
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].0.borrow().name(), "R0");
        assert_eq!(values[0].1.to_display(), "[][][][]");
        assert_eq!(values[1].0.borrow().name(), "R1");
        assert_eq!(values[1].1.to_display(), "[][]");
    }
}
