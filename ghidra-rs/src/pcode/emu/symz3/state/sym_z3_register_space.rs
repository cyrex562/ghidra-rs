//! Port of `ghidra.pcode.emu.symz3.state.SymZ3RegisterSpace`.
//!
//! The storage space for registers in a [`SymZ3PcodeExecutorStatePiece`]: a
//! [`SymZ3RegisterMap`] addressed by the language's registers.
//!
//! # Deviations from Java
//!
//! * **Callbacks.** Java's space holds a back-reference to its owning piece so it can report
//!   `cb.dataWritten(piece, ...)`/`cb.readUninitialized(piece, ...)`. The piece owns its spaces,
//!   so a space cannot also refer back to it; the owning
//!   [`SymZ3PcodeExecutorStatePiece`] fires those two callbacks itself, around the call into this
//!   space, at the same points Java's space does (after a write; before a read of a register with
//!   no value, see [`SymZ3RegisterSpace::has_value_for`]). The `cb` parameter of the
//!   [`SymZ3Space`] methods is therefore unused here.
//! * **`Context`.** Java's register map opens its own `new Context()` wherever it needs one; as
//!   for [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace),
//!   this space holds the context it was built with.
//! * **Reads mutate.** Java's `SymZ3RegisterMap.getRegister` records the register as read and may
//!   materialize a fresh symbolic value for it, all behind [`SymZ3Space::get`]'s non-mutating
//!   signature. The map is kept behind a [`Mutex`] so a read can do the same.
//! * **Unknown registers.** Java's `get` returns `null` for an offset that names no register;
//!   [`SymZ3Space::get`] returns an owned value, so this returns [`SymValueZ3::default`] (no
//!   expression), as [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace)
//!   does for an unwritten unique.
//!
//! [`SymZ3PcodeExecutorStatePiece`]: crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece

use std::sync::{Arc, Mutex, MutexGuard};

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space;
use crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::util::msg::Msg;

/// The storage space for registers.
///
/// Port of `ghidra.pcode.emu.symz3.state.SymZ3RegisterSpace`. See the module docs.
pub struct SymZ3RegisterSpace {
    rmap: Mutex<SymZ3RegisterMap>,
    language: Arc<dyn Language>,
    space: Arc<AddressSpace>,
    ctx: Arc<dyn Z3Context>,
}

impl SymZ3RegisterSpace {
    /// Construct the register space for the given language's register space.
    ///
    /// Port of `SymZ3RegisterSpace(Language, AddressSpace, AbstractSymZ3OffsetPcodeExecutorStatePiece)`;
    /// the piece is not held (see the module docs), and `ctx` stands for Java's per-use contexts.
    pub fn new(language: Arc<dyn Language>, space: Arc<AddressSpace>, ctx: Arc<dyn Z3Context>) -> Self {
        Self { rmap: Mutex::new(SymZ3RegisterMap::new()), language, space, ctx }
    }

    /// The address space this stores.
    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    fn rmap(&self) -> MutexGuard<'_, SymZ3RegisterMap> {
        self.rmap.lock().expect("register map lock poisoned")
    }

    /// Port of the private `getRegister(SymValueZ3, int)`.
    ///
    /// # Panics
    ///
    /// If `offset` is symbolic, as Java throws `AssertionError("getRegister was given a symbolic
    /// register, should not be possible")`.
    fn get_register(&self, offset: &SymValueZ3, size: i32) -> Option<RegisterRef> {
        let Some(offset_long) = offset.to_long(&*self.ctx) else {
            panic!("getRegister was given a symbolic register, should not be possible");
        };
        self.language.get_register_in_space(&self.space, offset_long, size)
    }

    /// Whether the register at `offset` has a value, i.e., whether Java's `get` would *not* report
    /// `readUninitialized` for it. `false` for an offset that names no register, for which Java
    /// returns before consulting the callbacks.
    ///
    /// This is the condition the owning piece checks before firing that callback; see the module
    /// docs.
    pub fn has_value_for(&self, offset: &SymValueZ3, size: i32) -> Option<bool> {
        let r = self.get_register(offset, size)?;
        Some(self.rmap().has_value_for_register(&r))
    }
}

impl SymZ3Space for SymZ3RegisterSpace {
    /// Port of the overridden `set(SymValueZ3, int, SymValueZ3, PcodeStateCallbacks)`. The
    /// owning piece reports `dataWritten`; see the module docs.
    fn set<CB: PcodeStateCallbacks>(&mut self, offset: &SymValueZ3, size: i32, val: &SymValueZ3, _cb: &CB) {
        let Some(r) = self.get_register(offset, size) else {
            Msg::warn(
                "SymZ3RegisterSpace",
                &format!(
                    "set is ignoring set register with offset: {offset} and size: {size} to: {val}"
                ),
            );
            return;
        };
        let ctx = Arc::clone(&self.ctx);
        self.rmap().update_register(&*ctx, &r, val);
    }

    /// Port of the overridden `get(SymValueZ3, int, Reason, PcodeStateCallbacks)`. The owning
    /// piece reports `readUninitialized`; see the module docs.
    fn get<CB: PcodeStateCallbacks>(&self, offset: &SymValueZ3, size: i32, _reason: Reason, _cb: &CB) -> SymValueZ3 {
        let Some(r) = self.get_register(offset, size) else {
            Msg::warn(
                "SymZ3RegisterSpace",
                &format!(
                    "unable to get register with space: {} offset_long: {offset} size: {size}",
                    self.space.space_id()
                ),
            );
            return SymValueZ3::default();
        };
        self.rmap().get_register(&*self.ctx, &r)
    }

    /// Port of the overridden `printableSummary()`.
    fn printable_summary(&self) -> String {
        let z3p = Z3InfixPrinter::new(Arc::clone(&self.ctx));
        self.rmap().printable_summary(&*self.ctx, &z3p)
    }

    /// Port of the overridden `streamValuations(Context, Z3InfixPrinter)`.
    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        self.rmap().stream_valuations(ctx, z3p)
    }

    /// Port of the overridden `getNextEntry(long)`.
    fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)> {
        self.rmap().get_next_entry(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::testing::EvalCtx;
    use crate::pcode::exec::pcode_state_callbacks::NONE;

    fn space() -> SymZ3RegisterSpace {
        let language = decode_tests::language();
        let register = language
            .get_address_factory()
            .get_address_space_by_name("register")
            .expect("the fixture has a register space");
        SymZ3RegisterSpace::new(language as Arc<dyn Language>, register, Arc::new(EvalCtx))
    }

    fn offset(v: i64) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(&EvalCtx, &*EvalCtx.mk_bv(v, 32))
    }

    #[test]
    fn a_register_reads_back_what_was_written() {
        let mut s = space();
        let value = SymValueZ3::from_bit_vec(&EvalCtx, &*EvalCtx.mk_bv(0x2a, 32));
        assert_eq!(s.has_value_for(&offset(4), 4), Some(false));
        s.set(&offset(4), 4, &value, &NONE);
        assert_eq!(s.has_value_for(&offset(4), 4), Some(true));
        assert_eq!(s.get(&offset(4), 4, Reason::Inspect, &NONE).to_long(&EvalCtx), Some(0x2a));
    }

    #[test]
    fn an_unwritten_register_reads_as_its_own_symbol() {
        // Java's SymZ3RegisterMap materializes an unread register as a same-named constant.
        let s = space();
        let r0 = s.get(&offset(0), 4, Reason::Inspect, &NONE);
        let bv = r0.get_bit_vec_expr(&EvalCtx).unwrap();
        assert_eq!(bv.as_expr().to_smt_string(), "r0");
        assert!(s.printable_summary().contains("r0"));
    }

    #[test]
    fn an_offset_naming_no_register_is_ignored() {
        let mut s = space();
        s.set(&offset(0x100), 4, &offset(1), &NONE);
        assert_eq!(s.has_value_for(&offset(0x100), 4), None);
        assert_eq!(s.get(&offset(0x100), 4, Reason::Inspect, &NONE), SymValueZ3::default());
    }

    #[test]
    #[should_panic(expected = "getRegister was given a symbolic register")]
    fn a_symbolic_offset_is_rejected() {
        let s = space();
        let symbolic = SymValueZ3::from_bit_vec(&EvalCtx, &*EvalCtx.mk_bv_const("x", 32));
        s.get(&symbolic, 4, Reason::Inspect, &NONE);
    }

    /// Records the callbacks the owning piece fires for its register and memory spaces.
    #[derive(Default)]
    struct Recording {
        events: Mutex<Vec<String>>,
    }

    impl PcodeStateCallbacks for Recording {
        fn data_written_abstract<A, T>(
            &self,
            _piece: &dyn crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<A, T>,
            space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _value: &T,
        ) {
            self.events.lock().unwrap().push(format!("written {}:{length}", space.name()));
        }

        fn read_uninitialized_abstract<A, T>(
            &self,
            _piece: &dyn crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<A, T>,
            space: &Arc<AddressSpace>,
            _offset: &A,
            length: i32,
            _reason: Reason,
        ) -> i32 {
            self.events.lock().unwrap().push(format!("uninit {}:{length}", space.name()));
            0
        }
    }

    #[test]
    fn the_owning_piece_reports_register_writes_and_uninitialized_reads() {
        use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::SymZ3PcodeArithmetic;
        use crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece;
        use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;

        let language: Arc<dyn Language> = decode_tests::language();
        let register = space().space().clone();
        let arithmetic: Arc<dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<SymValueZ3>> =
            Arc::new(SymZ3PcodeArithmetic::for_language(language.as_ref(), Arc::new(EvalCtx)));
        let cb = Arc::new(Recording::default());
        let mut piece = SymZ3PcodeExecutorStatePiece::new(
            language,
            Arc::clone(&arithmetic),
            arithmetic,
            Arc::clone(&cb),
            Arc::new(EvalCtx),
        );

        // Java's piece answers zero, reporting nothing, for a space it has not created yet.
        let _ = piece.get_var_abstract(&register, &offset(0), 4, false, Reason::Inspect);
        // The write creates the register space, and is reported.
        piece.set_var_abstract(&register, &offset(4), 4, false, &offset(7));
        // Java: SymZ3RegisterSpace.get reports readUninitialized before reading a register with
        // no value (r0), but not one with a value (r1).
        let _ = piece.get_var_abstract(&register, &offset(0), 4, false, Reason::Inspect);
        let _ = piece.get_var_abstract(&register, &offset(4), 4, false, Reason::Inspect);
        assert_eq!(
            *cb.events.lock().unwrap(),
            vec!["written register:4".to_string(), "uninit register:4".to_string()]
        );
    }
}
