//! Port of `ghidra.pcode.emu.symz3.state.SymZ3Space`.

use crate::feature::seam_stubs::Z3Context;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;

/// The storage space for symbolic values.
///
/// Port of the abstract class `ghidra.pcode.emu.symz3.state.SymZ3Space`. Java's abstract class has
/// no fields or concrete methods of its own -- every member is `abstract` -- so, following this
/// crate's composition-over-inheritance convention, this becomes a plain trait rather than a
/// struct with a `base` field.
///
/// This is the actual implementation of the in-memory storage for symbolic z3 values. For a
/// stand-alone emulator, this is the full state. For a trace- or Debugger-integrated emulator,
/// this is a cache of values loaded from a trace backing this emulator. Most likely, that trace is
/// the user's current trace.
///
/// # Deviations from Java
///
/// * [`PcodeStateCallbacks`] has generic methods and so is not object-safe (see that trait's own
///   docs); [`SymZ3Space::set`]/[`SymZ3Space::get`] take it as a generic `CB` parameter instead of
///   `&dyn PcodeStateCallbacks`, matching the convention already used by
///   [`AuxEmulatorPartsFactory`](crate::pcode::emu::auxiliary::AuxEmulatorPartsFactory)'s
///   `create_shared_state`/`create_local_state`. This makes `SymZ3Space` itself not object-safe
///   either (there is no valid `&dyn SymZ3Space`), same as that trait.
/// * Java's `Stream<Map.Entry<String, String>> streamValuations(...)` is rendered as an eagerly
///   collected `Vec<(String, String)>`; nothing in this crate's ports of `Stream`-returning Java
///   methods (e.g.
///   [`SymValueZ3`](crate::feature::symz3::model::sym_value_z3::SymValueZ3)'s callers) has needed
///   Java's laziness.
pub trait SymZ3Space {
    /// Store a symbolic value at the given (symbolic) offset.
    ///
    /// Port of `set(SymValueZ3, int, SymValueZ3, PcodeStateCallbacks)`.
    fn set<CB: PcodeStateCallbacks>(
        &mut self,
        offset: &SymValueZ3,
        size: i32,
        val: &SymValueZ3,
        cb: &CB,
    );

    /// Load a symbolic value from the given (symbolic) offset.
    ///
    /// Port of `get(SymValueZ3, int, Reason, PcodeStateCallbacks)`.
    fn get<CB: PcodeStateCallbacks>(
        &self,
        offset: &SymValueZ3,
        size: i32,
        reason: Reason,
        cb: &CB,
    ) -> SymValueZ3;

    /// A human-readable summary of this space's contents.
    ///
    /// Port of `printableSummary()`.
    fn printable_summary(&self) -> String;

    /// The (name, printable value) pairs for every valuation this space holds.
    ///
    /// Port of `streamValuations(Context, Z3InfixPrinter)`. See the trait docs for why this
    /// returns a `Vec` rather than a lazy stream.
    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)>;

    /// The entry (by symbolic-memory offset) at or after the given offset, if any.
    ///
    /// Port of `getNextEntry(long)`.
    fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use std::collections::BTreeMap;

    /// A minimal, real `SymZ3Space` implementor: keys symbolic offsets by their serialized form
    /// (this crate's `SymValueZ3` has no numeric identity outside of Z3, so a byte-offset-indexed
    /// backing store -- what a real implementation would use -- is out of scope here; this is
    /// enough to prove the trait's shape and default-free method set are usable).
    #[derive(Default)]
    struct FlatSpace {
        cells: BTreeMap<String, SymValueZ3>,
    }

    impl SymZ3Space for FlatSpace {
        fn set<CB: PcodeStateCallbacks>(
            &mut self,
            offset: &SymValueZ3,
            _size: i32,
            val: &SymValueZ3,
            _cb: &CB,
        ) {
            let key = offset.serialize().unwrap_or_default();
            self.cells.insert(key, val.clone());
        }

        fn get<CB: PcodeStateCallbacks>(
            &self,
            offset: &SymValueZ3,
            _size: i32,
            _reason: Reason,
            _cb: &CB,
        ) -> SymValueZ3 {
            let key = offset.serialize().unwrap_or_default();
            self.cells.get(&key).cloned().unwrap_or_default()
        }

        fn printable_summary(&self) -> String {
            format!("{} cell(s)", self.cells.len())
        }

        fn stream_valuations(
            &self,
            _ctx: &dyn Z3Context,
            _z3p: &Z3InfixPrinter,
        ) -> Vec<(String, String)> {
            self.cells.iter().map(|(k, v)| (k.clone(), v.serialize().unwrap_or_default())).collect()
        }

        fn get_next_entry(&self, _offset: i64) -> Option<(i64, SymValueZ3)> {
            None
        }
    }

    fn addr(tag: &str) -> SymValueZ3 {
        SymValueZ3::parse(&format!("B:bool;{tag}:::::")).expect("well-formed serialization")
    }

    #[test]
    fn set_then_get_round_trips_through_the_same_offset() {
        let mut space = FlatSpace::default();
        let offset = addr("off1");
        let value = addr("val1");

        space.set(&offset, 4, &value, &NONE);
        let got = space.get(&offset, 4, Reason::ExecuteRead, &NONE);

        assert_eq!(got, value);
    }

    #[test]
    fn get_of_an_unset_offset_is_the_default_value() {
        let space = FlatSpace::default();
        let offset = addr("nope");

        assert_eq!(space.get(&offset, 4, Reason::ExecuteRead, &NONE), SymValueZ3::default());
    }

    #[test]
    fn printable_summary_reflects_the_number_of_stored_cells() {
        let mut space = FlatSpace::default();
        assert_eq!(space.printable_summary(), "0 cell(s)");

        space.set(&addr("a"), 1, &addr("1"), &NONE);
        space.set(&addr("b"), 1, &addr("2"), &NONE);
        assert_eq!(space.printable_summary(), "2 cell(s)");
    }

    #[test]
    fn get_next_entry_default_double_is_unimplemented_by_this_flat_test_space() {
        let space = FlatSpace::default();
        assert_eq!(space.get_next_entry(0), None);
    }

    #[test]
    fn stream_valuations_is_object_free_and_reflects_all_entries() {
        // `FlatSpace::stream_valuations` never actually calls `ctx`/`z3p` (a real
        // implementation, unlike this test double, would use them to render each valuation), so
        // a `Z3Context` that panics on every method suffices here -- it only needs to exist to
        // satisfy the trait's signature.
        struct UnusedCtx;
        impl Z3Context for UnusedCtx {
            fn smt_lib_for_bit_vec(&self, _b: &dyn crate::feature::seam_stubs::BitVecExpr) -> String {
                unimplemented!()
            }
            fn smt_lib_for_bool(&self, _b: &dyn crate::feature::seam_stubs::BoolExpr) -> String {
                unimplemented!()
            }
            fn parse_smt_lib2(&self, _smt: &str) -> Option<Box<dyn crate::feature::seam_stubs::BoolExpr>> {
                unimplemented!()
            }
            fn mk_bv(&self, _value: i64, _size_bits: u32) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bv_const(&self, _name: &str, _size_bits: u32) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_true(&self) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_false(&self) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_eq(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_ite_bv(
                &self,
                _predicate: &dyn crate::feature::seam_stubs::BoolExpr,
                _t: &dyn crate::feature::seam_stubs::BitVecExpr,
                _f: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_ite_bool(
                &self,
                _predicate: &dyn crate::feature::seam_stubs::BoolExpr,
                _t: &dyn crate::feature::seam_stubs::BoolExpr,
                _f: &dyn crate::feature::seam_stubs::BoolExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bvslt(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bvsle(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bvult(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bvule(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bv_add_no_overflow(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
                _signed: bool,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bv_sub_no_overflow(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_bvadd(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvsub(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvxor(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvand(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvor(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvmul(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvudiv(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvsdiv(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvshl(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvlshr(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_bvashr(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_concat(
                &self,
                _l: &dyn crate::feature::seam_stubs::BitVecExpr,
                _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_zero_ext(
                &self,
                _bits: u32,
                _b: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_sign_ext(
                &self,
                _bits: u32,
                _b: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_extract(
                &self,
                _high: u32,
                _low: u32,
                _b: &dyn crate::feature::seam_stubs::BitVecExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
                unimplemented!()
            }
            fn mk_not(&self, _u: &dyn crate::feature::seam_stubs::BoolExpr) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_xor(
                &self,
                _l: &dyn crate::feature::seam_stubs::BoolExpr,
                _r: &dyn crate::feature::seam_stubs::BoolExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_and(
                &self,
                _l: &dyn crate::feature::seam_stubs::BoolExpr,
                _r: &dyn crate::feature::seam_stubs::BoolExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
            fn mk_or(
                &self,
                _l: &dyn crate::feature::seam_stubs::BoolExpr,
                _r: &dyn crate::feature::seam_stubs::BoolExpr,
            ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
                unimplemented!()
            }
        }

        let mut space = FlatSpace::default();
        space.set(&addr("a"), 1, &addr("1"), &NONE);
        space.set(&addr("b"), 1, &addr("2"), &NONE);

        let ctx = UnusedCtx;
        let printer = Z3InfixPrinter::new(std::sync::Arc::new(UnusedCtx));
        let valuations = space.stream_valuations(&ctx, &printer);

        assert_eq!(valuations.len(), 2);
    }
}
