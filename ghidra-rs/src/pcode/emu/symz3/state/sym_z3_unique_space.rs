//! Port of `ghidra.pcode.emu.symz3.state.SymZ3UniqueSpace`.
//!
//! The storage space for unique registers.
//!
//! This is the actual implementation of the in-memory storage for symbolic z3 values. For a
//! stand-alone emulator, this is the full state. For a trace- or Debugger-integrated emulator,
//! this is a cache of values loaded from a trace backing this emulator. Most likely, that trace is
//! the user's current trace.
//!
//! # Deviations from Java
//!
//! * Java's `set(SymValueZ3, int, SymValueZ3, PcodeStateCallbacks)`/`get(SymValueZ3, int, Reason,
//!   PcodeStateCallbacks)` (the [`SymZ3Space`] trait methods this implements) each open their own
//!   `try (Context ctx = new Context())` to decode `offset` into a numeric key. The
//!   [`SymZ3Space`] trait itself (already ported) takes no `ctx` parameter on these methods --
//!   unlike, e.g.,
//!   [`SymZ3RegisterMap`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap), which
//!   isn't a trait implementor and so is free to add `ctx` as an explicit parameter everywhere --
//!   so [`SymZ3UniqueSpace`] instead holds its own `ctx: Arc<dyn Z3Context>`, injected at
//!   construction, standing in for Java's own `new Context()`. This mirrors the same
//!   constructor-injection pattern already used by
//!   [`Z3InfixPrinter`](crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter) (which
//!   faces the identical "Java opens its own Context inline" problem).
//! * Java's `uniqvals` is a `TreeMap<Long, SymValueZ3>` with no explicit comparator, i.e. natural
//!   (signed) `Long` ordering -- unlike, e.g.,
//!   [`SymZ3MemoryMap`](crate::pcode::emu::symz3::sym_z3_memory_map::SymZ3MemoryMap)'s `byOffset`,
//!   which explicitly uses `Long::compareUnsigned`. Rust's `BTreeMap<i64, _>` already orders keys
//!   by signed comparison, so this is a direct, no-adaptation-needed match.
//! * `set(long, int, SymValueZ3)`/`get(long, int)` accept a `size` Java never actually reads in
//!   either method body (both ignore it entirely, delegating straight to `updateUnique`/
//!   `getUnique`); this port keeps the parameter, unused, for signature parity.
//! * The trait's `SymZ3Space::get` must return an owned `SymValueZ3` (not `Option`), so a missing
//!   entry there falls back to [`SymValueZ3::default`] -- the same substitution
//!   [`SymZ3Space`]'s own module docs and test double already establish for a trait implementor
//!   backed by a possibly-absent value, standing in for Java's `null`. The *inherent*
//!   [`SymZ3UniqueSpace::get`]/[`SymZ3UniqueSpace::get_unique`] methods instead return
//!   `Option<SymValueZ3>`, faithfully matching `Map.get`'s own possibly-`null` Java return.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::feature::seam_stubs::{BitVecExpr, Z3Context};
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;

/// The storage space for unique registers.
///
/// Port of `ghidra.pcode.emu.symz3.state.SymZ3UniqueSpace`. See the module docs for why this
/// holds its own `ctx` rather than taking one per call.
pub struct SymZ3UniqueSpace {
    ctx: Arc<dyn Z3Context>,
    uniqvals: BTreeMap<i64, SymValueZ3>,
}

impl SymZ3UniqueSpace {
    /// Construct an empty unique-register space using the given Z3 context.
    pub fn new(ctx: Arc<dyn Z3Context>) -> Self {
        Self { ctx, uniqvals: BTreeMap::new() }
    }

    /// Port of `set(long, int, SymValueZ3)`. `size` is unused; see the module docs.
    pub fn set(&mut self, offset: i64, _size: i32, val: SymValueZ3) {
        self.update_unique(offset, val);
    }

    /// Port of `get(long, int)`. `size` is unused; see the module docs.
    pub fn get(&self, offset: i64, _size: i32) -> Option<SymValueZ3> {
        self.get_unique(offset)
    }

    /// Port of `updateUnique(long, SymValueZ3)`.
    pub fn update_unique(&mut self, s: i64, value: SymValueZ3) {
        self.uniqvals.insert(s, value);
    }

    /// Port of `getUnique(long)`.
    pub fn get_unique(&self, s: i64) -> Option<SymValueZ3> {
        self.uniqvals.get(&s).cloned()
    }
}

impl SymZ3Space for SymZ3UniqueSpace {
    /// Port of the overridden `set(SymValueZ3, int, SymValueZ3, PcodeStateCallbacks)`.
    ///
    /// # Panics
    ///
    /// If `offset` does not decode to a numeral bit-vector, mirroring Java's
    /// `throw new AssertionError("how can we have a symbolic offset for a unique set:" + ...)`.
    /// Java's own `assert val != null;` precondition has no Rust equivalent to check: `val: &_`
    /// can never be null.
    fn set<CB: PcodeStateCallbacks>(&mut self, offset: &SymValueZ3, size: i32, val: &SymValueZ3, _cb: &CB) {
        let b = offset
            .get_bit_vec_expr(&*self.ctx)
            .expect("Java: unchecked getBitVecExpr(ctx) on the set offset");
        if !BitVecExpr::is_numeral(&*b) {
            panic!(
                "how can we have a symbolic offset for a unique set:{offset}is numeral? {} is BV numeral: {}",
                BitVecExpr::is_numeral(&*b),
                BitVecExpr::is_numeral(&*b),
            );
        }
        let long_val = b.to_long().expect("Java: BitVecNum.getLong() on the numeral offset");
        self.set(long_val, size, val.clone());
    }

    /// Port of the overridden `get(SymValueZ3, int, Reason, PcodeStateCallbacks)`. Falls back to
    /// [`SymValueZ3::default`] for a missing entry; see the module docs for why.
    ///
    /// # Panics
    ///
    /// If `offset` does not decode to a numeral bit-vector, mirroring Java's
    /// `throw new AssertionError("how can we have a symbolic offset for unique get?")`.
    fn get<CB: PcodeStateCallbacks>(
        &self,
        offset: &SymValueZ3,
        size: i32,
        _reason: Reason,
        _cb: &CB,
    ) -> SymValueZ3 {
        let b = offset
            .get_bit_vec_expr(&*self.ctx)
            .expect("Java: unchecked getBitVecExpr(ctx) on the get offset");
        if !BitVecExpr::is_numeral(&*b) {
            panic!("how can we have a symbolic offset for unique get?");
        }
        let long_val = b.to_long().expect("Java: BitVecNum.getLong() on the numeral offset");
        SymZ3UniqueSpace::get(self, long_val, size).unwrap_or_default()
    }

    /// Port of the overridden `printableSummary()`, which always returns the empty string.
    fn printable_summary(&self) -> String {
        String::new()
    }

    /// Port of the overridden `streamValuations(Context, Z3InfixPrinter)`, which always returns
    /// an empty stream.
    fn stream_valuations(
        &self,
        _ctx: &dyn Z3Context,
        _z3p: &crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter,
    ) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Port of the overridden `getNextEntry(long)`.
    fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)> {
        self.uniqvals.range(offset..).next().map(|(k, v)| (*k, v.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr};
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use std::any::Any;

    /// A bit-vector expression carrying its SMT-LIB2 text, size, and (optionally) a numeral
    /// value, mirroring this module family's other `Bv` test doubles.
    #[derive(Clone)]
    struct Bv {
        smt: String,
        size: u32,
        numeral: Option<i64>,
    }

    impl Expr for Bv {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl BitVecExpr for Bv {
        fn as_expr(&self) -> &dyn Expr {
            self
        }
        fn sort_size(&self) -> u32 {
            self.size
        }
        fn is_numeral(&self) -> bool {
            self.numeral.is_some()
        }
        fn to_big_integer(&self) -> Option<i128> {
            self.numeral.map(|v| v as i128)
        }
        fn to_long(&self) -> Option<i64> {
            self.numeral
        }
    }

    #[derive(Clone)]
    struct Bl {
        smt: String,
        arg: Option<Bv>,
    }

    impl Expr for Bl {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl BoolExpr for Bl {
        fn as_expr(&self) -> &dyn Expr {
            self
        }
        fn bit_vec_arg(&self, index: usize) -> Option<Box<dyn BitVecExpr>> {
            match (index, &self.arg) {
                (0, Some(bv)) => Some(Box::new(bv.clone())),
                _ => None,
            }
        }
    }

    /// A `Z3Context` test double round-tripping bit-vector expressions through SMT-LIB2-ish text,
    /// distinguishing numeral (`n;<value>;<size>;<text>`) from symbolic (`s;<size>;<text>`)
    /// constants; only what `SymZ3UniqueSpace` actually exercises is implemented for real.
    struct MockCtx;

    impl MockCtx {
        fn numeral_bv(&self, value: i64, size: u32) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt: format!("#x{:x}", value), size, numeral: Some(value) })
        }
        fn symbolic_bv(&self, name: &str, size: u32) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt: name.to_string(), size, numeral: None })
        }
    }

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
            match b.to_long() {
                Some(v) => format!("n;{};{};{}", v, b.sort_size(), b.as_expr().to_smt_string()),
                None => format!("s;{};{}", b.sort_size(), b.as_expr().to_smt_string()),
            }
        }
        fn smt_lib_for_bool(&self, _b: &dyn BoolExpr) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            let mut parts = smt.splitn(4, ';');
            match parts.next()? {
                "n" => {
                    let value: i64 = parts.next()?.parse().ok()?;
                    let size: u32 = parts.next()?.parse().ok()?;
                    let text = parts.next()?.to_string();
                    let bv = Bv { smt: text.clone(), size, numeral: Some(value) };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", text), arg: Some(bv) }))
                }
                "s" => {
                    let size: u32 = parts.next()?.parse().ok()?;
                    let text = parts.next()?.to_string();
                    let bv = Bv { smt: text.clone(), size, numeral: None };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", text), arg: Some(bv) }))
                }
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.numeral_bv(value, size_bits)
        }
        fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn BitVecExpr> {
            self.symbolic_bv(name, size_bits)
        }
        fn mk_true(&self) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_false(&self) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_eq(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_ite_bv(&self, _p: &dyn BoolExpr, _t: &dyn BitVecExpr, _f: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_ite_bool(&self, _p: &dyn BoolExpr, _t: &dyn BoolExpr, _f: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvslt(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvsle(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvult(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvule(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bv_add_no_overflow(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr, _s: bool) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bv_sub_no_overflow(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvadd(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvsub(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvxor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvand(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvmul(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvudiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvsdiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvshl(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvlshr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bvashr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_concat(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_zero_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_sign_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_extract(&self, _high: u32, _low: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_not(&self, _u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_xor(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_and(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_or(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn numeral_offset(ctx: &MockCtx, value: i64) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(ctx, &*ctx.numeral_bv(value, 64))
    }

    fn symbolic_offset(ctx: &MockCtx, name: &str) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(ctx, &*ctx.symbolic_bv(name, 64))
    }

    #[test]
    fn set_at_then_get_at_round_trips_through_the_same_offset() {
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let value = SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.symbolic_bv("v", 32));

        space.set(0x10, 4, value.clone());

        assert_eq!(space.get(0x10, 4), Some(value));
        assert_eq!(space.get(0x20, 4), None);
    }

    #[test]
    fn update_unique_and_get_unique_are_the_underlying_primitives() {
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let value = SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.symbolic_bv("v", 32));

        space.update_unique(5, value.clone());

        assert_eq!(space.get_unique(5), Some(value));
        assert_eq!(space.get_unique(6), None);
    }

    #[test]
    fn trait_set_decodes_a_numeral_offset_and_stores_by_its_long_value() {
        let ctx = MockCtx;
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let offset = numeral_offset(&ctx, 0x30);
        let value = SymValueZ3::from_bit_vec(&ctx, &*ctx.symbolic_bv("v", 32));

        SymZ3Space::set(&mut space, &offset, 4, &value, &NONE);

        assert_eq!(space.get_unique(0x30), Some(value));
    }

    #[test]
    fn trait_get_of_a_stored_numeral_offset_returns_the_stored_value() {
        let ctx = MockCtx;
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let offset = numeral_offset(&ctx, 0x40);
        let value = SymValueZ3::from_bit_vec(&ctx, &*ctx.symbolic_bv("v", 32));
        space.update_unique(0x40, value.clone());

        let got = SymZ3Space::get(&space, &offset, 4, Reason::ExecuteRead, &NONE);

        assert_eq!(got, value);
    }

    #[test]
    fn trait_get_of_an_unstored_numeral_offset_falls_back_to_the_default_value() {
        let ctx = MockCtx;
        let space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let offset = numeral_offset(&ctx, 0x50);

        let got = SymZ3Space::get(&space, &offset, 4, Reason::ExecuteRead, &NONE);

        assert_eq!(got, SymValueZ3::default());
    }

    #[test]
    #[should_panic(expected = "how can we have a symbolic offset for a unique set:")]
    fn trait_set_panics_on_a_symbolic_offset() {
        let ctx = MockCtx;
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let offset = symbolic_offset(&ctx, "RCX");
        let value = SymValueZ3::from_bit_vec(&ctx, &*ctx.symbolic_bv("v", 32));

        SymZ3Space::set(&mut space, &offset, 4, &value, &NONE);
    }

    #[test]
    #[should_panic(expected = "how can we have a symbolic offset for unique get?")]
    fn trait_get_panics_on_a_symbolic_offset() {
        let ctx = MockCtx;
        let space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        let offset = symbolic_offset(&ctx, "RCX");

        SymZ3Space::get(&space, &offset, 4, Reason::ExecuteRead, &NONE);
    }

    #[test]
    fn printable_summary_is_always_empty() {
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        space.set(1, 4, SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.symbolic_bv("v", 32)));
        assert_eq!(SymZ3Space::printable_summary(&space), "");
    }

    #[test]
    fn stream_valuations_is_always_empty() {
        let ctx = MockCtx;
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        space.set(1, 4, SymValueZ3::from_bit_vec(&ctx, &*ctx.symbolic_bv("v", 32)));
        let printer = crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter::new(Arc::new(MockCtx));

        assert!(SymZ3Space::stream_valuations(&space, &ctx, &printer).is_empty());
    }

    #[test]
    fn get_next_entry_returns_the_ceiling_entry_by_signed_natural_ordering() {
        let mut space = SymZ3UniqueSpace::new(Arc::new(MockCtx));
        space.update_unique(-5, SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.symbolic_bv("a", 8)));
        space.update_unique(10, SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.symbolic_bv("b", 8)));

        // Natural (signed) `Long` ordering, unlike `SymZ3MemoryMap`'s unsigned `byOffset`: -5 is
        // the smallest key here, not the largest.
        let (offset, _) = SymZ3Space::get_next_entry(&space, i64::MIN).expect("an entry exists");
        assert_eq!(offset, -5);

        assert_eq!(SymZ3Space::get_next_entry(&space, 0).unwrap().0, 10);
        assert!(SymZ3Space::get_next_entry(&space, 11).is_none());
    }
}
