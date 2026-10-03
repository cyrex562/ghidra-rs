//! Port of `ghidra.pcode.emu.symz3.state.SymZ3Preconditions`.
//!
//! Store not related to a specific space for the Symbolic Summary Z3.
//!
//! This information is available to any [`SymZ3Space`](super::sym_z3_space::SymZ3Space) and is
//! shared across them.
//!
//! # Deviations from Java
//!
//! * Java's methods that touch Z3 open their own `try (Context ctx = new Context())`; following
//!   the convention already established by
//!   [`SymZ3RegisterMap`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap) (this
//!   crate has no live Z3 binding yet), every Z3-dependent method here takes the context
//!   explicitly instead ([`crate::feature::seam_stubs::Z3Context`]).
//! * `printableSummary()`/`streamPreconditions(...)` call `.simplify()` on the deserialized
//!   boolean expression before printing it. There is no real Z3 engine behind the
//!   [`crate::feature::seam_stubs::Z3Context`] seam to simplify anything with, and no `simplify`
//!   method on the `BoolExpr` seam trait, so this step is not modeled: the raw (unsimplified)
//!   expression is rendered instead, matching the same substitution `SymZ3RegisterMap` already
//!   makes for the same reason.
//! * Despite sharing a same-shaped `getPreconditions()` method with the unrelated interface
//!   [`SymZ3RecordsPreconditions`](crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions),
//!   Java's `SymZ3Preconditions` class does not `implements` that interface, and this port
//!   preserves that: [`SymZ3Preconditions`] does not implement the
//!   [`SymZ3RecordsPreconditions`](crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions)
//!   trait, even though it would trivially satisfy it.

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;

/// Store not related to a specific space for the Symbolic Summary Z3.
///
/// Port of `ghidra.pcode.emu.symz3.state.SymZ3Preconditions`.
#[derive(Debug, Default, Clone)]
pub struct SymZ3Preconditions {
    preconditions: Vec<String>,
}

impl SymZ3Preconditions {
    /// Construct an empty precondition store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `addPrecondition(String)`.
    pub fn add_precondition(&mut self, r: impl Into<String>) {
        self.preconditions.push(r.into());
    }

    /// Port of `printableSummary()`. Takes `ctx`/`z3p` explicitly; see the module docs.
    pub fn printable_summary(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        if self.preconditions.is_empty() {
            return "NO PRECONDITIONS\n".to_string();
        }
        let mut result = String::from("PRECONDITIONS:\n");
        for b in &self.preconditions {
            let be = SymValueZ3::deserialize_bool_expr(ctx, b)
                .expect("Java: unchecked deserializeBoolExpr(ctx, b) on a stored precondition");
            // Java: `be = (BoolExpr) be.simplify();` -- not modeled; see module docs.
            result.push_str(&z3p.infix(be.as_expr()));
            result.push('\n');
        }
        result
    }

    /// Port of `getPreconditions()`. Java returns an unmodifiable *view* of the live list; this
    /// returns an owned copy, matching this crate's established handling of Java's
    /// `Collections.unmodifiableList` elsewhere (e.g.
    /// [`SymZ3RegisterMap::get_register_names_read`](crate::pcode::emu::symz3::sym_z3_register_map::SymZ3RegisterMap::get_register_names_read)).
    pub fn get_preconditions(&self) -> Vec<String> {
        self.preconditions.clone()
    }

    /// Port of `streamPreconditions(Context, Z3InfixPrinter)`. Returns a `Vec` rather than a lazy
    /// stream; see
    /// [`SymZ3Space::stream_valuations`](super::sym_z3_space::SymZ3Space::stream_valuations)'s
    /// docs for why this crate makes the same substitution elsewhere.
    pub fn stream_preconditions(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<String> {
        self.preconditions
            .iter()
            .map(|b| {
                let be = SymValueZ3::deserialize_bool_expr(ctx, b)
                    .expect("Java: unchecked deserializeBoolExpr(ctx, b) on a stored precondition");
                // Java: `z3p.infix(be.simplify())` -- simplify not modeled; see module docs.
                z3p.infix(be.as_expr())
            })
            .collect()
    }

    /// Port of `clear()`.
    pub fn clear(&mut self) {
        self.preconditions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr};
    use std::any::Any;
    use std::sync::Arc;

    /// A minimal boolean expression carrying its SMT-LIB2 text, mirroring the `Bl` test doubles
    /// already established elsewhere in this module family (e.g. `sym_z3_register_map`'s own
    /// tests).
    #[derive(Clone)]
    struct Bl {
        smt: String,
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
        fn bit_vec_arg(&self, _index: usize) -> Option<Box<dyn BitVecExpr>> {
            None
        }
    }

    /// A `Z3Context` test double that round-trips a boolean expression's SMT-LIB2 text through
    /// `parse_smt_lib2`; only the operations `SymZ3Preconditions` actually exercises are
    /// implemented for real, following the same convention as this module family's other tests.
    struct MockCtx;

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, _b: &dyn BitVecExpr) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn smt_lib_for_bool(&self, b: &dyn BoolExpr) -> String {
            b.as_expr().to_smt_string()
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            Some(Box::new(Bl { smt: smt.to_string() }))
        }
        fn mk_bv(&self, _value: i64, _size_bits: u32) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_bv_const(&self, _name: &str, _size_bits: u32) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
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
        fn mk_ite_bv(
            &self,
            _p: &dyn BoolExpr,
            _t: &dyn BitVecExpr,
            _f: &dyn BitVecExpr,
        ) -> Box<dyn BitVecExpr> {
            unimplemented!("not exercised by these tests")
        }
        fn mk_ite_bool(
            &self,
            _p: &dyn BoolExpr,
            _t: &dyn BoolExpr,
            _f: &dyn BoolExpr,
        ) -> Box<dyn BoolExpr> {
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
        fn mk_bv_add_no_overflow(
            &self,
            _l: &dyn BitVecExpr,
            _r: &dyn BitVecExpr,
            _s: bool,
        ) -> Box<dyn BoolExpr> {
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

    fn precondition(text: &str) -> String {
        SymValueZ3::serialize_bool(&MockCtx, &Bl { smt: text.to_string() })
    }

    #[test]
    fn new_store_has_no_preconditions() {
        let store = SymZ3Preconditions::new();
        assert!(store.get_preconditions().is_empty());
    }

    #[test]
    fn add_precondition_appends_in_order() {
        let mut store = SymZ3Preconditions::new();
        store.add_precondition("a");
        store.add_precondition("b");
        assert_eq!(store.get_preconditions(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn clear_empties_the_store() {
        let mut store = SymZ3Preconditions::new();
        store.add_precondition("a");
        store.clear();
        assert!(store.get_preconditions().is_empty());
    }

    #[test]
    fn printable_summary_reports_no_preconditions_when_empty() {
        let store = SymZ3Preconditions::new();
        let printer = Z3InfixPrinter::new(Arc::new(MockCtx));
        assert_eq!(store.printable_summary(&MockCtx, &printer), "NO PRECONDITIONS\n");
    }

    #[test]
    fn printable_summary_lists_each_precondition_infix_rendered() {
        let mut store = SymZ3Preconditions::new();
        store.add_precondition(precondition("(> x 0)"));
        store.add_precondition(precondition("(< y 10)"));

        let printer = Z3InfixPrinter::new(Arc::new(MockCtx));
        let summary = store.printable_summary(&MockCtx, &printer);

        assert!(summary.starts_with("PRECONDITIONS:\n"));
        assert!(summary.contains("(> x 0)"));
        assert!(summary.contains("(< y 10)"));
    }

    #[test]
    fn stream_preconditions_renders_every_stored_precondition() {
        let mut store = SymZ3Preconditions::new();
        store.add_precondition(precondition("(> x 0)"));
        store.add_precondition(precondition("(< y 10)"));

        let printer = Z3InfixPrinter::new(Arc::new(MockCtx));
        let rendered = store.stream_preconditions(&MockCtx, &printer);

        assert_eq!(rendered, vec!["(> x 0)".to_string(), "(< y 10)".to_string()]);
    }

    #[test]
    fn stream_preconditions_of_an_empty_store_is_empty() {
        let store = SymZ3Preconditions::new();
        let printer = Z3InfixPrinter::new(Arc::new(MockCtx));
        assert!(store.stream_preconditions(&MockCtx, &printer).is_empty());
    }
}
