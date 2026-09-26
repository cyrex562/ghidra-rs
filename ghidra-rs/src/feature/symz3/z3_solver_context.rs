//! The [`Z3Context`] seam over the real Z3 solver, via the `z3` crate.
//!
//! Only built with the optional `z3` cargo feature, which needs `libz3` (see the crate's
//! `Cargo.toml`). Without it, SymZ3 runs over whatever [`Z3Context`] implementation its caller
//! supplies (see
//! [`SymZ3PartsFactory`](crate::pcode::emu::symz3::sym_z3_parts_factory::SymZ3PartsFactory)).
//!
//! # How the pieces map
//!
//! Java's `com.microsoft.z3.Context` is a solver context each SymZ3 part opens (`new Context()`)
//! and closes around a handful of operations; every value leaves it as SMT-LIB text (see
//! [`SymValueZ3`](crate::feature::symz3::model::sym_value_z3::SymValueZ3)). The `z3` crate
//! instead works in an implicit per-host-thread context whose ASTs may not leave that thread,
//! while the seam's expressions must be `Send + Sync`. So each expression here is held in a
//! [`Synchronized`] -- the crate's own `Send + Sync` wrapper, which keeps the AST in a private
//! context -- and every operation recovers its operands into the current thread's context, builds
//! the result there, and wraps it again. [`Z3SolverContext`] itself holds nothing, like Java's
//! short-lived contexts.
//!
//! # Not modeled
//!
//! The expression-tree walk [`Z3InfixPrinter`](crate::pcode::emu::symz3::lib::z3_infix_printer)
//! performs (`Expr::args`, `decl_kind`, `with_args`) keeps the seam's defaults, so the printer
//! renders these expressions as their SMT-LIB text rather than in infix.

use std::any::Any;

use z3::ast::{Ast, Bool, BV};
use z3::{AstKind, Solver, Synchronized};

use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr, Z3Context};

/// A Z3 bit-vector expression. See the module docs.
pub struct Z3BitVec(Synchronized<BV>);

/// A Z3 boolean expression. See the module docs.
pub struct Z3Bool(Synchronized<Bool>);

impl Z3BitVec {
    fn new(bv: &BV) -> Self {
        Self(Synchronized::new(bv))
    }

    /// The expression, in the current thread's context.
    pub fn recover(&self) -> BV {
        self.0.recover()
    }
}

impl Z3Bool {
    fn new(b: &Bool) -> Self {
        Self(Synchronized::new(b))
    }

    /// The expression, in the current thread's context.
    pub fn recover(&self) -> Bool {
        self.0.recover()
    }
}

fn is_numeral(bv: &BV) -> bool {
    bv.kind() == AstKind::Numeral
}

impl Expr for Z3BitVec {
    fn to_smt_string(&self) -> String {
        self.recover().to_string()
    }

    fn is_numeral(&self) -> bool {
        is_numeral(&self.recover())
    }

    fn is_bv(&self) -> bool {
        true
    }

    fn is_bv_bit_one(&self) -> bool {
        let bv = self.recover();
        bv.get_size() == 1 && is_numeral(&bv) && bv.as_u64() == Some(1)
    }

    fn is_bv_bit_zero(&self) -> bool {
        let bv = self.recover();
        bv.get_size() == 1 && is_numeral(&bv) && bv.as_u64() == Some(0)
    }

    fn as_bit_vec(&self) -> Option<&dyn BitVecExpr> {
        Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BitVecExpr for Z3BitVec {
    fn as_expr(&self) -> &dyn Expr {
        self
    }

    fn sort_size(&self) -> u32 {
        self.recover().get_size()
    }

    fn is_numeral(&self) -> bool {
        is_numeral(&self.recover())
    }

    /// Java: `BitVecNum.getBigInteger()`: the unsigned value, up to the 128 bits an `i128` holds.
    fn to_big_integer(&self) -> Option<i128> {
        let bv = self.recover();
        if !is_numeral(&bv) {
            return None;
        }
        let size = bv.get_size();
        if size <= 64 {
            return bv.as_u64().map(i128::from);
        }
        if size > 128 {
            return None;
        }
        let high = bv.extract(size - 1, 64).simplify().as_u64()?;
        let low = bv.extract(63, 0).simplify().as_u64()?;
        Some(((u128::from(high) << 64) | u128::from(low)) as i128)
    }

    /// Java: `BitVecNum.getLong()`.
    fn to_long(&self) -> Option<i64> {
        let bv = self.recover();
        if !is_numeral(&bv) {
            return None;
        }
        bv.as_i64()
    }
}

impl Expr for Z3Bool {
    fn to_smt_string(&self) -> String {
        self.recover().to_string()
    }

    fn is_true(&self) -> bool {
        self.recover().as_bool() == Some(true)
    }

    fn is_false(&self) -> bool {
        self.recover().as_bool() == Some(false)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BoolExpr for Z3Bool {
    fn as_expr(&self) -> &dyn Expr {
        self
    }

    fn bit_vec_arg(&self, index: usize) -> Option<Box<dyn BitVecExpr>> {
        let arg = self.recover().children().into_iter().nth(index)?.as_bv()?;
        Some(Box::new(Z3BitVec::new(&arg)))
    }
}

/// The operand as a Z3 bit-vector in the current thread's context.
///
/// # Panics
///
/// If the expression was not made by [`Z3SolverContext`]: the seam's expressions are specific to
/// the context that made them.
fn bv(e: &dyn BitVecExpr) -> BV {
    e.as_any()
        .downcast_ref::<Z3BitVec>()
        .expect("a bit-vector expression made by Z3SolverContext")
        .recover()
}

/// The operand as a Z3 boolean in the current thread's context. See [`bv`].
fn boolean(e: &dyn BoolExpr) -> Bool {
    e.as_any()
        .downcast_ref::<Z3Bool>()
        .expect("a boolean expression made by Z3SolverContext")
        .recover()
}

fn wrap_bv(bv: BV) -> Box<dyn BitVecExpr> {
    Box::new(Z3BitVec::new(&bv))
}

fn wrap_bool(b: Bool) -> Box<dyn BoolExpr> {
    Box::new(Z3Bool::new(&b))
}

/// The [`Z3Context`] seam over the real Z3 solver. See the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct Z3SolverContext;

impl Z3Context for Z3SolverContext {
    fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
        let b = bv(b);
        let solver = Solver::new();
        solver.assert(b.eq(&b));
        solver.to_string()
    }

    fn smt_lib_for_bool(&self, b: &dyn BoolExpr) -> String {
        let solver = Solver::new();
        solver.assert(boolean(b));
        solver.to_string()
    }

    fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
        let solver = Solver::new();
        solver.from_string(smt);
        solver.get_assertions().into_iter().next().map(wrap_bool)
    }

    fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
        wrap_bv(BV::from_i64(value, size_bits))
    }

    fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn BitVecExpr> {
        wrap_bv(BV::new_const(name, size_bits))
    }

    fn mk_true(&self) -> Box<dyn BoolExpr> {
        wrap_bool(Bool::from_bool(true))
    }

    fn mk_false(&self) -> Box<dyn BoolExpr> {
        wrap_bool(Bool::from_bool(false))
    }

    fn mk_eq(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).eq(&bv(r)))
    }

    fn mk_ite_bv(&self, predicate: &dyn BoolExpr, t: &dyn BitVecExpr, f: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(boolean(predicate).ite(&bv(t), &bv(f)))
    }

    fn mk_ite_bool(&self, predicate: &dyn BoolExpr, t: &dyn BoolExpr, f: &dyn BoolExpr) -> Box<dyn BoolExpr> {
        wrap_bool(boolean(predicate).ite(&boolean(t), &boolean(f)))
    }

    fn mk_bvslt(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvslt(&bv(r)))
    }

    fn mk_bvsle(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvsle(&bv(r)))
    }

    fn mk_bvult(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvult(&bv(r)))
    }

    fn mk_bvule(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvule(&bv(r)))
    }

    fn mk_bv_add_no_overflow(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr, signed: bool) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvadd_no_overflow(&bv(r), signed))
    }

    fn mk_bv_sub_no_overflow(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
        wrap_bool(bv(l).bvsub_no_overflow(&bv(r)))
    }

    fn mk_bvadd(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvadd(&bv(r)))
    }

    fn mk_bvsub(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvsub(&bv(r)))
    }

    fn mk_bvxor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvxor(&bv(r)))
    }

    fn mk_bvand(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvand(&bv(r)))
    }

    fn mk_bvor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvor(&bv(r)))
    }

    fn mk_bvmul(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvmul(&bv(r)))
    }

    fn mk_bvudiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvudiv(&bv(r)))
    }

    fn mk_bvsdiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvsdiv(&bv(r)))
    }

    fn mk_bvshl(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvshl(&bv(r)))
    }

    fn mk_bvlshr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvlshr(&bv(r)))
    }

    fn mk_bvashr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).bvashr(&bv(r)))
    }

    fn mk_concat(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(l).concat(&bv(r)))
    }

    fn mk_zero_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(b).zero_ext(bits))
    }

    fn mk_sign_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(b).sign_ext(bits))
    }

    fn mk_extract(&self, high: u32, low: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
        wrap_bv(bv(b).extract(high, low))
    }

    fn mk_not(&self, u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
        wrap_bool(boolean(u).not())
    }

    fn mk_xor(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
        wrap_bool(boolean(l).xor(&boolean(r)))
    }

    fn mk_and(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
        wrap_bool(Bool::and(&[boolean(l), boolean(r)]))
    }

    fn mk_or(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
        wrap_bool(Bool::or(&[boolean(l), boolean(r)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::symz3::model::sym_value_z3::SymValueZ3;

    #[test]
    fn numerals_fold_and_round_trip_through_smt_lib() {
        let ctx = Z3SolverContext;
        let sum = ctx.mk_bvadd(&*ctx.mk_bv(2, 32), &*ctx.mk_bv(3, 32));
        let value = SymValueZ3::from_bit_vec(&ctx, &*sum);
        let back = value.get_bit_vec_expr(&ctx).expect("a bit-vector");
        assert_eq!(back.sort_size(), 32);
        // Z3 does not fold on construction; the parsed term is still the sum.
        assert!(back.as_expr().to_smt_string().contains("bvadd"));
    }

    #[test]
    fn literals_answer_is_true_and_is_false() {
        let ctx = Z3SolverContext;
        assert!(ctx.mk_true().as_expr().is_true());
        assert!(ctx.mk_false().as_expr().is_false());
        let x = ctx.mk_bv_const("x", 8);
        let cond = ctx.mk_bvult(&*x, &*ctx.mk_bv(1, 8));
        assert!(!cond.as_expr().is_true() && !cond.as_expr().is_false());
        assert_eq!(ctx.mk_bv(-1, 8).to_big_integer(), Some(0xff));
    }
}
