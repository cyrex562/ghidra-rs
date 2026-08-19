//! Port of `ghidra.symz3.model.SymValueZ3`.

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Z3Context, Z3InfixPrinter};
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::Purpose;
use crate::util::msg::Msg;

/// The delimiter separating the boolean and bit-vector halves of a serialized value.
const DELIMITER: &str = ":::::";

/// A symbolic value consisting of a either a Z3 bit-vector expression, and an optional Z3 boolean
/// expression. We could simply always use a bit-vector, but we are hoping to avoid simplification
/// of complex ITE expressions. We explored having the value be either a bit-vector or a boolean,
/// but problems arise when we need to create a new symbolic value for a register like "ZF" that
/// from PCode perspective is a base register with 8 bits. Everything worked pretty much if we just
/// made it a Boolean, but that seems very fragile. Thus, we won't need code to convert from Boolean
/// back to bit-vector, because we will always have a bit-vector.
///
/// # Differences from Java
///
/// Java's methods take a live `com.microsoft.z3.Context`, and the ones that do not (`toString`,
/// `toDisplay`, `toBigInteger`, `toLong`) open a throw-away one via try-with-resources. This crate
/// has no Z3 binding yet, so the Z3 boundary is the [`Z3Context`] seam and every Z3-dependent
/// method takes the context explicitly. That also makes the operations total: where Java would
/// throw (`NullPointerException` on a missing expression, a Z3 parse failure), these return
/// `None`, and where it throws `ConcretionError` the Rust signature says so.
#[derive(Clone, Debug, Default)]
pub struct SymValueZ3 {
    /// The serialized bit-vector expression, `V:` followed by SMT-LIB2 text.
    pub bit_vec_expr_string: Option<String>,
    /// The serialized boolean expression, `B:` followed by SMT-LIB2 text.
    pub bool_expr_string: Option<String>,
}

impl SymValueZ3 {
    /// Serializes a bit-vector expression.
    ///
    /// Serialization is a bit goofy, because we must create a boolean expression; see
    /// <https://github.com/Z3Prover/z3/issues/2674>.
    ///
    /// Java: `serialize(Context, BitVecExpr)`.
    pub fn serialize_bit_vec<C: Z3Context + ?Sized>(ctx: &C, b: &dyn BitVecExpr) -> String {
        format!("V:{}", ctx.smt_lib_for_bit_vec(b))
    }

    /// Java: `serialize(Context, BoolExpr)`.
    pub fn serialize_bool<C: Z3Context + ?Sized>(ctx: &C, b: &dyn BoolExpr) -> String {
        format!("B:{}", ctx.smt_lib_for_bool(b))
    }

    /// Deserializes a value from a string, or `None` if it carries no [`DELIMITER`].
    ///
    /// Java: `parse(String)`, which throws `StringIndexOutOfBoundsException` on a missing
    /// delimiter.
    pub fn parse(serialized: &str) -> Option<Self> {
        let index = serialized.find(DELIMITER)?;
        let left = &serialized[..index];
        let right = &serialized[index + DELIMITER.len()..];
        Some(Self::from_strings(left, right))
    }

    /// Java: the private `SymValueZ3(String be, String bve)`.
    fn from_strings(be: &str, bve: &str) -> Self {
        Self {
            bool_expr_string: (!be.is_empty()).then(|| be.to_string()),
            bit_vec_expr_string: (!bve.is_empty()).then(|| bve.to_string()),
        }
    }

    /// Java: `deserializeBitVecExpr(Context, String)`. Returns `None` if `s` is not a `V:`-tagged
    /// serialization, or if Z3 cannot recover a bit-vector from it.
    pub fn deserialize_bit_vec_expr<C: Z3Context + ?Sized>(
        ctx: &C,
        s: &str,
    ) -> Option<Box<dyn BitVecExpr>> {
        if !s.starts_with('V') {
            return None;
        }
        let f = ctx.parse_smt_lib2(&s[2..])?;
        // The bit-vector was serialized as the trivial assertion `(= b b)`.
        f.bit_vec_arg(0)
    }

    /// Java: `deserializeBoolExpr(Context, String)`. Returns `None` if `s` is not a `B:`-tagged
    /// serialization, or if Z3 cannot parse it.
    pub fn deserialize_bool_expr<C: Z3Context + ?Sized>(
        ctx: &C,
        s: &str,
    ) -> Option<Box<dyn BoolExpr>> {
        if !s.starts_with('B') {
            return None;
        }
        ctx.parse_smt_lib2(&s[2..])
    }

    /// Java: `SymValueZ3(Context, BitVecExpr)`.
    pub fn from_bit_vec<C: Z3Context + ?Sized>(ctx: &C, bve: &dyn BitVecExpr) -> Self {
        Self {
            bit_vec_expr_string: Some(Self::serialize_bit_vec(ctx, bve)),
            bool_expr_string: None,
        }
    }

    /// Java: `SymValueZ3(Context, BitVecExpr, BoolExpr)`.
    pub fn from_bit_vec_and_bool<C: Z3Context + ?Sized>(
        ctx: &C,
        bve: &dyn BitVecExpr,
        be: &dyn BoolExpr,
    ) -> Self {
        Self {
            bit_vec_expr_string: Some(Self::serialize_bit_vec(ctx, bve)),
            bool_expr_string: Some(Self::serialize_bool(ctx, be)),
        }
    }

    /// Java: `getBitVecExpr(Context)`.
    pub fn get_bit_vec_expr<C: Z3Context + ?Sized>(&self, ctx: &C) -> Option<Box<dyn BitVecExpr>> {
        Self::deserialize_bit_vec_expr(ctx, self.bit_vec_expr_string.as_deref()?)
    }

    /// Java: `getBoolExpr(Context)`. With no boolean expression of its own, the bit-vector is
    /// coerced to `ITE(b == 0, false, true)`.
    pub fn get_bool_expr<C: Z3Context + ?Sized>(&self, ctx: &C) -> Option<Box<dyn BoolExpr>> {
        let Some(s) = self.bool_expr_string.as_deref() else {
            let b = self.get_bit_vec_expr(ctx)?;
            let zero = ctx.mk_bv(0, b.sort_size());
            let predicate = ctx.mk_eq(&*b, &*zero);
            return Some(ctx.mk_ite_bool(&*predicate, &*ctx.mk_false(), &*ctx.mk_true()));
        };
        Self::deserialize_bool_expr(ctx, s)
    }

    /// Java: `hasBoolExpr()`.
    pub fn has_bool_expr(&self) -> bool {
        self.bool_expr_string.is_some()
    }

    /// Java: `hasBitVecExpr()`.
    pub fn has_bit_vec_expr(&self) -> bool {
        self.bit_vec_expr_string.is_some()
    }

    /// Java: `toDisplay()`, the infix rendering of the boolean expression if there is one, else of
    /// the bit-vector. Java opens its own `Context`; here both it and the printer are passed in.
    pub fn to_display<C: Z3Context + ?Sized, P: Z3InfixPrinter + ?Sized>(
        &self,
        ctx: &C,
        printer: &P,
    ) -> Option<String> {
        if let Some(s) = self.bool_expr_string.as_deref() {
            let e = Self::deserialize_bool_expr(ctx, s)?;
            return Some(printer.infix(e.as_expr()));
        }
        let e = Self::deserialize_bit_vec_expr(ctx, self.bit_vec_expr_string.as_deref()?)?;
        Some(printer.infix(e.as_expr()))
    }

    /// Java: `serialize()`. Returns `None` where Java throws `AssertionError` for a value with
    /// neither expression.
    pub fn serialize(&self) -> Option<String> {
        if let Some(be) = &self.bool_expr_string {
            return Some(format!("{}{}", be, DELIMITER));
        }
        let bve = self.bit_vec_expr_string.as_deref()?;
        Some(format!("{}{}", DELIMITER, bve))
    }

    /// Java: `toBigInteger()`, the integer value, or `None` if this is not a numeral.
    /// Arbitrary-precision integers are modelled as `i128` throughout this crate.
    pub fn to_big_integer<C: Z3Context + ?Sized>(&self, ctx: &C) -> Option<i128> {
        let b = self.get_bit_vec_expr(ctx)?;
        if !b.is_numeral() {
            return None;
        }
        b.to_big_integer()
    }

    /// Java: `toLong()`, the `long` value, or `None` if this is not a long.
    pub fn to_long<C: Z3Context + ?Sized>(&self, ctx: &C) -> Option<i64> {
        let b = self.get_bit_vec_expr(ctx)?;
        if !b.is_numeral() {
            return None;
        }
        match b.to_long() {
            Some(v) => Some(v),
            None => {
                Msg::info(
                    "SymValueZ3",
                    &format!("tolong invoked bit not a long returning null {}", self),
                );
                None
            }
        }
    }

    /// Java: the private `ite(Context, BoolExpr)`, which selects between the 8-bit constants one
    /// and zero (`SymZ3PcodeArithmetic.one`/`zero`).
    fn ite<C: Z3Context + ?Sized>(ctx: &C, predicate: &dyn BoolExpr) -> Self {
        let one = ctx.mk_bv(1, 8);
        let zero = ctx.mk_bv(0, 8);
        Self::from_bit_vec(ctx, &*ctx.mk_ite_bv(predicate, &*one, &*zero))
    }

    /// Java: the private `iteInv(Context, BoolExpr)`.
    fn ite_inv<C: Z3Context + ?Sized>(ctx: &C, predicate: &dyn BoolExpr) -> Self {
        let one = ctx.mk_bv(1, 8);
        let zero = ctx.mk_bv(0, 8);
        Self::from_bit_vec(ctx, &*ctx.mk_ite_bv(predicate, &*zero, &*one))
    }

    /// Java: the private `ite(Context, SymValueZ3, Z3CmpOp, SymValueZ3)`.
    fn ite_cmp<C, F>(ctx: &C, l: &Self, op: F, r: &Self) -> Option<Self>
    where
        C: Z3Context + ?Sized,
        F: Fn(&C, &dyn BitVecExpr, &dyn BitVecExpr) -> Box<dyn BoolExpr>,
    {
        let lb = l.get_bit_vec_expr(ctx)?;
        let rb = r.get_bit_vec_expr(ctx)?;
        Some(Self::ite(ctx, &*op(ctx, &*lb, &*rb)))
    }

    /// Java: the private `iteInv(Context, SymValueZ3, Z3CmpOp, SymValueZ3)`.
    fn ite_inv_cmp<C, F>(ctx: &C, l: &Self, op: F, r: &Self) -> Option<Self>
    where
        C: Z3Context + ?Sized,
        F: Fn(&C, &dyn BitVecExpr, &dyn BitVecExpr) -> Box<dyn BoolExpr>,
    {
        let lb = l.get_bit_vec_expr(ctx)?;
        let rb = r.get_bit_vec_expr(ctx)?;
        Some(Self::ite_inv(ctx, &*op(ctx, &*lb, &*rb)))
    }

    /// Java: the private `binBitVec(Context, SymValueZ3, Z3BinBitVecOp, SymValueZ3)`.
    fn bin_bit_vec<C, F>(ctx: &C, l: &Self, op: F, r: &Self) -> Option<Self>
    where
        C: Z3Context + ?Sized,
        F: Fn(&C, &dyn BitVecExpr, &dyn BitVecExpr) -> Box<dyn BitVecExpr>,
    {
        let lb = l.get_bit_vec_expr(ctx)?;
        let rb = r.get_bit_vec_expr(ctx)?;
        Some(Self::from_bit_vec(ctx, &*op(ctx, &*lb, &*rb)))
    }

    /// Java: the private `binBool(Context, SymValueZ3, Z3BinBoolOp, SymValueZ3)`, which
    /// `binABool` matches for the two-argument varargs operators.
    fn bin_bool<C, F>(ctx: &C, l: &Self, op: F, r: &Self) -> Option<Self>
    where
        C: Z3Context + ?Sized,
        F: Fn(&C, &dyn BoolExpr, &dyn BoolExpr) -> Box<dyn BoolExpr>,
    {
        let lb = l.get_bool_expr(ctx)?;
        let rb = r.get_bool_expr(ctx)?;
        Some(Self::ite(ctx, &*op(ctx, &*lb, &*rb)))
    }

    /// Java: `intEqual(Context, SymValueZ3)`.
    pub fn int_equal<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_cmp(ctx, self, |c, l, r| c.mk_eq(l, r), that)
    }

    /// Java: `intNotEqual(Context, SymValueZ3)`.
    pub fn int_not_equal<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_inv_cmp(ctx, self, |c, l, r| c.mk_eq(l, r), that)
    }

    /// Java: `intSLess(Context, SymValueZ3)`.
    pub fn int_sless<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_cmp(ctx, self, |c, l, r| c.mk_bvslt(l, r), that)
    }

    /// Java: `intSLessEqual(Context, SymValueZ3)`.
    pub fn int_sless_equal<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_cmp(ctx, self, |c, l, r| c.mk_bvsle(l, r), that)
    }

    /// Java: `intLess(Context, SymValueZ3)`.
    pub fn int_less<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_cmp(ctx, self, |c, l, r| c.mk_bvult(l, r), that)
    }

    /// Java: `intLessEqual(Context, SymValueZ3)`.
    pub fn int_less_equal<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_cmp(ctx, self, |c, l, r| c.mk_bvule(l, r), that)
    }

    /// Java: `intZExt(Context, int)`. `None` if the value is already wider than `out_size_bytes`,
    /// where Z3 would reject the negative extension count.
    pub fn int_zext<C: Z3Context + ?Sized>(&self, ctx: &C, out_size_bytes: u32) -> Option<Self> {
        let bv = self.get_bit_vec_expr(ctx)?;
        let bits = (out_size_bytes * 8).checked_sub(bv.sort_size())?;
        Some(Self::from_bit_vec(ctx, &*ctx.mk_zero_ext(bits, &*bv)))
    }

    /// Java: `intSExt(Context, int)`. `None` if the value is already wider than `out_size_bytes`,
    /// where Z3 would reject the negative extension count.
    pub fn int_sext<C: Z3Context + ?Sized>(&self, ctx: &C, out_size_bytes: u32) -> Option<Self> {
        let bv = self.get_bit_vec_expr(ctx)?;
        let bits = (out_size_bytes * 8).checked_sub(bv.sort_size())?;
        Some(Self::from_bit_vec(ctx, &*ctx.mk_sign_ext(bits, &*bv)))
    }

    /// Java: `intAdd(Context, SymValueZ3)`.
    pub fn int_add<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvadd(l, r), that)
    }

    /// Java: `intSub(Context, SymValueZ3)`.
    pub fn int_sub<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvsub(l, r), that)
    }

    /// Java: `intCarry(Context, SymValueZ3)`, the inverse of unsigned add-without-overflow.
    pub fn int_carry<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_inv_cmp(ctx, self, |c, l, r| c.mk_bv_add_no_overflow(l, r, false), that)
    }

    /// Java: `intSCarry(Context, SymValueZ3)`, the inverse of signed add-without-overflow.
    pub fn int_scarry<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_inv_cmp(ctx, self, |c, l, r| c.mk_bv_add_no_overflow(l, r, true), that)
    }

    /// Java: `intSBorrow(Context, SymValueZ3)`.
    pub fn int_sborrow<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::ite_inv_cmp(ctx, self, |c, l, r| c.mk_bv_sub_no_overflow(l, r), that)
    }

    /// Java: `intXor(Context, SymValueZ3)`.
    pub fn int_xor<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvxor(l, r), that)
    }

    /// Java: `intAnd(Context, SymValueZ3)`.
    pub fn int_and<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvand(l, r), that)
    }

    /// Java: `intOr(Context, SymValueZ3)`.
    pub fn int_or<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvor(l, r), that)
    }

    /// Java: the private `matchSortSize(Context, int, BitVecExpr)`.
    fn match_sort_size<C: Z3Context + ?Sized>(
        ctx: &C,
        size_bits: u32,
        bv: Box<dyn BitVecExpr>,
    ) -> Box<dyn BitVecExpr> {
        let sort_size = bv.sort_size();
        if sort_size == size_bits {
            return bv;
        }
        if sort_size > size_bits {
            return ctx.mk_extract(size_bits - 1, 0, &*bv);
        }
        ctx.mk_zero_ext(size_bits - sort_size, &*bv)
    }

    /// Java: the private `shift(Context, SymValueZ3, Z3BinBitVecOp, SymValueZ3)`, which normalizes
    /// the shift amount to the shifted value's width.
    fn shift<C, F>(ctx: &C, value: &Self, op: F, amt: &Self) -> Option<Self>
    where
        C: Z3Context + ?Sized,
        F: Fn(&C, &dyn BitVecExpr, &dyn BitVecExpr) -> Box<dyn BitVecExpr>,
    {
        let val_bv = value.get_bit_vec_expr(ctx)?;
        let norm_amt = Self::match_sort_size(ctx, val_bv.sort_size(), amt.get_bit_vec_expr(ctx)?);
        Some(Self::from_bit_vec(ctx, &*op(ctx, &*val_bv, &*norm_amt)))
    }

    /// Java: `intLeft(Context, SymValueZ3)`.
    pub fn int_left<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::shift(ctx, self, |c, l, r| c.mk_bvshl(l, r), that)
    }

    /// Java: `intRight(Context, SymValueZ3)`.
    pub fn int_right<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::shift(ctx, self, |c, l, r| c.mk_bvlshr(l, r), that)
    }

    /// Java: `intSRight(Context, SymValueZ3)`.
    pub fn int_sright<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::shift(ctx, self, |c, l, r| c.mk_bvashr(l, r), that)
    }

    /// Java: `intMult(Context, SymValueZ3)`.
    pub fn int_mult<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvmul(l, r), that)
    }

    /// Java: `intDiv(Context, SymValueZ3)`.
    pub fn int_div<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvudiv(l, r), that)
    }

    /// Java: `intSDiv(Context, SymValueZ3)`.
    pub fn int_sdiv<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_bvsdiv(l, r), that)
    }

    /// Java: `boolNegate(Context)`.
    pub fn bool_negate<C: Z3Context + ?Sized>(&self, ctx: &C) -> Option<Self> {
        let u = self.get_bool_expr(ctx)?;
        Some(Self::ite(ctx, &*ctx.mk_not(&*u)))
    }

    /// Java: `boolXor(Context, SymValueZ3)`.
    pub fn bool_xor<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bool(ctx, self, |c, l, r| c.mk_xor(l, r), that)
    }

    /// Java: `boolAnd(Context, SymValueZ3)`.
    pub fn bool_and<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bool(ctx, self, |c, l, r| c.mk_and(l, r), that)
    }

    /// Java: `boolOr(Context, SymValueZ3)`.
    pub fn bool_or<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bool(ctx, self, |c, l, r| c.mk_or(l, r), that)
    }

    /// Java: `piece(Context, SymValueZ3)`.
    pub fn piece<C: Z3Context + ?Sized>(&self, ctx: &C, that: &Self) -> Option<Self> {
        Self::bin_bit_vec(ctx, self, |c, l, r| c.mk_concat(l, r), that)
    }

    /// Java: `subpiece(Context, int, SymValueZ3)`. `that` is the byte offset to shift off the
    /// bottom and must be concrete, hence the `ConcretionError` Java's
    /// `SymZ3PcodeArithmetic.isInt` throws.
    pub fn subpiece<C: Z3Context + ?Sized>(
        &self,
        ctx: &C,
        out_size_bytes: u32,
        that: &Self,
    ) -> Result<Self, ConcretionError> {
        let this_bv = self
            .get_bit_vec_expr(ctx)
            .ok_or_else(|| ConcretionError::new("No bit-vector expression", Purpose::ByDef))?;
        let that_bv = that
            .get_bit_vec_expr(ctx)
            .ok_or_else(|| ConcretionError::new("No bit-vector expression", Purpose::ByDef))?;
        let shift = that_bv
            .is_numeral()
            .then(|| that_bv.to_long())
            .flatten()
            .ok_or_else(|| ConcretionError::new("Not a numeral", Purpose::ByDef))?;

        let out_size_bits = i64::from(out_size_bytes) * 8;
        let this_size_bits = i64::from(this_bv.sort_size());
        let shift_bits = shift * 8;
        let (high, low) = if this_size_bits - shift_bits > out_size_bits {
            (out_size_bits + shift_bits - 1, shift_bits)
        } else {
            (this_size_bits - 1, shift_bits)
        };
        let out = ctx.mk_extract(high as u32, low as u32, &*this_bv);
        Ok(Self::from_bit_vec(ctx, &*out))
    }

    /// Java: `popcount(Context, int)`, the sum of this value's bits widened to `out_size_bytes`.
    pub fn popcount<C: Z3Context + ?Sized>(&self, ctx: &C, out_size_bytes: u32) -> Option<Self> {
        let this_bv = self.get_bit_vec_expr(ctx)?;
        let mut out_bv = ctx.mk_bv(0, out_size_bytes * 8);
        for i in 0..this_bv.sort_size() {
            let the_bit = ctx.mk_zero_ext(out_bv.sort_size() - 1, &*ctx.mk_extract(i, i, &*this_bv));
            out_bv = ctx.mk_bvadd(&*out_bv, &*the_bit);
        }
        Some(Self::from_bit_vec(ctx, &*out_bv))
    }
}

impl fmt::Display for SymValueZ3 {
    /// Java: `toString()`, `<SymValueZ3: %s>` around `toDisplay()`. Rendering the infix form needs
    /// a Z3 context, which `Display` cannot supply, so this falls back to the serialized
    /// expression; see [`SymValueZ3::to_display`] for the Java rendering.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expr = self
            .bool_expr_string
            .as_deref()
            .or(self.bit_vec_expr_string.as_deref())
            .unwrap_or("");
        write!(f, "<SymValueZ3: {}>", expr)
    }
}

impl PartialEq for SymValueZ3 {
    /// Java: `equals(Object)`, which compares only the bit-vector expression.
    fn eq(&self, other: &Self) -> bool {
        self.bit_vec_expr_string == other.bit_vec_expr_string
    }
}

impl Eq for SymValueZ3 {}

impl Hash for SymValueZ3 {
    /// Java: `hashCode()`, which hashes only the bit-vector expression.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bit_vec_expr_string.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::Expr;
    use std::collections::hash_map::DefaultHasher;

    /// A bit-vector expression carrying its SMT-LIB2 text, width, and (if numeral) value.
    #[derive(Clone)]
    struct Bv {
        smt: String,
        size: u32,
        num: Option<i64>,
    }

    impl Bv {
        fn term(smt: impl Into<String>, size: u32) -> Self {
            Self { smt: smt.into(), size, num: None }
        }
    }

    impl Expr for Bv {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
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
            self.num.is_some()
        }
        fn to_big_integer(&self) -> Option<i128> {
            self.num.map(i128::from)
        }
        fn to_long(&self) -> Option<i64> {
            self.num
        }
    }

    /// A boolean expression, optionally remembering the bit-vector it asserts `(= b b)` over.
    #[derive(Clone)]
    struct Bl {
        smt: String,
        arg: Option<Bv>,
    }

    impl Expr for Bl {
        fn to_smt_string(&self) -> String {
            self.smt.clone()
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

    /// A Z3 stand-in that builds SMT-LIB2 text instead of calling a solver. Serialization encodes
    /// the fields the real Z3 recovers by parsing: `bv;<size>;<numeral>;<term>` for a bit-vector,
    /// `bool;<term>` for a boolean.
    struct MockCtx;

    impl MockCtx {
        fn bv(&self, smt: String, size: u32) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt, size, num: None })
        }
        fn bl(&self, smt: String) -> Box<dyn BoolExpr> {
            Box::new(Bl { smt, arg: None })
        }
    }

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
            format!(
                "bv;{};{};{}",
                b.sort_size(),
                b.to_long().map(|n| n.to_string()).unwrap_or_default(),
                b.to_smt_string()
            )
        }
        fn smt_lib_for_bool(&self, b: &dyn BoolExpr) -> String {
            format!("bool;{}", b.to_smt_string())
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            let mut parts = smt.splitn(4, ';');
            match parts.next()? {
                "bv" => {
                    let size = parts.next()?.parse().ok()?;
                    let num = parts.next()?.parse().ok();
                    let term = parts.next()?.to_string();
                    let bv = Bv { smt: term.clone(), size, num };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", term), arg: Some(bv) }))
                }
                "bool" => Some(Box::new(Bl { smt: parts.next()?.to_string(), arg: None })),
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
            Box::new(Bv { smt: format!("#x{:x}:{}", value, size_bits), size: size_bits, num: Some(value) })
        }
        fn mk_true(&self) -> Box<dyn BoolExpr> {
            self.bl("true".to_string())
        }
        fn mk_false(&self) -> Box<dyn BoolExpr> {
            self.bl("false".to_string())
        }
        fn mk_eq(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(= {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_ite_bv(
            &self,
            predicate: &dyn BoolExpr,
            t: &dyn BitVecExpr,
            f: &dyn BitVecExpr,
        ) -> Box<dyn BitVecExpr> {
            self.bv(
                format!(
                    "(ite {} {} {})",
                    predicate.to_smt_string(),
                    t.to_smt_string(),
                    f.to_smt_string()
                ),
                t.sort_size(),
            )
        }
        fn mk_ite_bool(
            &self,
            predicate: &dyn BoolExpr,
            t: &dyn BoolExpr,
            f: &dyn BoolExpr,
        ) -> Box<dyn BoolExpr> {
            self.bl(format!(
                "(ite {} {} {})",
                predicate.to_smt_string(),
                t.to_smt_string(),
                f.to_smt_string()
            ))
        }
        fn mk_bvslt(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(bvslt {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_bvsle(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(bvsle {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_bvult(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(bvult {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_bvule(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(bvule {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_bv_add_no_overflow(
            &self,
            l: &dyn BitVecExpr,
            r: &dyn BitVecExpr,
            signed: bool,
        ) -> Box<dyn BoolExpr> {
            self.bl(format!(
                "(bvaddno {} {} {})",
                l.to_smt_string(),
                r.to_smt_string(),
                signed
            ))
        }
        fn mk_bv_sub_no_overflow(
            &self,
            l: &dyn BitVecExpr,
            r: &dyn BitVecExpr,
        ) -> Box<dyn BoolExpr> {
            self.bl(format!("(bvsubno {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_bvadd(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvadd {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvsub(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvsub {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvxor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvxor {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvand(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvand {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvor {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvmul(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvmul {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvudiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvudiv {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvsdiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvsdiv {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvshl(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvshl {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvlshr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvlshr {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_bvashr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(bvashr {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size(),
            )
        }
        fn mk_concat(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("(concat {} {})", l.to_smt_string(), r.to_smt_string()),
                l.sort_size() + r.sort_size(),
            )
        }
        fn mk_zero_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("((_ zero_extend {}) {})", bits, b.to_smt_string()),
                b.sort_size() + bits,
            )
        }
        fn mk_sign_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("((_ sign_extend {}) {})", bits, b.to_smt_string()),
                b.sort_size() + bits,
            )
        }
        fn mk_extract(&self, high: u32, low: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            self.bv(
                format!("((_ extract {} {}) {})", high, low, b.to_smt_string()),
                high - low + 1,
            )
        }
        fn mk_not(&self, u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(not {})", u.to_smt_string()))
        }
        fn mk_xor(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(xor {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_and(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(and {} {})", l.to_smt_string(), r.to_smt_string()))
        }
        fn mk_or(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            self.bl(format!("(or {} {})", l.to_smt_string(), r.to_smt_string()))
        }
    }

    /// An infix printer stand-in that just echoes the SMT text.
    struct MockPrinter;

    impl Z3InfixPrinter for MockPrinter {
        fn infix(&self, e: &dyn Expr) -> String {
            e.to_smt_string()
        }
    }

    fn value(smt: &str, size: u32) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(&MockCtx, &Bv::term(smt, size))
    }

    fn bit_vec_term(v: &SymValueZ3) -> String {
        v.get_bit_vec_expr(&MockCtx).unwrap().to_smt_string()
    }

    fn hash_of(v: &SymValueZ3) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn serialization_tags_bit_vectors_with_v_and_booleans_with_b() {
        let v = SymValueZ3::from_bit_vec_and_bool(&MockCtx, &Bv::term("x", 8), &Bl {
            smt: "(= x x)".to_string(),
            arg: None,
        });
        assert!(v.bit_vec_expr_string.as_deref().unwrap().starts_with("V:"));
        assert!(v.bool_expr_string.as_deref().unwrap().starts_with("B:"));
        assert!(v.has_bit_vec_expr());
        assert!(v.has_bool_expr());
    }

    #[test]
    fn serialize_puts_bool_left_and_bit_vec_right_of_the_delimiter() {
        let bool_only = SymValueZ3::parse("B:bool;p:::::").unwrap();
        assert_eq!(bool_only.serialize().unwrap(), "B:bool;p:::::");
        assert!(bool_only.has_bool_expr());
        assert!(!bool_only.has_bit_vec_expr());

        let bv_only = value("x", 8);
        let serialized = bv_only.serialize().unwrap();
        assert!(serialized.starts_with(":::::V:"));
        // Java: a value with a boolean serializes the boolean and drops the bit-vector.
        let round_tripped = SymValueZ3::parse(&serialized).unwrap();
        assert_eq!(round_tripped, bv_only);
        assert!(!round_tripped.has_bool_expr());
    }

    #[test]
    fn parse_requires_the_delimiter() {
        assert!(SymValueZ3::parse("V:no delimiter here").is_none());
        // Java's private constructor maps empty halves to null.
        let empty = SymValueZ3::parse(":::::").unwrap();
        assert!(!empty.has_bool_expr());
        assert!(!empty.has_bit_vec_expr());
        assert!(empty.serialize().is_none());
    }

    #[test]
    fn equality_and_hash_consider_only_the_bit_vector() {
        let bare = value("x", 8);
        let with_bool = SymValueZ3 {
            bit_vec_expr_string: bare.bit_vec_expr_string.clone(),
            bool_expr_string: Some("B:bool;(= x x)".to_string()),
        };
        assert_eq!(bare, with_bool);
        assert_eq!(hash_of(&bare), hash_of(&with_bool));
        assert_ne!(bare, value("y", 8));
    }

    #[test]
    fn deserialization_recovers_the_bit_vector_from_its_equality_wrapper() {
        let v = value("x", 8);
        let bv = v.get_bit_vec_expr(&MockCtx).unwrap();
        assert_eq!(bv.to_smt_string(), "x");
        assert_eq!(bv.sort_size(), 8);
        // The wrong tag is not a bit-vector serialization.
        assert!(SymValueZ3::deserialize_bit_vec_expr(&MockCtx, "B:bool;p").is_none());
        assert!(SymValueZ3::deserialize_bool_expr(&MockCtx, "V:bv;8;;x").is_none());
    }

    #[test]
    fn get_bool_expr_coerces_a_bit_vector_by_comparing_against_zero() {
        let v = value("x", 8);
        let b = v.get_bool_expr(&MockCtx).unwrap();
        assert_eq!(b.to_smt_string(), "(ite (= x #x0:8) false true)");
    }

    #[test]
    fn comparisons_select_between_the_one_and_zero_byte_constants() {
        let l = value("x", 8);
        let r = value("y", 8);
        assert_eq!(
            bit_vec_term(&l.int_equal(&MockCtx, &r).unwrap()),
            "(ite (= x y) #x1:8 #x0:8)"
        );
        // intNotEqual inverts the arms rather than negating the predicate.
        assert_eq!(
            bit_vec_term(&l.int_not_equal(&MockCtx, &r).unwrap()),
            "(ite (= x y) #x0:8 #x1:8)"
        );
        assert_eq!(
            bit_vec_term(&l.int_sless(&MockCtx, &r).unwrap()),
            "(ite (bvslt x y) #x1:8 #x0:8)"
        );
        assert_eq!(
            bit_vec_term(&l.int_carry(&MockCtx, &r).unwrap()),
            "(ite (bvaddno x y false) #x0:8 #x1:8)"
        );
        assert_eq!(
            bit_vec_term(&l.int_scarry(&MockCtx, &r).unwrap()),
            "(ite (bvaddno x y true) #x0:8 #x1:8)"
        );
    }

    #[test]
    fn arithmetic_wraps_the_operands_in_a_new_value() {
        let l = value("x", 8);
        let r = value("y", 8);
        assert_eq!(bit_vec_term(&l.int_add(&MockCtx, &r).unwrap()), "(bvadd x y)");
        assert_eq!(bit_vec_term(&l.int_sub(&MockCtx, &r).unwrap()), "(bvsub x y)");
        assert_eq!(bit_vec_term(&l.int_mult(&MockCtx, &r).unwrap()), "(bvmul x y)");
        assert_eq!(
            bit_vec_term(&l.piece(&MockCtx, &r).unwrap()),
            "(concat x y)"
        );
    }

    #[test]
    fn extension_counts_are_the_difference_in_widths() {
        let v = value("x", 8);
        assert_eq!(
            bit_vec_term(&v.int_zext(&MockCtx, 4).unwrap()),
            "((_ zero_extend 24) x)"
        );
        assert_eq!(
            bit_vec_term(&v.int_sext(&MockCtx, 2).unwrap()),
            "((_ sign_extend 8) x)"
        );
        // Narrowing would ask Z3 for a negative extension.
        assert!(value("w", 32).int_zext(&MockCtx, 1).is_none());
    }

    #[test]
    fn shifts_normalize_the_amount_to_the_shifted_value_width() {
        let v = value("x", 32);
        // A narrower amount is zero-extended...
        assert_eq!(
            bit_vec_term(&v.int_left(&MockCtx, &value("n", 8)).unwrap()),
            "(bvshl x ((_ zero_extend 24) n))"
        );
        // ...a wider one truncated...
        assert_eq!(
            bit_vec_term(&v.int_right(&MockCtx, &value("m", 64)).unwrap()),
            "(bvlshr x ((_ extract 31 0) m))"
        );
        // ...and a matching one passed through unchanged.
        assert_eq!(
            bit_vec_term(&v.int_sright(&MockCtx, &value("k", 32)).unwrap()),
            "(bvashr x k)"
        );
    }

    #[test]
    fn boolean_ops_go_through_the_bool_expr_coercion() {
        let v = SymValueZ3::parse("B:bool;p:::::").unwrap();
        let w = SymValueZ3::parse("B:bool;q:::::").unwrap();
        assert_eq!(
            bit_vec_term(&v.bool_negate(&MockCtx).unwrap()),
            "(ite (not p) #x1:8 #x0:8)"
        );
        assert_eq!(
            bit_vec_term(&v.bool_and(&MockCtx, &w).unwrap()),
            "(ite (and p q) #x1:8 #x0:8)"
        );
        assert_eq!(
            bit_vec_term(&v.bool_or(&MockCtx, &w).unwrap()),
            "(ite (or p q) #x1:8 #x0:8)"
        );
    }

    #[test]
    fn subpiece_extracts_from_the_concrete_byte_offset() {
        let v = value("x", 64);
        let one_byte = SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.mk_bv(1, 8));
        // 64 - 8 > 32, so the extract is clamped to the requested output width.
        let narrowed = v.subpiece(&MockCtx, 4, &one_byte).unwrap();
        assert_eq!(bit_vec_term(&narrowed), "((_ extract 39 8) x)");
        // 64 - 8 <= 56, so everything above the shift is kept.
        let widened = v.subpiece(&MockCtx, 7, &one_byte).unwrap();
        assert_eq!(bit_vec_term(&widened), "((_ extract 63 8) x)");
    }

    #[test]
    fn subpiece_needs_a_concrete_offset() {
        let err = value("x", 64)
            .subpiece(&MockCtx, 4, &value("sym", 8))
            .unwrap_err();
        assert_eq!(err.message(), "Not a numeral");
        assert_eq!(err.purpose(), Purpose::ByDef);
    }

    #[test]
    fn popcount_sums_every_bit_widened_to_the_output() {
        let summed = value("x", 2).popcount(&MockCtx, 1).unwrap();
        assert_eq!(
            bit_vec_term(&summed),
            "(bvadd (bvadd #x0:8 ((_ zero_extend 7) ((_ extract 0 0) x))) \
             ((_ zero_extend 7) ((_ extract 1 1) x)))"
        );
    }

    #[test]
    fn numerals_convert_and_symbols_do_not() {
        let numeral = SymValueZ3::from_bit_vec(&MockCtx, &*MockCtx.mk_bv(42, 32));
        assert_eq!(numeral.to_long(&MockCtx), Some(42));
        assert_eq!(numeral.to_big_integer(&MockCtx), Some(42));

        let symbol = value("x", 32);
        assert_eq!(symbol.to_long(&MockCtx), None);
        assert_eq!(symbol.to_big_integer(&MockCtx), None);
    }

    #[test]
    fn display_and_to_display_prefer_the_boolean_expression() {
        let v = SymValueZ3 {
            bit_vec_expr_string: Some("V:bv;8;;x".to_string()),
            bool_expr_string: Some("B:bool;(bvult x #x08)".to_string()),
        };
        assert_eq!(v.to_display(&MockCtx, &MockPrinter).unwrap(), "(bvult x #x08)");
        assert_eq!(v.to_string(), "<SymValueZ3: B:bool;(bvult x #x08)>");

        let bv_only = value("y", 8);
        assert_eq!(bv_only.to_display(&MockCtx, &MockPrinter).unwrap(), "y");
    }
}
