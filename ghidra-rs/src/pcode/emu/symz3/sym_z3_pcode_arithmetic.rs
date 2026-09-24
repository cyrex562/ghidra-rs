//! The symbolic-Z3 p-code arithmetic.
//!
//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeArithmetic`.
//!
//! # Divergences from Java
//!
//! * **The Z3 context.** Every Java method opens a throw-away `try (Context ctx = new Context())`.
//!   This crate has no Z3 binding; the Z3 boundary is the
//!   [`Z3Context`](crate::feature::seam_stubs::Z3Context) seam, and the established convention in
//!   this package (see [`SymZ3PcodeExecutorStatePiece`]'s module docs) is to inject an
//!   `Arc<dyn Z3Context>` at construction. Java's type is an `enum` of the two endiannesses, so
//!   each variant carries that injected context; [`for_endian`](SymZ3PcodeArithmetic::for_endian)
//!   and [`for_language`](SymZ3PcodeArithmetic::for_language) take it as an extra argument.
//! * **Static initialization.** Java's static initializer loads the native Z3 libraries and logs
//!   the Z3 version. There is no native library behind the seam, so there is nothing to load.
//! * **Exceptions.** `ConcretionError` is returned where the [`PcodeArithmetic`] signature allows
//!   it. Java's unchecked failures -- `AssertionError` for an unsupported opcode, a
//!   `NullPointerException` for a value missing its expression, a `ConcretionError` from
//!   `SUBPIECE` inside `binaryOp` (whose signature cannot carry it), and `Z3Exception` for a
//!   numeral that does not fit a `long`/`int` -- panic.
//!
//! [`SymZ3PcodeExecutorStatePiece`]: crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::SymZ3PcodeExecutorStatePiece

use std::sync::Arc;

use crate::feature::seam_stubs::{BitVecExpr, Z3Context};
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::utils::{big_integer_to_bytes, bytes_to_big_integer};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::OpCode;

/// The symbolic-Z3 arithmetic, one instance per endianness.
///
/// Each variant carries the [`Z3Context`] its operations build expressions with (see the module
/// docs).
#[derive(Clone)]
pub enum SymZ3PcodeArithmetic {
    /// The instance for big-endian languages.
    BigEndian(Arc<dyn Z3Context>),
    /// The instance for little-endian languages.
    LittleEndian(Arc<dyn Z3Context>),
}

impl std::fmt::Debug for SymZ3PcodeArithmetic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BigEndian(_) => f.write_str("BIG_ENDIAN"),
            Self::LittleEndian(_) => f.write_str("LITTLE_ENDIAN"),
        }
    }
}

impl SymZ3PcodeArithmetic {
    /// Get the arithmetic for the given endianness.
    ///
    /// Java: `forEndian(boolean)`.
    pub fn for_endian(big_endian: bool, ctx: Arc<dyn Z3Context>) -> Self {
        if big_endian {
            Self::BigEndian(ctx)
        }
        else {
            Self::LittleEndian(ctx)
        }
    }

    /// Get the symbolic arithmetic for the given language.
    ///
    /// Java: `forLanguage(Language)`.
    pub fn for_language<L: Language + ?Sized>(language: &L, ctx: Arc<dyn Z3Context>) -> Self {
        Self::for_endian(language.is_big_endian(), ctx)
    }

    /// The endianness of this instance (Java: the constant's `endian` field).
    pub fn endian(&self) -> Endian {
        match self {
            Self::BigEndian(_) => Endian::Big,
            Self::LittleEndian(_) => Endian::Little,
        }
    }

    /// The Z3 context this instance builds expressions with.
    pub fn ctx(&self) -> &Arc<dyn Z3Context> {
        match self {
            Self::BigEndian(ctx) | Self::LittleEndian(ctx) => ctx,
        }
    }

    /// Java: `zero(Context)`, the 8-bit numeral 0.
    pub fn zero(ctx: &dyn Z3Context) -> Box<dyn BitVecExpr> {
        ctx.mk_bv(0, 8)
    }

    /// Java: `one(Context)`, the 8-bit numeral 1.
    pub fn one(ctx: &dyn Z3Context) -> Box<dyn BitVecExpr> {
        ctx.mk_bv(1, 8)
    }

    /// Java: `isNumeral(BitVecExpr, Purpose)`, which fails with "Not a numeral" unless `eb` is a
    /// numeral.
    pub fn is_numeral(eb: &dyn BitVecExpr, purpose: Purpose) -> Result<&dyn BitVecExpr, ConcretionError> {
        if !BitVecExpr::is_numeral(eb) {
            return Err(ConcretionError::new("Not a numeral", purpose));
        }
        Ok(eb)
    }

    /// Java: `isInt(BitVecExpr, Purpose)`.
    pub fn is_int(eb: &dyn BitVecExpr, purpose: Purpose) -> Result<i32, ConcretionError> {
        Ok(Self::is_numeral(eb, purpose)?
            .to_int()
            .expect("Java: BitVecNum.getInt() throws Z3Exception when the numeral is not an int"))
    }

    /// Java: `isLong(BitVecExpr, Purpose)`.
    pub fn is_long(eb: &dyn BitVecExpr, purpose: Purpose) -> Result<i64, ConcretionError> {
        Ok(Self::is_numeral(eb, purpose)?
            .to_long()
            .expect("Java: BitVecNum.getLong() throws Z3Exception when the numeral is not a long"))
    }

    /// Java: `isBigInteger(BitVecExpr, Purpose)`.
    pub fn is_big_integer(eb: &dyn BitVecExpr, purpose: Purpose) -> Result<i128, ConcretionError> {
        Ok(Self::is_numeral(eb, purpose)?
            .to_big_integer()
            .expect("a numeral always has a BigInteger value"))
    }

    /// Java: `isConcrete(BitVecExpr, Purpose, Endian)`.
    ///
    /// Faithful to Java, the array length is `getSortSize() * 8`, i.e. the sort size in *bits*
    /// times eight, not the value's size in bytes: the value occupies its low-order bytes and the
    /// rest is zero (or sign) padding.
    pub fn is_concrete(eb: &dyn BitVecExpr, purpose: Purpose, endian: Endian) -> Result<Vec<u8>, ConcretionError> {
        let bi = Self::is_big_integer(eb, purpose)?;
        let size = (eb.sort_size() * 8) as usize;
        // `Utils.bigIntegerToBytes` sign-pads past the value's own width; this crate's
        // `big_integer_to_bytes` stops at the 16 bytes an `i128` holds, so pad the rest here.
        let mut bytes = big_integer_to_bytes(bi, size.min(16), false);
        bytes.resize(size, if bi < 0 { 0xff } else { 0 });
        if endian.is_big_endian() {
            bytes.reverse();
        }
        Ok(bytes)
    }

    fn bit_vec_expr(&self, value: &SymValueZ3) -> Box<dyn BitVecExpr> {
        value
            .get_bit_vec_expr(&**self.ctx())
            .expect("Java: getBitVecExpr(ctx) on a value without a bit-vector expression")
    }
}

fn required(result: Option<SymValueZ3>, op: OpCode) -> SymValueZ3 {
    result.unwrap_or_else(|| panic!("{}: operand is missing its Z3 expression", op.mnemonic()))
}

impl PcodeArithmetic<SymValueZ3> for SymZ3PcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "SymValueZ3"
    }

    fn get_endian(&self) -> Option<Endian> {
        Some(self.endian())
    }

    fn to_long(&self, value: &SymValueZ3, purpose: Purpose) -> Result<i64, ConcretionError> {
        Self::is_long(&*self.bit_vec_expr(value), purpose)
    }

    fn to_big_integer(&self, value: &SymValueZ3, purpose: Purpose) -> Result<i128, ConcretionError> {
        Self::is_big_integer(&*self.bit_vec_expr(value), purpose)
    }

    fn to_concrete(&self, value: &SymValueZ3, purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
        Self::is_concrete(&*self.bit_vec_expr(value), purpose, self.endian())
    }

    fn is_true(&self, cond: &SymValueZ3, purpose: Purpose) -> Result<bool, ConcretionError> {
        let ctx = &**self.ctx();
        if cond.has_bool_expr() {
            let bool_expr = cond
                .get_bool_expr(ctx)
                .expect("Java: getBoolExpr(ctx) on an unparseable boolean expression");
            if bool_expr.is_true() {
                return Ok(true);
            }
            if bool_expr.is_false() {
                return Ok(false);
            }
            return Err(ConcretionError::new("Condition is not constant", purpose));
        }
        let bv_expr = self.bit_vec_expr(cond);
        if bv_expr.is_bv_bit_one() {
            return Ok(true);
        }
        if bv_expr.is_bv_bit_zero() {
            return Ok(false);
        }
        Err(ConcretionError::new("Condition is not constant", purpose))
    }

    fn unary_op(&self, opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &SymValueZ3) -> SymValueZ3 {
        let ctx = &**self.ctx();
        let sizeout = sizeout as u32;
        match opcode {
            OpCode::Copy => in1.clone(),
            OpCode::IntZext => required(in1.int_zext(ctx, sizeout), opcode),
            OpCode::IntSext => required(in1.int_sext(ctx, sizeout), opcode),
            OpCode::BoolNegate => required(in1.bool_negate(ctx), opcode),
            OpCode::Popcount => required(in1.popcount(ctx, sizeout), opcode),
            _ => panic!("need to implement unary op: {}", opcode.mnemonic()),
        }
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        sizeout: i32,
        _sizein1: i32,
        in1: &SymValueZ3,
        _sizein2: i32,
        in2: &SymValueZ3,
    ) -> SymValueZ3 {
        let ctx = &**self.ctx();
        let result = match opcode {
            OpCode::IntEqual => in1.int_equal(ctx, in2),
            OpCode::IntNotEqual => in1.int_not_equal(ctx, in2),
            OpCode::IntSless => in1.int_sless(ctx, in2),
            OpCode::IntSlessEqual => in1.int_sless_equal(ctx, in2),
            OpCode::IntLess => in1.int_less(ctx, in2),
            OpCode::IntLessEqual => in1.int_less_equal(ctx, in2),

            OpCode::IntAdd => in1.int_add(ctx, in2),
            OpCode::IntSub => in1.int_sub(ctx, in2),
            OpCode::IntCarry => in1.int_carry(ctx, in2),
            OpCode::IntScarry => in1.int_scarry(ctx, in2),
            OpCode::IntSborrow => in1.int_sborrow(ctx, in2),

            OpCode::IntXor => in1.int_xor(ctx, in2),
            OpCode::IntAnd => in1.int_and(ctx, in2),
            OpCode::IntOr => in1.int_or(ctx, in2),

            OpCode::IntLeft => in1.int_left(ctx, in2),
            OpCode::IntRight => in1.int_right(ctx, in2),
            OpCode::IntSright => in1.int_sright(ctx, in2),

            OpCode::IntMult => in1.int_mult(ctx, in2),
            OpCode::IntDiv => in1.int_div(ctx, in2),
            OpCode::IntSdiv => in1.int_sdiv(ctx, in2),

            OpCode::BoolXor => in1.bool_xor(ctx, in2),
            OpCode::BoolAnd => in1.bool_and(ctx, in2),
            OpCode::BoolOr => in1.bool_or(ctx, in2),

            // NOTE: Seeing these in low p-code would be unusual
            OpCode::Piece => in1.piece(ctx, in2),
            OpCode::Subpiece => {
                return in1
                    .subpiece(ctx, sizeout as u32, in2)
                    .unwrap_or_else(|e| panic!("{}", e.message()));
            }
            _ => panic!("need to implement binary op: {}", opcode.mnemonic()),
        };
        required(result, opcode)
    }

    fn from_const_u64(&self, value: u64, size: i32) -> SymValueZ3 {
        let ctx = &**self.ctx();
        SymValueZ3::from_bit_vec(ctx, &*ctx.mk_bv(value as i64, (size * 8) as u32))
    }

    fn from_const_big_int(&self, value: i128, size: i32, _is_contextreg: bool) -> SymValueZ3 {
        let ctx = &**self.ctx();
        SymValueZ3::from_bit_vec(ctx, &*ctx.mk_bv_big(value, (size * 8) as u32))
    }

    fn from_const_bytes(&self, value: &[u8]) -> SymValueZ3 {
        self.from_const_big_int(
            bytes_to_big_integer(value, value.len(), self.endian().is_big_endian(), false),
            value.len() as i32,
            false,
        )
    }

    fn size_of(&self, value: &SymValueZ3) -> i64 {
        i64::from(self.bit_vec_expr(value).sort_size() / 8)
    }

    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &SymValueZ3,
        _sizein_value: i32,
        in_value: &SymValueZ3,
    ) -> SymValueZ3 {
        in_value.clone()
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &SymValueZ3,
        _sizein_value: i32,
        in_value: &SymValueZ3,
    ) -> SymValueZ3 {
        in_value.clone()
    }
}

/// A Z3 test double that evaluates numerals concretely (so operation results can be checked
/// against Java's concrete semantics) and keeps anything involving a free constant symbolic.
/// Shared with the other SymZ3 modules' tests, following the `pub(crate) mod testing` convention
/// of [`crate::pcode::emu::symz3::sym_z3_pcode_executor_state_piece::testing`].
#[cfg(test)]
pub(crate) mod testing {
    use std::any::Any;

    use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr, Z3Context};

    fn mask(size: u32) -> u128 {
        if size >= 128 { u128::MAX } else { (1u128 << size) - 1 }
    }

    fn signed(v: u128, size: u32) -> i128 {
        if size >= 128 {
            return v as i128;
        }
        let sign = 1u128 << (size - 1);
        if v & sign != 0 { (v | !mask(size)) as i128 } else { v as i128 }
    }

    /// A bit-vector: its width, its value if it is a numeral, and a rendering.
    #[derive(Clone, Debug)]
    pub(crate) struct Bv {
        pub(crate) size: u32,
        pub(crate) value: Option<u128>,
        pub(crate) text: String,
    }

    impl Expr for Bv {
        fn to_smt_string(&self) -> String {
            self.text.clone()
        }
        fn is_numeral(&self) -> bool {
            self.value.is_some()
        }
        fn is_bv(&self) -> bool {
            true
        }
        fn is_bv_bit_one(&self) -> bool {
            self.size == 1 && self.value == Some(1)
        }
        fn is_bv_bit_zero(&self) -> bool {
            self.size == 1 && self.value == Some(0)
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
            self.value.is_some()
        }
        fn to_big_integer(&self) -> Option<i128> {
            self.value.map(|v| v as i128)
        }
        fn to_long(&self) -> Option<i64> {
            self.value.and_then(|v| i64::try_from(v).ok())
        }
    }

    /// A boolean: a literal, or symbolic text.
    #[derive(Clone, Debug)]
    pub(crate) struct Bl {
        pub(crate) value: Option<bool>,
        pub(crate) text: String,
        /// The bit-vector a `V:` serialization wraps as `(= b b)`.
        pub(crate) arg: Option<Bv>,
    }

    impl Expr for Bl {
        fn to_smt_string(&self) -> String {
            self.text.clone()
        }
        fn is_true(&self) -> bool {
            self.value == Some(true)
        }
        fn is_false(&self) -> bool {
            self.value == Some(false)
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
            (index == 0).then(|| self.arg.clone()).flatten().map(|b| Box::new(b) as Box<dyn BitVecExpr>)
        }
    }

    fn bv_of(e: &dyn BitVecExpr) -> Bv {
        let size = e.sort_size();
        let value = if BitVecExpr::is_numeral(e) { e.to_big_integer().map(|v| v as u128 & mask(size)) } else { None };
        Bv { size, value, text: e.as_expr().to_smt_string() }
    }

    fn bl_of(e: &dyn BoolExpr) -> Bl {
        let x = e.as_expr();
        let value = if x.is_true() { Some(true) } else if x.is_false() { Some(false) } else { None };
        Bl { value, text: x.to_smt_string(), arg: None }
    }

    fn num(size: u32, v: u128) -> Box<dyn BitVecExpr> {
        let v = v & mask(size);
        Box::new(Bv { size, value: Some(v), text: format!("(_ bv{v} {size})") })
    }

    fn sym_bv(size: u32, text: String) -> Box<dyn BitVecExpr> {
        Box::new(Bv { size, value: None, text })
    }

    fn lit(b: bool) -> Box<dyn BoolExpr> {
        Box::new(Bl { value: Some(b), text: b.to_string(), arg: None })
    }

    fn sym_bool(text: String) -> Box<dyn BoolExpr> {
        Box::new(Bl { value: None, text, arg: None })
    }

    fn bin_bv(name: &str, l: &dyn BitVecExpr, r: &dyn BitVecExpr, size: u32, f: impl Fn(u128, u128) -> u128) -> Box<dyn BitVecExpr> {
        let (l, r) = (bv_of(l), bv_of(r));
        match (l.value, r.value) {
            (Some(a), Some(b)) => num(size, f(a, b)),
            _ => sym_bv(size, format!("({name} {} {})", l.text, r.text)),
        }
    }

    fn cmp(name: &str, l: &dyn BitVecExpr, r: &dyn BitVecExpr, f: impl Fn(&Bv, &Bv) -> bool) -> Box<dyn BoolExpr> {
        let (l, r) = (bv_of(l), bv_of(r));
        if l.value.is_some() && r.value.is_some() {
            lit(f(&l, &r))
        }
        else {
            sym_bool(format!("({name} {} {})", l.text, r.text))
        }
    }

    fn bin_bool(name: &str, l: &dyn BoolExpr, r: &dyn BoolExpr, f: impl Fn(bool, bool) -> bool) -> Box<dyn BoolExpr> {
        let (l, r) = (bl_of(l), bl_of(r));
        match (l.value, r.value) {
            (Some(a), Some(b)) => lit(f(a, b)),
            _ => sym_bool(format!("({name} {} {})", l.text, r.text)),
        }
    }

    /// The concretely-evaluating Z3 test double. Serializes to `bv;size;value;text` and
    /// `bool;t|f|s;text`, which [`Z3Context::parse_smt_lib2`] reverses.
    pub(crate) struct EvalCtx;

    impl Z3Context for EvalCtx {
        fn smt_lib_for_bit_vec(&self, b: &dyn BitVecExpr) -> String {
            let b = bv_of(b);
            format!("bv;{};{};{}", b.size, b.value.map(|v| v.to_string()).unwrap_or_default(), b.text)
        }
        fn smt_lib_for_bool(&self, b: &dyn BoolExpr) -> String {
            let b = bl_of(b);
            let tag = match b.value {
                Some(true) => "t",
                Some(false) => "f",
                None => "s",
            };
            format!("bool;{tag};{}", b.text)
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn BoolExpr>> {
            let mut parts = smt.splitn(4, ';');
            match parts.next()? {
                "bv" => {
                    let size: u32 = parts.next()?.parse().ok()?;
                    let v = parts.next()?;
                    let value = if v.is_empty() { None } else { Some(v.parse().ok()?) };
                    let text = parts.next()?.to_string();
                    let arg = Bv { size, value, text: text.clone() };
                    Some(Box::new(Bl { value: None, text: format!("(= {text} {text})"), arg: Some(arg) }))
                }
                "bool" => {
                    let value = match parts.next()? {
                        "t" => Some(true),
                        "f" => Some(false),
                        _ => None,
                    };
                    Some(Box::new(Bl { value, text: parts.next()?.to_string(), arg: None }))
                }
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn BitVecExpr> {
            num(size_bits, value as i128 as u128)
        }
        fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn BitVecExpr> {
            sym_bv(size_bits, name.to_string())
        }
        fn mk_true(&self) -> Box<dyn BoolExpr> {
            lit(true)
        }
        fn mk_false(&self) -> Box<dyn BoolExpr> {
            lit(false)
        }
        fn mk_eq(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("=", l, r, |a, b| a.value == b.value)
        }
        fn mk_ite_bv(&self, predicate: &dyn BoolExpr, t: &dyn BitVecExpr, f: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let p = bl_of(predicate);
            match p.value {
                Some(true) => Box::new(bv_of(t)),
                Some(false) => Box::new(bv_of(f)),
                None => sym_bv(t.sort_size(), format!("(ite {} {} {})", p.text, bv_of(t).text, bv_of(f).text)),
            }
        }
        fn mk_ite_bool(&self, predicate: &dyn BoolExpr, t: &dyn BoolExpr, f: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            let p = bl_of(predicate);
            match p.value {
                Some(true) => Box::new(bl_of(t)),
                Some(false) => Box::new(bl_of(f)),
                None => sym_bool(format!("(ite {} {} {})", p.text, bl_of(t).text, bl_of(f).text)),
            }
        }
        fn mk_bvslt(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("bvslt", l, r, |a, b| signed(a.value.unwrap(), a.size) < signed(b.value.unwrap(), b.size))
        }
        fn mk_bvsle(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("bvsle", l, r, |a, b| signed(a.value.unwrap(), a.size) <= signed(b.value.unwrap(), b.size))
        }
        fn mk_bvult(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("bvult", l, r, |a, b| a.value < b.value)
        }
        fn mk_bvule(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("bvule", l, r, |a, b| a.value <= b.value)
        }
        fn mk_bv_add_no_overflow(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr, is_signed: bool) -> Box<dyn BoolExpr> {
            cmp("bvadd_noovfl", l, r, |a, b| {
                let (x, y) = (a.value.unwrap(), b.value.unwrap());
                if is_signed {
                    let s = signed(x, a.size) + signed(y, a.size);
                    let max = (1i128 << (a.size - 1)) - 1;
                    s <= max
                }
                else {
                    x + y <= mask(a.size)
                }
            })
        }
        fn mk_bv_sub_no_overflow(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            cmp("bvsub_noovfl", l, r, |a, b| {
                let d = signed(a.value.unwrap(), a.size) - signed(b.value.unwrap(), b.size);
                let (min, max) = (-(1i128 << (a.size - 1)), (1i128 << (a.size - 1)) - 1);
                min <= d && d <= max
            })
        }
        fn mk_bvadd(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvadd", l, r, l.sort_size(), |a, b| a.wrapping_add(b))
        }
        fn mk_bvsub(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvsub", l, r, l.sort_size(), |a, b| a.wrapping_sub(b))
        }
        fn mk_bvxor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvxor", l, r, l.sort_size(), |a, b| a ^ b)
        }
        fn mk_bvand(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvand", l, r, l.sort_size(), |a, b| a & b)
        }
        fn mk_bvor(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvor", l, r, l.sort_size(), |a, b| a | b)
        }
        fn mk_bvmul(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvmul", l, r, l.sort_size(), |a, b| a.wrapping_mul(b))
        }
        fn mk_bvudiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let size = l.sort_size();
            bin_bv("bvudiv", l, r, size, move |a, b| if b == 0 { mask(size) } else { a / b })
        }
        fn mk_bvsdiv(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let size = l.sort_size();
            bin_bv("bvsdiv", l, r, size, move |a, b| (signed(a, size) / signed(b, size)) as u128)
        }
        fn mk_bvshl(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvshl", l, r, l.sort_size(), |a, b| if b >= 128 { 0 } else { a << b })
        }
        fn mk_bvlshr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            bin_bv("bvlshr", l, r, l.sort_size(), |a, b| if b >= 128 { 0 } else { a >> b })
        }
        fn mk_bvashr(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let size = l.sort_size();
            bin_bv("bvashr", l, r, size, move |a, b| (signed(a, size) >> b.min(127)) as u128)
        }
        fn mk_concat(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let rs = r.sort_size();
            bin_bv("concat", l, r, l.sort_size() + rs, move |a, b| (a << rs) | b)
        }
        fn mk_zero_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let b = bv_of(b);
            match b.value {
                Some(v) => num(b.size + bits, v),
                None => sym_bv(b.size + bits, format!("((_ zero_extend {bits}) {})", b.text)),
            }
        }
        fn mk_sign_ext(&self, bits: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let b = bv_of(b);
            match b.value {
                Some(v) => num(b.size + bits, signed(v, b.size) as u128),
                None => sym_bv(b.size + bits, format!("((_ sign_extend {bits}) {})", b.text)),
            }
        }
        fn mk_extract(&self, high: u32, low: u32, b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let b = bv_of(b);
            let size = high - low + 1;
            match b.value {
                Some(v) => num(size, v >> low),
                None => sym_bv(size, format!("((_ extract {high} {low}) {})", b.text)),
            }
        }
        fn mk_not(&self, u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            let u = bl_of(u);
            match u.value {
                Some(v) => lit(!v),
                None => sym_bool(format!("(not {})", u.text)),
            }
        }
        fn mk_xor(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            bin_bool("xor", l, r, |a, b| a ^ b)
        }
        fn mk_and(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            bin_bool("and", l, r, |a, b| a && b)
        }
        fn mk_or(&self, l: &dyn BoolExpr, r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            bin_bool("or", l, r, |a, b| a || b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::EvalCtx;
    use super::*;

    fn le() -> SymZ3PcodeArithmetic {
        SymZ3PcodeArithmetic::for_endian(false, Arc::new(EvalCtx))
    }

    fn be() -> SymZ3PcodeArithmetic {
        SymZ3PcodeArithmetic::for_endian(true, Arc::new(EvalCtx))
    }

    fn val(a: &SymZ3PcodeArithmetic, v: u64, size: i32) -> SymValueZ3 {
        a.from_const_u64(v, size)
    }

    fn long(a: &SymZ3PcodeArithmetic, v: &SymValueZ3) -> i64 {
        a.to_long(v, Purpose::Inspect).unwrap()
    }

    #[test]
    fn for_endian_selects_the_variant() {
        assert_eq!(be().endian(), Endian::Big);
        assert_eq!(le().endian(), Endian::Little);
        assert_eq!(le().get_endian(), Some(Endian::Little));
        assert_eq!(le().get_domain(), "SymValueZ3");
    }

    #[test]
    fn from_const_and_size_of() {
        let a = le();
        let v = val(&a, 0x1234, 4);
        assert_eq!(a.size_of(&v), 4);
        assert_eq!(long(&a, &v), 0x1234);
        assert_eq!(a.to_big_integer(&v, Purpose::Inspect).unwrap(), 0x1234);
    }

    #[test]
    fn from_const_bytes_reads_by_endianness() {
        assert_eq!(long(&le(), &le().from_const_bytes(&[0x34, 0x12])), 0x1234);
        assert_eq!(long(&be(), &be().from_const_bytes(&[0x12, 0x34])), 0x1234);
        assert_eq!(le().size_of(&le().from_const_bytes(&[0x34, 0x12])), 2);
    }

    #[test]
    fn from_const_big_int_wider_than_a_long() {
        let a = le();
        let v = a.from_const_big_int((1i128 << 64) | 5, 16, false);
        assert_eq!(a.size_of(&v), 16);
        assert_eq!(a.to_big_integer(&v, Purpose::Inspect).unwrap(), (1i128 << 64) | 5);
    }

    #[test]
    fn integer_binary_ops_evaluate_numerals() {
        let a = le();
        let (x, y) = (val(&a, 7, 4), val(&a, 3, 4));
        assert_eq!(long(&a, &a.binary_op(OpCode::IntAdd, 4, 4, &x, 4, &y)), 10);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntSub, 4, 4, &x, 4, &y)), 4);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntMult, 4, 4, &x, 4, &y)), 21);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntDiv, 4, 4, &x, 4, &y)), 2);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntXor, 4, 4, &x, 4, &y)), 4);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntLeft, 4, 4, &x, 4, &y)), 56);
        // Comparisons produce the 8-bit one/zero (SymZ3PcodeArithmetic.one/zero).
        let lt = a.binary_op(OpCode::IntLess, 1, 4, &y, 4, &x);
        assert_eq!((a.size_of(&lt), long(&a, &lt)), (1, 1));
        assert_eq!(long(&a, &a.binary_op(OpCode::IntEqual, 1, 4, &x, 4, &y)), 0);
        // INT_SLESS: 0xffffffff is -1 signed.
        let m1 = val(&a, 0xffff_ffff, 4);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntSless, 1, 4, &m1, 4, &y)), 1);
        assert_eq!(long(&a, &a.binary_op(OpCode::IntLess, 1, 4, &m1, 4, &y)), 0);
        // INT_CARRY: 0xffffffff + 3 overflows unsigned.
        assert_eq!(long(&a, &a.binary_op(OpCode::IntCarry, 1, 4, &m1, 4, &y)), 1);
    }

    #[test]
    fn piece_and_subpiece() {
        let a = le();
        let hi = val(&a, 0x12, 1);
        let lo = val(&a, 0x34, 1);
        let p = a.binary_op(OpCode::Piece, 2, 1, &hi, 1, &lo);
        assert_eq!((a.size_of(&p), long(&a, &p)), (2, 0x1234));
        let w = val(&a, 0x1122_3344, 4);
        let s = a.binary_op(OpCode::Subpiece, 2, 4, &w, 4, &val(&a, 2, 4));
        assert_eq!((a.size_of(&s), long(&a, &s)), (2, 0x1122));
    }

    #[test]
    fn unary_ops() {
        let a = le();
        let v = val(&a, 0x80, 1);
        assert_eq!(a.unary_op(OpCode::Copy, 1, 1, &v), v);
        let z = a.unary_op(OpCode::IntZext, 2, 1, &v);
        assert_eq!((a.size_of(&z), long(&a, &z)), (2, 0x80));
        let s = a.unary_op(OpCode::IntSext, 2, 1, &v);
        assert_eq!(long(&a, &s), 0xff80);
        assert_eq!(long(&a, &a.unary_op(OpCode::Popcount, 1, 2, &val(&a, 0xf00f, 2))), 8);
        assert_eq!(long(&a, &a.unary_op(OpCode::BoolNegate, 1, 1, &val(&a, 0, 1))), 1);
    }

    #[test]
    fn bool_ops() {
        let a = le();
        let (t, f) = (val(&a, 1, 1), val(&a, 0, 1));
        assert_eq!(long(&a, &a.binary_op(OpCode::BoolAnd, 1, 1, &t, 1, &f)), 0);
        assert_eq!(long(&a, &a.binary_op(OpCode::BoolOr, 1, 1, &t, 1, &f)), 1);
        assert_eq!(long(&a, &a.binary_op(OpCode::BoolXor, 1, 1, &t, 1, &t)), 0);
    }

    #[test]
    fn symbolic_values_do_not_concretize() {
        let a = le();
        let ctx = EvalCtx;
        let x = SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv_const("RAX", 64));
        let sum = a.binary_op(OpCode::IntAdd, 8, 8, &x, 8, &val(&a, 1, 8));
        assert_eq!(a.size_of(&sum), 8);
        let err = a.to_long(&sum, Purpose::Branch).unwrap_err();
        assert_eq!((err.message(), err.purpose()), ("Not a numeral", Purpose::Branch));
        assert!(a.to_concrete(&sum, Purpose::Load).is_err());
    }

    #[test]
    fn to_concrete_is_sort_size_times_eight_bytes_like_java() {
        // Java: Utils.bigIntegerToBytes(bi, eb.getSortSize() * 8, bigEndian) -- 8 bits -> 64 bytes.
        let a = le();
        let bytes = a.to_concrete(&val(&a, 0xab, 1), Purpose::Inspect).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0], 0xab);
        assert!(bytes[1..].iter().all(|&b| b == 0));
        let bytes = be().to_concrete(&val(&be(), 0xab, 1), Purpose::Inspect).unwrap();
        assert_eq!(bytes[63], 0xab);
    }

    #[test]
    fn is_true_needs_a_literal() {
        let a = le();
        let ctx = EvalCtx;
        // A boolean literal decides.
        let t = SymValueZ3::from_bit_vec_and_bool(&ctx, &*ctx.mk_bv(1, 8), &*ctx.mk_true());
        let f = SymValueZ3::from_bit_vec_and_bool(&ctx, &*ctx.mk_bv(0, 8), &*ctx.mk_false());
        assert!(a.is_true(&t, Purpose::Condition).unwrap());
        assert!(!a.is_true(&f, Purpose::Condition).unwrap());
        // So does a one-bit bit-vector literal.
        assert!(a.is_true(&SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv(1, 1)), Purpose::Condition).unwrap());
        assert!(!a.is_true(&SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv(0, 1)), Purpose::Condition).unwrap());
        // An 8-bit numeral is not Z3's `bit1`, so Java reports it as not constant.
        let err = a.is_true(&val(&a, 1, 1), Purpose::Condition).unwrap_err();
        assert_eq!(err.message(), "Condition is not constant");
    }

    #[test]
    fn mod_before_store_and_after_load_are_identity() {
        let a = le();
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let v = val(&a, 9, 4);
        assert_eq!(a.mod_before_store(4, &space, &val(&a, 0, 4), 4, &v), v);
        assert_eq!(a.mod_after_load(4, &space, &val(&a, 0, 4), 4, &v), v);
    }

    #[test]
    #[should_panic(expected = "need to implement unary op: INT_NEGATE")]
    fn unsupported_unary_op_panics() {
        let a = le();
        a.unary_op(OpCode::IntNegate, 4, 4, &val(&a, 1, 4));
    }

    #[test]
    #[should_panic(expected = "need to implement binary op: INT_REM")]
    fn unsupported_binary_op_panics() {
        let a = le();
        a.binary_op(OpCode::IntRem, 4, 4, &val(&a, 1, 4), 4, &val(&a, 1, 4));
    }
}
