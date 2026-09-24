//! A p-code arithmetic operating on concrete byte arrays.
//!
//! Port of `ghidra.pcode.exec.BytesPcodeArithmetic`.
//!
//! # Divergences from Java
//!
//! * **Op behavior dispatch.** Java asks `OpBehaviorFactory.getOpBehavior(opcode)` for a behavior
//!   instance and casts it to `UnaryOpBehavior`/`BinaryOpBehavior`. This crate's
//!   [`opbehavior`](crate::pcode::opbehavior) traits are not object-safe and there is no factory
//!   (see [`PcodeExecutor`](crate::pcode::exec::pcode_executor)'s module docs for the same
//!   divergence), so the dispatch is a `match` on the opcode that mirrors the factory's table
//!   entry for entry, calling the same concrete behavior. An opcode the factory maps to a
//!   `SpecialOpBehavior` (or to nothing) fails Java's cast; here it panics with the mnemonic.
//! * **FLOAT_\* ops.** The `OpBehaviorFloat*` classes are not ported. Each one's body is a single
//!   call on the `FloatFormat` that `FloatFormatFactory.getFloatFormat(size)` returns; those
//!   bodies are reproduced here verbatim against the
//!   [`FloatFormatFactory`](crate::pcode::seam_stubs::FloatFormatFactory) /
//!   [`FloatFormat`](crate::pcode::seam_stubs::FloatFormat) placeholders. `FloatFormat` (and the
//!   arbitrary-precision `BigFloat` it needs) is unported, so evaluating a FLOAT_* op panics in
//!   that placeholder until it is.
//! * **`BigInteger`.** Values wider than 8 bytes take Java's `BigInteger` path, which is `i128`
//!   here per the crate-wide convention, so operands wider than 16 bytes are not representable.

use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::opbehavior::{
    BinaryOpBehavior, OpBehaviorBoolAnd, OpBehaviorBoolNegate, OpBehaviorBoolOr, OpBehaviorBoolXor,
    OpBehaviorCopy, OpBehaviorEqual, OpBehaviorInt2Comp, OpBehaviorIntAdd, OpBehaviorIntAnd,
    OpBehaviorIntCarry, OpBehaviorIntDiv, OpBehaviorIntLeft, OpBehaviorIntLess,
    OpBehaviorIntLessEqual, OpBehaviorIntMult, OpBehaviorIntNegate, OpBehaviorIntOr,
    OpBehaviorIntRem, OpBehaviorIntRight, OpBehaviorIntSborrow, OpBehaviorIntScarry,
    OpBehaviorIntSdiv, OpBehaviorIntSext, OpBehaviorIntSless, OpBehaviorIntSlessEqual,
    OpBehaviorIntSrem, OpBehaviorIntSright, OpBehaviorIntSub, OpBehaviorIntXor, OpBehaviorIntZext,
    OpBehaviorLzcount, OpBehaviorNotEqual, OpBehaviorPiece, OpBehaviorPopcount, OpBehaviorSubpiece,
    UnaryOpBehavior,
};
use crate::pcode::seam_stubs::FloatFormatFactory;
use crate::pcode::utils::{big_integer_to_bytes, bytes_to_big_integer, bytes_to_long, long_to_bytes};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::OpCode;

/// A p-code arithmetic that operates on concrete byte array values.
///
/// The arithmetic interprets the arrays as big- or little-endian values, then performs the
/// operation as a `long` (64-bit) or, for operands or results wider than 8 bytes, as a big integer.
/// Java's enum of the same name has exactly these two constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BytesPcodeArithmetic {
    /// The instance which interprets arrays as big-endian values.
    BigEndian,
    /// The instance which interprets arrays as little-endian values.
    LittleEndian,
}

impl BytesPcodeArithmetic {
    /// Obtain the instance for the given endianness: [`Self::BigEndian`] if `big_endian`, else
    /// [`Self::LittleEndian`].
    pub fn for_endian(big_endian: bool) -> Self {
        if big_endian {
            Self::BigEndian
        }
        else {
            Self::LittleEndian
        }
    }

    /// Obtain the instance for the given language's endianness.
    pub fn for_language<L: Language + ?Sized>(language: &L) -> Self {
        Self::for_endian(language.is_big_endian())
    }

    /// As [`for_language`](Self::for_language), for a caller holding the concrete
    /// [`SleighLanguage`] that Java upcasts to `Language` at the call site (e.g. `PcodeEmulator`'s
    /// `language` field). `SleighLanguage` does not implement [`Language`] in this crate (see
    /// `AbstractPcodeMachine`'s module docs), so the two entry points cannot be unified yet.
    pub fn for_sleigh_language(language: &SleighLanguage) -> Self {
        Self::for_endian(language.is_big_endian())
    }

    /// The endianness of this instance (Java: the enum constant's `endian` field).
    pub fn endian(self) -> Endian {
        match self {
            Self::BigEndian => Endian::Big,
            Self::LittleEndian => Endian::Little,
        }
    }

    fn is_big_endian(self) -> bool {
        self == Self::BigEndian
    }
}

/// Java's `(UnaryOpBehavior) OpBehaviorFactory.getOpBehavior(opcode)` followed by
/// `evaluateUnary(int, int, long)`.
fn evaluate_unary_long(opcode: OpCode, sizeout: i32, sizein: i32, in1: i64) -> i64 {
    use OpCode::*;
    match opcode {
        Copy => OpBehaviorCopy::new().evaluate_unary_i64(sizeout, sizein, in1),
        IntZext => OpBehaviorIntZext::new().evaluate_unary_i64(sizeout, sizein, in1),
        IntSext => OpBehaviorIntSext::new().evaluate_unary_i64(sizeout, sizein, in1),
        Int2Comp => OpBehaviorInt2Comp::new().evaluate_unary_i64(sizeout, sizein, in1),
        IntNegate => OpBehaviorIntNegate::new().evaluate_unary_i64(sizeout, sizein, in1),
        BoolNegate => OpBehaviorBoolNegate::new().evaluate_unary_i64(sizeout, sizein, in1),
        Popcount => OpBehaviorPopcount::new().evaluate_unary_i64(sizeout, sizein, in1),
        Lzcount => OpBehaviorLzcount::new().evaluate_unary_i64(sizeout, sizein, in1),
        // OpBehaviorFloat*: see the module docs.
        FloatNan => FloatFormatFactory::get_float_format(sizein).op_nan(in1),
        FloatNeg => FloatFormatFactory::get_float_format(sizein).op_neg(in1),
        FloatAbs => FloatFormatFactory::get_float_format(sizein).op_abs(in1),
        FloatSqrt => FloatFormatFactory::get_float_format(sizein).op_sqrt(in1),
        FloatInt2Float => FloatFormatFactory::get_float_format(sizeout).op_int2float(in1, sizein),
        FloatFloat2Float => {
            let formatout = FloatFormatFactory::get_float_format(sizeout);
            let formatin = FloatFormatFactory::get_float_format(sizein);
            formatin.op_float2float(in1, &*formatout)
        }
        FloatTrunc => FloatFormatFactory::get_float_format(sizein).op_trunc(in1, sizeout),
        FloatCeil => FloatFormatFactory::get_float_format(sizein).op_ceil(in1),
        FloatFloor => FloatFormatFactory::get_float_format(sizein).op_floor(in1),
        FloatRound => FloatFormatFactory::get_float_format(sizein).op_round(in1),
        other => panic!("{} is not a unary p-code op (OpBehaviorFactory has no UnaryOpBehavior for it)", other.mnemonic()),
    }
}

/// As [`evaluate_unary_long`], for Java's `evaluateUnary(int, int, BigInteger)`.
fn evaluate_unary_big(opcode: OpCode, sizeout: i32, sizein: i32, in1: i128) -> i128 {
    use OpCode::*;
    match opcode {
        Copy => OpBehaviorCopy::new().evaluate_unary_i128(sizeout, sizein, in1),
        IntZext => OpBehaviorIntZext::new().evaluate_unary_i128(sizeout, sizein, in1),
        IntSext => OpBehaviorIntSext::new().evaluate_unary_i128(sizeout, sizein, in1),
        Int2Comp => OpBehaviorInt2Comp::new().evaluate_unary_i128(sizeout, sizein, in1),
        IntNegate => OpBehaviorIntNegate::new().evaluate_unary_i128(sizeout, sizein, in1),
        BoolNegate => OpBehaviorBoolNegate::new().evaluate_unary_i128(sizeout, sizein, in1),
        Popcount => OpBehaviorPopcount::new().evaluate_unary_i128(sizeout, sizein, in1),
        Lzcount => OpBehaviorLzcount::new().evaluate_unary_i128(sizeout, sizein, in1),
        FloatNan => FloatFormatFactory::get_float_format(sizein).op_nan_big(in1),
        FloatNeg => FloatFormatFactory::get_float_format(sizein).op_neg_big(in1),
        FloatAbs => FloatFormatFactory::get_float_format(sizein).op_abs_big(in1),
        FloatSqrt => FloatFormatFactory::get_float_format(sizein).op_sqrt_big(in1),
        FloatInt2Float => {
            FloatFormatFactory::get_float_format(sizeout).op_int2float_big(in1, sizein, true)
        }
        FloatFloat2Float => {
            let formatout = FloatFormatFactory::get_float_format(sizeout);
            let formatin = FloatFormatFactory::get_float_format(sizein);
            formatin.op_float2float_big(in1, &*formatout)
        }
        FloatTrunc => FloatFormatFactory::get_float_format(sizein).op_trunc_big(in1, sizeout),
        FloatCeil => FloatFormatFactory::get_float_format(sizein).op_ceil_big(in1),
        FloatFloor => FloatFormatFactory::get_float_format(sizein).op_floor_big(in1),
        FloatRound => FloatFormatFactory::get_float_format(sizein).op_round_big(in1),
        other => panic!("{} is not a unary p-code op (OpBehaviorFactory has no UnaryOpBehavior for it)", other.mnemonic()),
    }
}

/// Java's `(BinaryOpBehavior) OpBehaviorFactory.getOpBehavior(opcode)` followed by
/// `evaluateBinary(int, int, long, long)`.
fn evaluate_binary_long(opcode: OpCode, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
    use OpCode::*;
    match opcode {
        Piece => OpBehaviorPiece::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        Subpiece => OpBehaviorSubpiece::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntEqual => OpBehaviorEqual::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntNotEqual => OpBehaviorNotEqual::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSless => OpBehaviorIntSless::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSlessEqual => OpBehaviorIntSlessEqual::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntLess => OpBehaviorIntLess::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntLessEqual => OpBehaviorIntLessEqual::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntAdd => OpBehaviorIntAdd::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSub => OpBehaviorIntSub::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntCarry => OpBehaviorIntCarry::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntScarry => OpBehaviorIntScarry::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSborrow => OpBehaviorIntSborrow::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntXor => OpBehaviorIntXor::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntAnd => OpBehaviorIntAnd::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntOr => OpBehaviorIntOr::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntLeft => OpBehaviorIntLeft::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntRight => OpBehaviorIntRight::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSright => OpBehaviorIntSright::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntMult => OpBehaviorIntMult::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntDiv => OpBehaviorIntDiv::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSdiv => OpBehaviorIntSdiv::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntRem => OpBehaviorIntRem::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        IntSrem => OpBehaviorIntSrem::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        BoolXor => OpBehaviorBoolXor::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        BoolAnd => OpBehaviorBoolAnd::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        BoolOr => OpBehaviorBoolOr::new().evaluate_binary_i64(sizeout, sizein, in1, in2),
        // OpBehaviorFloat*: see the module docs.
        FloatEqual => FloatFormatFactory::get_float_format(sizein).op_equal(in1, in2),
        FloatNotEqual => FloatFormatFactory::get_float_format(sizein).op_not_equal(in1, in2),
        FloatLess => FloatFormatFactory::get_float_format(sizein).op_less(in1, in2),
        FloatLessEqual => FloatFormatFactory::get_float_format(sizein).op_less_equal(in1, in2),
        FloatAdd => FloatFormatFactory::get_float_format(sizein).op_add(in1, in2),
        FloatDiv => FloatFormatFactory::get_float_format(sizein).op_div(in1, in2),
        FloatMult => FloatFormatFactory::get_float_format(sizein).op_mult(in1, in2),
        FloatSub => FloatFormatFactory::get_float_format(sizein).op_sub(in1, in2),
        other => panic!("{} is not a binary p-code op (OpBehaviorFactory has no BinaryOpBehavior for it)", other.mnemonic()),
    }
}

/// As [`evaluate_binary_long`], for Java's `evaluateBinary(int, int, BigInteger, BigInteger)`.
fn evaluate_binary_big(opcode: OpCode, sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
    use OpCode::*;
    match opcode {
        Piece => OpBehaviorPiece::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        Subpiece => OpBehaviorSubpiece::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntEqual => OpBehaviorEqual::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntNotEqual => OpBehaviorNotEqual::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSless => OpBehaviorIntSless::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSlessEqual => OpBehaviorIntSlessEqual::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntLess => OpBehaviorIntLess::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntLessEqual => OpBehaviorIntLessEqual::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntAdd => OpBehaviorIntAdd::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSub => OpBehaviorIntSub::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntCarry => OpBehaviorIntCarry::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntScarry => OpBehaviorIntScarry::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSborrow => OpBehaviorIntSborrow::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntXor => OpBehaviorIntXor::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntAnd => OpBehaviorIntAnd::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntOr => OpBehaviorIntOr::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntLeft => OpBehaviorIntLeft::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntRight => OpBehaviorIntRight::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSright => OpBehaviorIntSright::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntMult => OpBehaviorIntMult::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntDiv => OpBehaviorIntDiv::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSdiv => OpBehaviorIntSdiv::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntRem => OpBehaviorIntRem::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        IntSrem => OpBehaviorIntSrem::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        BoolXor => OpBehaviorBoolXor::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        BoolAnd => OpBehaviorBoolAnd::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        BoolOr => OpBehaviorBoolOr::new().evaluate_binary_i128(sizeout, sizein, in1, in2),
        FloatEqual => FloatFormatFactory::get_float_format(sizein).op_equal_big(in1, in2),
        FloatNotEqual => FloatFormatFactory::get_float_format(sizein).op_not_equal_big(in1, in2),
        FloatLess => FloatFormatFactory::get_float_format(sizein).op_less_big(in1, in2),
        FloatLessEqual => FloatFormatFactory::get_float_format(sizein).op_less_equal_big(in1, in2),
        FloatAdd => FloatFormatFactory::get_float_format(sizein).op_add_big(in1, in2),
        FloatDiv => FloatFormatFactory::get_float_format(sizein).op_div_big(in1, in2),
        FloatMult => FloatFormatFactory::get_float_format(sizein).op_mult_big(in1, in2),
        FloatSub => FloatFormatFactory::get_float_format(sizein).op_sub_big(in1, in2),
        other => panic!("{} is not a binary p-code op (OpBehaviorFactory has no BinaryOpBehavior for it)", other.mnemonic()),
    }
}

impl PcodeArithmetic<Vec<u8>> for BytesPcodeArithmetic {
    fn get_endian(&self) -> Option<Endian> {
        Some(self.endian())
    }

    fn unary_op(&self, opcode: OpCode, sizeout: i32, sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
        let is_big_endian = self.is_big_endian();
        if sizein1 > 8 || sizeout > 8 {
            let in1_val = bytes_to_big_integer(in1, sizein1 as usize, is_big_endian, false);
            let out_val = evaluate_unary_big(opcode, sizeout, sizein1, in1_val);
            return big_integer_to_bytes(out_val, sizeout as usize, is_big_endian);
        }
        let in1_val = bytes_to_long(in1, sizein1 as usize, is_big_endian);
        let out_val = evaluate_unary_long(opcode, sizeout, sizein1, in1_val);
        long_to_bytes(out_val, sizeout as usize, is_big_endian)
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        sizeout: i32,
        sizein1: i32,
        in1: &Vec<u8>,
        sizein2: i32,
        in2: &Vec<u8>,
    ) -> Vec<u8> {
        let is_big_endian = self.is_big_endian();
        if sizein1 > 8 || sizein2 > 8 || sizeout > 8 {
            let in1_val = bytes_to_big_integer(in1, sizein1 as usize, is_big_endian, false);
            let in2_val = bytes_to_big_integer(in2, sizein2 as usize, is_big_endian, false);
            let out_val = evaluate_binary_big(opcode, sizeout, sizein1, in1_val, in2_val);
            return big_integer_to_bytes(out_val, sizeout as usize, is_big_endian);
        }
        let in1_val = bytes_to_long(in1, sizein1 as usize, is_big_endian);
        let in2_val = bytes_to_long(in2, sizein2 as usize, is_big_endian);
        let out_val = evaluate_binary_long(opcode, sizeout, sizein1, in1_val, in2_val);
        long_to_bytes(out_val, sizeout as usize, is_big_endian)
    }

    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Vec<u8>,
        _sizein_value: i32,
        in_value: &Vec<u8>,
    ) -> Vec<u8> {
        in_value.clone()
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Vec<u8>,
        _sizein_value: i32,
        in_value: &Vec<u8>,
    ) -> Vec<u8> {
        in_value.clone()
    }

    fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }

    fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
        Ok(value.clone())
    }

    fn size_of(&self, value: &Vec<u8>) -> i64 {
        value.len() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BE: BytesPcodeArithmetic = BytesPcodeArithmetic::BigEndian;
    const LE: BytesPcodeArithmetic = BytesPcodeArithmetic::LittleEndian;

    #[test]
    fn for_endian_selects_the_matching_constant() {
        assert_eq!(BytesPcodeArithmetic::for_endian(true), BE);
        assert_eq!(BytesPcodeArithmetic::for_endian(false), LE);
        assert_eq!(BE.get_endian(), Some(Endian::Big));
        assert_eq!(LE.get_endian(), Some(Endian::Little));
    }

    #[test]
    fn int_add_respects_endianness() {
        // 0x01020304 + 0x00000001, 4 bytes.
        assert_eq!(
            BE.binary_op(OpCode::IntAdd, 4, 4, &vec![1, 2, 3, 4], 4, &vec![0, 0, 0, 1]),
            vec![1, 2, 3, 5]
        );
        assert_eq!(
            LE.binary_op(OpCode::IntAdd, 4, 4, &vec![4, 3, 2, 1], 4, &vec![1, 0, 0, 0]),
            vec![5, 3, 2, 1]
        );
    }

    #[test]
    fn int_add_wraps_at_output_size() {
        // 0xff + 0x01 in one byte: Java's longToBytes keeps only the low byte.
        assert_eq!(BE.binary_op(OpCode::IntAdd, 1, 1, &vec![0xff], 1, &vec![1]), vec![0]);
    }

    #[test]
    fn comparisons_produce_one_byte_booleans() {
        // INT_SLESS: -1 < 1 signed; INT_LESS: 0xff > 0x01 unsigned.
        assert_eq!(BE.binary_op(OpCode::IntSless, 1, 1, &vec![0xff], 1, &vec![1]), vec![1]);
        assert_eq!(BE.binary_op(OpCode::IntLess, 1, 1, &vec![0xff], 1, &vec![1]), vec![0]);
        assert_eq!(LE.binary_op(OpCode::IntEqual, 1, 2, &vec![0x34, 0x12], 2, &vec![0x34, 0x12]), vec![1]);
        assert_eq!(LE.binary_op(OpCode::IntNotEqual, 1, 2, &vec![0x34, 0x12], 2, &vec![0x34, 0x12]), vec![0]);
    }

    #[test]
    fn unary_extensions() {
        // INT_ZEXT 0x80 (1 byte) to 2 bytes, then INT_SEXT.
        assert_eq!(BE.unary_op(OpCode::IntZext, 2, 1, &vec![0x80]), vec![0x00, 0x80]);
        assert_eq!(BE.unary_op(OpCode::IntSext, 2, 1, &vec![0x80]), vec![0xff, 0x80]);
        assert_eq!(LE.unary_op(OpCode::IntSext, 4, 2, &vec![0x00, 0x80]), vec![0x00, 0x80, 0xff, 0xff]);
        assert_eq!(BE.unary_op(OpCode::Int2Comp, 1, 1, &vec![1]), vec![0xff]);
        assert_eq!(BE.unary_op(OpCode::Copy, 2, 2, &vec![0xab, 0xcd]), vec![0xab, 0xcd]);
        assert_eq!(BE.unary_op(OpCode::Popcount, 1, 2, &vec![0xf0, 0x0f]), vec![8]);
    }

    #[test]
    fn piece_and_subpiece() {
        // PIECE 0x12:0x34 -> 0x1234; SUBPIECE 0x11223344, 2 -> 0x1122.
        assert_eq!(BE.binary_op(OpCode::Piece, 2, 1, &vec![0x12], 1, &vec![0x34]), vec![0x12, 0x34]);
        assert_eq!(
            BE.binary_op(OpCode::Subpiece, 2, 4, &vec![0x11, 0x22, 0x33, 0x44], 4, &vec![0, 0, 0, 2]),
            vec![0x11, 0x22]
        );
    }

    #[test]
    fn wide_operands_take_the_big_integer_path() {
        // 16-byte INT_ADD with a carry out of the low 8 bytes, which the long path would lose.
        let mut a = vec![0u8; 16];
        a[8..].copy_from_slice(&[0xff; 8]);
        let mut one = vec![0u8; 16];
        one[15] = 1;
        let mut expected = vec![0u8; 16];
        expected[7] = 1;
        assert_eq!(BE.binary_op(OpCode::IntAdd, 16, 16, &a, 16, &one), expected);

        // INT_ZEXT from 8 to 16 bytes, little-endian: high bytes become zero.
        let v = vec![0xffu8; 8];
        let mut zext = vec![0xffu8; 8];
        zext.extend_from_slice(&[0u8; 8]);
        assert_eq!(LE.unary_op(OpCode::IntZext, 16, 8, &v), zext);
    }

    #[test]
    fn identity_members() {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let v = vec![1u8, 2, 3];
        assert_eq!(BE.mod_before_store(4, &space, &vec![0; 4], 3, &v), v);
        assert_eq!(BE.mod_after_load(4, &space, &vec![0; 4], 3, &v), v);
        assert_eq!(BE.from_const_bytes(&v), v);
        assert_eq!(BE.to_concrete(&v, Purpose::Inspect).unwrap(), v);
        assert_eq!(BE.size_of(&v), 3);
    }

    #[test]
    fn from_const_and_to_long_round_trip_by_endianness() {
        assert_eq!(BE.from_const_u64(0x1234, 2), vec![0x12, 0x34]);
        assert_eq!(LE.from_const_u64(0x1234, 2), vec![0x34, 0x12]);
        assert_eq!(LE.to_long(&vec![0x34, 0x12], Purpose::Inspect).unwrap(), 0x1234);
    }

    #[test]
    #[should_panic(expected = "not a binary p-code op")]
    fn special_op_is_not_an_arithmetic_op() {
        // Java: OpBehaviorFactory maps LOAD to a SpecialOpBehavior, so the cast fails.
        BE.binary_op(OpCode::Load, 4, 4, &vec![0; 4], 4, &vec![0; 4]);
    }
}
