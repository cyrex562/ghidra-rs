//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntRem`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::error::LowlevelError;
use crate::program::model::pcode::OpCode;

/// INT_REM p-code operation behavior: unsigned remainder.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntRem`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntRem {
    base: OpBehavior,
}

impl OpBehaviorIntRem {
    /// Construct a new `OpBehaviorIntRem` for [`OpCode::IntRem`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntRem as i32) }
    }
}

impl Default for OpBehaviorIntRem {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntRem {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    /// # Panics
    /// Java throws `LowlevelError("Remainder by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i64(&self, _sizeout: i32, _sizein: i32, in1: i64, in2: i64) -> i64 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Remainder by 0"));
        }
        ((in1 as u64) % (in2 as u64)) as i64
    }

    /// # Panics
    /// Java throws `LowlevelError("Remainder by 0")` if `in2 == 0`; ported here as a panic since
    /// this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        if in2 == 0 {
            panic!("{}", LowlevelError::with_message("Remainder by 0"));
        }
        in1 % in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntRem::new().opcode(), OpCode::IntRem as i32);
    }

    #[test]
    fn computes_remainder() {
        let b = OpBehaviorIntRem::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 10, 3), 1);
    }

    #[test]
    fn unsigned_remainder_with_high_bit_set() {
        let b = OpBehaviorIntRem::new();
        let in1 = -1i64; // u64::MAX
        assert_eq!(b.evaluate_binary_i64(8, 8, in1, 10), (u64::MAX % 10) as i64);
    }

    #[test]
    #[should_panic(expected = "Remainder by 0")]
    fn panics_on_zero_divisor() {
        let b = OpBehaviorIntRem::new();
        b.evaluate_binary_i64(4, 4, 10, 0);
    }

    #[test]
    fn i128_computes_remainder() {
        let b = OpBehaviorIntRem::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 10, 3), 1);
    }

    #[test]
    #[should_panic(expected = "Remainder by 0")]
    fn i128_panics_on_zero_divisor() {
        let b = OpBehaviorIntRem::new();
        b.evaluate_binary_i128(4, 4, 10, 0);
    }
}
