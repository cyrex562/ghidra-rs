//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntLess`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;

/// INT_LESS p-code operation behavior: unsigned less-than comparison.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntLess`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntLess {
    base: OpBehavior,
}

impl OpBehaviorIntLess {
    /// Construct a new `OpBehaviorIntLess` for [`OpCode::IntLess`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntLess as i32) }
    }
}

impl Default for OpBehaviorIntLess {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntLess {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if sizein <= 0 {
            return 0;
        }
        let mask = calc_mask(sizein);
        let in1 = in1 & mask;
        let in2 = in2 & mask;
        if in1 == in2 {
            0
        }
        else if sizein < 8 {
            if in1 < in2 { 1 } else { 0 }
        }
        else {
            let sign_mask: i64 = 0x80u64.wrapping_shl((8 * (sizein - 1)) as u32) as i64;
            let bit1 = in1 & sign_mask;
            let bit2 = in2 & sign_mask;
            if bit1 != bit2 {
                if bit1 != 0 { 0 } else { 1 }
            }
            else if in1 < in2 { 1 } else { 0 }
        }
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, _sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 < in2 { 1 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntLess::new().opcode(), OpCode::IntLess as i32);
    }

    #[test]
    fn small_size_unsigned_compare() {
        let b = OpBehaviorIntLess::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 2, 5), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 5, 2), 0);
        assert_eq!(b.evaluate_binary_i64(1, 1, 5, 5), 0);
    }

    /// 8-byte unsigned comparison where the raw `i64` bit pattern would look negative if compared
    /// signed: `0xFFFF...` (an unsigned value near `u64::MAX`) must compare greater than `1`.
    #[test]
    fn eight_byte_unsigned_compare_handles_high_bit() {
        let b = OpBehaviorIntLess::new();
        let huge = -1i64; // 0xFFFFFFFFFFFFFFFF, i.e. u64::MAX
        assert_eq!(b.evaluate_binary_i64(1, 8, 1, huge), 1);
        assert_eq!(b.evaluate_binary_i64(1, 8, huge, 1), 0);
    }

    #[test]
    fn zero_sizein_yields_zero() {
        let b = OpBehaviorIntLess::new();
        assert_eq!(b.evaluate_binary_i64(1, 0, 5, 2), 0);
    }

    #[test]
    fn i128_compares_values() {
        let b = OpBehaviorIntLess::new();
        assert_eq!(b.evaluate_binary_i128(1, 8, 2, 5), 1);
        assert_eq!(b.evaluate_binary_i128(1, 8, 5, 2), 0);
    }
}
