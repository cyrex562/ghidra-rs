//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntSlessEqual`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::convert_to_signed_value;
use crate::program::model::pcode::OpCode;

/// INT_SLESSEQUAL p-code operation behavior: signed less-than-or-equal comparison.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntSlessEqual`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSlessEqual {
    base: OpBehavior,
}

impl OpBehaviorIntSlessEqual {
    /// Construct a new `OpBehaviorIntSlessEqual` for [`OpCode::IntSlessEqual`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntSlessEqual as i32) }
    }
}

impl Default for OpBehaviorIntSlessEqual {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntSlessEqual {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, _sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if sizein <= 0 {
            return 0;
        }
        let sign_mask: i64 = 0x80u64.wrapping_shl((8 * (sizein - 1)) as u32) as i64;
        let bit1 = in1 & sign_mask;
        let bit2 = in2 & sign_mask;
        if bit1 != bit2 {
            if bit1 != 0 { 1 } else { 0 }
        }
        else if in1 <= in2 { 1 } else { 0 }
    }

    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if sizein <= 0 {
            return 0;
        }
        let in1 = convert_to_signed_value(in1, sizein);
        let in2 = convert_to_signed_value(in2, sizein);
        if in1 <= in2 { 1 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntSlessEqual::new().opcode(), OpCode::IntSlessEqual as i32);
    }

    #[test]
    fn positive_values_compare_normally() {
        let b = OpBehaviorIntSlessEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 2, 5), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 5, 5), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 5, 2), 0);
    }

    #[test]
    fn negative_one_byte_value_is_less_than_positive() {
        let b = OpBehaviorIntSlessEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0xff, 0x01), 1);
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x01, 0xff), 0);
    }

    #[test]
    fn zero_sizein_yields_zero() {
        let b = OpBehaviorIntSlessEqual::new();
        assert_eq!(b.evaluate_binary_i64(1, 0, 5, 2), 0);
        assert_eq!(b.evaluate_binary_i128(1, 0, 5, 2), 0);
    }

    #[test]
    fn i128_signed_comparison() {
        let b = OpBehaviorIntSlessEqual::new();
        assert_eq!(b.evaluate_binary_i128(1, 1, 0xff, 0x01), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x05, 0x05), 1);
        assert_eq!(b.evaluate_binary_i128(1, 1, 0x01, 0xff), 0);
    }
}
