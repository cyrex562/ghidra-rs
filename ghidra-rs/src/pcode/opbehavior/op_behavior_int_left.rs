//! Port of `ghidra.pcode.opbehavior.OpBehaviorIntLeft`.

use super::binary_op_behavior::BinaryOpBehavior;
use super::op_behavior::OpBehavior;
use crate::pcode::utils::calc_mask;
use crate::program::model::pcode::OpCode;
use crate::util::AssertException;

/// INT_LEFT p-code operation behavior: logical left shift.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehaviorIntLeft`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntLeft {
    base: OpBehavior,
}

impl OpBehaviorIntLeft {
    /// Construct a new `OpBehaviorIntLeft` for [`OpCode::IntLeft`].
    pub fn new() -> Self {
        Self { base: OpBehavior::new(OpCode::IntLeft as i32) }
    }
}

impl Default for OpBehaviorIntLeft {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryOpBehavior for OpBehaviorIntLeft {
    fn opcode(&self) -> i32 {
        self.base.opcode()
    }

    fn evaluate_binary_i64(&self, sizeout: i32, sizein: i32, in1: i64, in2: i64) -> i64 {
        if in2 < 0 || in2 >= (8 * sizein) as i64 {
            return 0;
        }
        // `checked_shl` (rather than plain `<<`) guards against a shift distance in
        // `0..(8*sizein)` that still exceeds `i64`'s own 64-bit width when `sizein > 8`; Java's
        // `long <<` would instead silently mask the distance modulo 64, but any `sizein > 8`
        // reaching this `long`-based overload is already out of its intended range, so shifting
        // out entirely (`0`) is the safer, panic-free choice here.
        in1.checked_shl(in2 as u32).unwrap_or(0) & calc_mask(sizeout)
    }

    /// # Panics
    /// Java throws `AssertException("Expected unsigned in values")` if either input is negative;
    /// ported here as a panic since this trait's methods are infallible.
    fn evaluate_binary_i128(&self, _sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        if in1 < 0 || in2 < 0 {
            panic!("{}", AssertException::with_message("Expected unsigned in values"));
        }
        let max_shift = (sizein as i128) * 8;
        if in2 >= max_shift {
            return 0;
        }
        in1.checked_shl(in2 as u32).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_matches_pcode_op() {
        assert_eq!(OpBehaviorIntLeft::new().opcode(), OpCode::IntLeft as i32);
    }

    #[test]
    fn shifts_left() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary_i64(4, 4, 1, 4), 16);
    }

    #[test]
    fn shift_beyond_width_yields_zero() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 8), 0);
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, 100), 0);
    }

    #[test]
    fn negative_shift_yields_zero() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 1, -1), 0);
    }

    #[test]
    fn masks_to_sizeout() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary_i64(1, 1, 0x01, 7), 0x80);
        // shifting further loses bits that overflow the 1-byte output.
        assert_eq!(b.evaluate_binary_i64(1, 2, 0x100, 0), 0x00);
    }

    #[test]
    fn i128_shifts_left() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary_i128(4, 4, 1, 4), 16);
        assert_eq!(b.evaluate_binary_i128(1, 1, 1, 8), 0);
    }

    #[test]
    #[should_panic(expected = "Expected unsigned in values")]
    fn i128_panics_on_negative_input() {
        let b = OpBehaviorIntLeft::new();
        b.evaluate_binary_i128(1, 1, -1, 1);
    }
}
