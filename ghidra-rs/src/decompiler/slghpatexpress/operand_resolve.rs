//! Models `ghidra.pcodeCPort.slghpatexpress.OperandResolve`.

use crate::decompiler::slghsymbol::OperandSymbol;

/// Holds state for resolving operands while traversing a pattern equation.
///
/// Tracks the current base operand being examined and the offsets traversed as the
/// pattern equation is traversed from left to right. Also records the resulting
/// rightmost operand and total bytes traversed.
///
/// Models the class `ghidra.pcodeCPort.slghpatexpress.OperandResolve`.
pub struct OperandResolve {
    /// All operands available for resolution.
    pub operands: Vec<OperandSymbol>,
    /// Current base operand (as we traverse the pattern equation from left to right).
    pub base: i32,
    /// Bytes we have traversed from the LEFT edge of the current base.
    pub offset: i32,
    /// (resulting) rightmost operand in our pattern.
    pub cur_rightmost: i32,
    /// (resulting) bytes traversed from the LEFT edge of the rightmost.
    pub size: i32,
}

impl OperandResolve {
    /// Creates a new operand resolver with the given operands.
    ///
    /// # Arguments
    ///
    /// * `operands` - Vector of operand symbols available for resolution.
    pub fn new(operands: Vec<OperandSymbol>) -> Self {
        Self {
            operands,
            base: -1,
            offset: 0,
            cur_rightmost: -1,
            size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::Location;

    #[test]
    fn new_initializes_fields() {
        let loc = Location::new("test.sla", 1);
        let operand = OperandSymbol::with_name(loc.clone(), "op1");
        let operands = vec![operand];
        let resolve = OperandResolve::new(operands);

        assert_eq!(resolve.operands.len(), 1);
        assert_eq!(resolve.base, -1);
        assert_eq!(resolve.offset, 0);
        assert_eq!(resolve.cur_rightmost, -1);
        assert_eq!(resolve.size, 0);
    }

    #[test]
    fn new_with_multiple_operands() {
        let loc = Location::new("test.sla", 1);
        let op1 = OperandSymbol::with_name(loc.clone(), "op1");
        let op2 = OperandSymbol::with_name(loc.clone(), "op2");
        let op3 = OperandSymbol::with_name(loc, "op3");
        let operands = vec![op1, op2, op3];

        let resolve = OperandResolve::new(operands);

        assert_eq!(resolve.operands.len(), 3);
        assert_eq!(resolve.base, -1);
        assert_eq!(resolve.offset, 0);
        assert_eq!(resolve.cur_rightmost, -1);
        assert_eq!(resolve.size, 0);
    }

    #[test]
    fn new_with_empty_operands() {
        let operands = vec![];
        let resolve = OperandResolve::new(operands);

        assert_eq!(resolve.operands.len(), 0);
        assert_eq!(resolve.base, -1);
        assert_eq!(resolve.offset, 0);
        assert_eq!(resolve.cur_rightmost, -1);
        assert_eq!(resolve.size, 0);
    }

    #[test]
    fn fields_are_mutable() {
        let operands = vec![];
        let mut resolve = OperandResolve::new(operands);

        resolve.base = 0;
        resolve.offset = 4;
        resolve.cur_rightmost = 2;
        resolve.size = 8;

        assert_eq!(resolve.base, 0);
        assert_eq!(resolve.offset, 4);
        assert_eq!(resolve.cur_rightmost, 2);
        assert_eq!(resolve.size, 8);
    }
}
