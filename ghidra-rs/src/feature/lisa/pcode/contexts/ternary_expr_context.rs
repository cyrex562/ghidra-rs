//! Port of `ghidra.lisa.pcode.contexts.TernaryExprContext`.

use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// The three operands of a ternary p-code operation, split out into named `left`/`middle`/`right`
/// [`VarnodeContext`]s.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.TernaryExprContext` in the Java source. Unlike
/// [`ConditionContext`](super::condition_context::ConditionContext), Java's class does not
/// `extend PcodeContext` -- it merely *takes one in its constructor* and copies its `op` field out
/// -- so there is no base to compose over here either; this is a plain struct with public fields
/// mirroring Java's own public fields.
#[derive(Clone, Debug)]
pub struct TernaryExprContext {
    /// The wrapped p-code operation. Mirrors the Java class's public `op` field.
    pub op: PcodeOp,
    /// The op's first input (index 0). Mirrors the Java class's public `left` field.
    pub left: VarnodeContext,
    /// The op's second input (index 1). Mirrors the Java class's public `middle` field.
    pub middle: VarnodeContext,
    /// The op's third input (index 2). Mirrors the Java class's public `right` field.
    pub right: VarnodeContext,
}

impl TernaryExprContext {
    /// Java: `TernaryExprContext(PcodeContext ctx)`.
    ///
    /// # Panics
    ///
    /// If `ctx`'s op has fewer than three inputs. Java's `op.getInput(i)` instead returns `null`
    /// there, which would surface as a `NullPointerException` from the very next use of
    /// `left`/`middle`/`right` -- see
    /// [`PcodeContext::basic_expr`](crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext::basic_expr)'s
    /// docs for why this port panics immediately instead, at the point Java's `null` would first
    /// become unusable.
    pub fn new(ctx: &PcodeContext) -> Self {
        let op = ctx.get_op().clone();
        let left = VarnodeContext::new(
            op.get_input(0).cloned().expect("TernaryExprContext::new: op has no input at index 0"),
        );
        let middle = VarnodeContext::new(
            op.get_input(1).cloned().expect("TernaryExprContext::new: op has no input at index 1"),
        );
        let right = VarnodeContext::new(
            op.get_input(2).cloned().expect("TernaryExprContext::new: op has no input at index 2"),
        );
        Self { op, left, middle, right }
    }

    /// Java: `opcode()`.
    pub fn opcode(&self) -> OpCode {
        self.op.get_opcode()
    }

    /// Java: `location()`.
    pub fn location(&self) -> PcodeLocation {
        PcodeLocation::new(self.op.clone())
    }

    /// Java: `mnemonic()`.
    pub fn mnemonic(&self) -> &'static str {
        self.op.get_mnemonic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{SequenceNumber, Varnode};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &std::sync::Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn ternary_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        // PTRADD is a real 3-input opcode (base, index, size), but this crate's `PcodeOp` does not
        // validate arity against opcode either way, and Java's own class works with any op whose
        // inputs happen to number three or more (nothing here checks arity beyond indexing).
        PcodeOp::new(OpCode::PtrAdd, seq, inputs, None)
    }

    #[test]
    fn splits_the_first_three_inputs_into_left_middle_right() {
        let space = ram_space();
        let a = varnode(&space, 0x10, 4);
        let b = varnode(&space, 0x14, 4);
        let c = varnode(&space, 0x18, 4);
        let op = ternary_op(vec![a.clone(), b.clone(), c.clone()]);
        let pcode_ctx = PcodeContext::new(op);

        let ternary = TernaryExprContext::new(&pcode_ctx);

        assert_eq!(ternary.left.varnode(), &a);
        assert_eq!(ternary.middle.varnode(), &b);
        assert_eq!(ternary.right.varnode(), &c);
    }

    #[test]
    fn opcode_mnemonic_and_location_read_through_the_op() {
        let space = ram_space();
        let op = ternary_op(vec![varnode(&space, 0x10, 4), varnode(&space, 0x14, 4), varnode(&space, 0x18, 4)]);
        let op_clone = op.clone();
        let pcode_ctx = PcodeContext::new(op);

        let ternary = TernaryExprContext::new(&pcode_ctx);

        assert_eq!(ternary.opcode(), OpCode::PtrAdd);
        assert_eq!(ternary.mnemonic(), op_clone.get_mnemonic());
        assert_eq!(ternary.location(), PcodeLocation::new(op_clone));
    }

    #[test]
    #[should_panic(expected = "op has no input at index 2")]
    fn constructor_panics_when_there_are_fewer_than_three_inputs() {
        let space = ram_space();
        let op = ternary_op(vec![varnode(&space, 0x10, 4), varnode(&space, 0x14, 4)]);
        let pcode_ctx = PcodeContext::new(op);
        let _ = TernaryExprContext::new(&pcode_ctx);
    }
}
