//! Port of `ghidra.lisa.pcode.contexts.UnaryExprContext`.

use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// The single operand of a unary p-code operation.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.UnaryExprContext` in the Java source. As with
/// [`TernaryExprContext`](super::ternary_expr_context::TernaryExprContext), Java's class does not
/// `extend PcodeContext` -- it merely takes one in its constructor and copies its `op` field out
/// -- so this is a plain struct with public fields mirroring Java's own public fields, not a
/// composition wrapper.
#[derive(Clone, Debug)]
pub struct UnaryExprContext {
    /// The wrapped p-code operation. Mirrors the Java class's public `op` field.
    pub op: PcodeOp,
    /// The op's first (only) input (index 0). Mirrors the Java class's public `arg` field.
    pub arg: VarnodeContext,
}

impl UnaryExprContext {
    /// Java: `UnaryExprContext(PcodeContext ctx)`.
    ///
    /// # Panics
    ///
    /// If `ctx`'s op has no input at index 0. Java's `op.getInput(0)` instead returns `null`
    /// there; see
    /// [`PcodeContext::basic_expr`](crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext::basic_expr)'s
    /// docs for why this port panics immediately instead, at the point Java's `null` would first
    /// become unusable.
    pub fn new(ctx: &PcodeContext) -> Self {
        let op = ctx.get_op().clone();
        let arg = VarnodeContext::new(
            op.get_input(0).cloned().expect("UnaryExprContext::new: op has no input at index 0"),
        );
        Self { op, arg }
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

    fn unary_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::IntNegate, seq, inputs, None)
    }

    #[test]
    fn wraps_the_first_input_as_arg() {
        let space = ram_space();
        let a = varnode(&space, 0x10, 4);
        let op = unary_op(vec![a.clone()]);
        let pcode_ctx = PcodeContext::new(op);

        let unary = UnaryExprContext::new(&pcode_ctx);

        assert_eq!(unary.arg.varnode(), &a);
    }

    #[test]
    fn opcode_mnemonic_and_location_read_through_the_op() {
        let space = ram_space();
        let op = unary_op(vec![varnode(&space, 0x10, 4)]);
        let op_clone = op.clone();
        let pcode_ctx = PcodeContext::new(op);

        let unary = UnaryExprContext::new(&pcode_ctx);

        assert_eq!(unary.opcode(), OpCode::IntNegate);
        assert_eq!(unary.mnemonic(), op_clone.get_mnemonic());
        assert_eq!(unary.location(), PcodeLocation::new(op_clone));
    }

    #[test]
    #[should_panic(expected = "op has no input at index 0")]
    fn constructor_panics_when_there_is_no_input() {
        let op = unary_op(vec![]);
        let pcode_ctx = PcodeContext::new(op);
        let _ = UnaryExprContext::new(&pcode_ctx);
    }
}
