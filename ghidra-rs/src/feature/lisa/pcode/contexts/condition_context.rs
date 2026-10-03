//! Port of `ghidra.lisa.pcode.contexts.ConditionContext`.

use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// A [`PcodeContext`] specialized for a conditional branch (`CBRANCH`) p-code op, exposing its
/// branch-condition operand.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.ConditionContext` in the Java source, which
/// `extends PcodeContext` and adds nothing else. Following this crate's
/// composition-over-inheritance convention, this wraps a `PcodeContext` by composition instead,
/// re-exposing the members Java inherits unmodified.
#[derive(Clone, Debug)]
pub struct ConditionContext {
    base: PcodeContext,
}

impl ConditionContext {
    /// Java: `ConditionContext(PcodeOp op)`.
    ///
    /// Java's constructor also asserts `op.getOpcode() == PcodeOp.CBRANCH` -- a Java `assert`
    /// statement, which (per this crate's convention for Java `assert`, as opposed to an
    /// unconditional `throw`) is compiled out of production Java builds by default. This port
    /// models it the same way, via `debug_assert_eq!`.
    pub fn new(op: PcodeOp) -> Self {
        debug_assert_eq!(
            op.get_opcode(),
            OpCode::CBranch,
            "Java: `assert (op.getOpcode() == PcodeOp.CBRANCH);`"
        );
        Self { base: PcodeContext::new(op) }
    }

    /// Java: the inherited `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        self.base.get_op()
    }

    /// Java: the inherited `location()`.
    pub fn location(&self) -> PcodeLocation {
        self.base.location()
    }

    /// Java: the inherited `basicExpr()`.
    pub fn basic_expr(&self) -> VarnodeContext {
        self.base.basic_expr()
    }

    /// Java: the inherited `opcode()`.
    pub fn opcode(&self) -> OpCode {
        self.base.opcode()
    }

    /// Java: the inherited `getNumInputs()`.
    pub fn get_num_inputs(&self) -> i32 {
        self.base.get_num_inputs()
    }

    /// The branch condition operand: the op's second input (index 1).
    ///
    /// Java: `expression()`. Java's method also asserts `op.getInputs().length <= 2`; modeled the
    /// same way as the constructor's assertion, via `debug_assert!`.
    pub fn expression(&self) -> VarnodeContext {
        debug_assert!(
            self.base.get_op().get_inputs().len() <= 2,
            "Java: `assert (op.getInputs().length <= 2);`"
        );
        VarnodeContext::new(
            self.base
                .get_op()
                .get_input(1)
                .cloned()
                .expect("ConditionContext::expression: op has no input at index 1"),
        )
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

    fn cbranch_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::CBranch, seq, inputs, None)
    }

    #[test]
    fn expression_wraps_the_second_input_the_branch_condition() {
        let space = ram_space();
        let target = varnode(&space, 0x2000, 4);
        let condition = varnode(&space, 0x10, 1);
        let op = cbranch_op(vec![target, condition.clone()]);

        let ctx = ConditionContext::new(op);
        let expr = ctx.expression();

        assert_eq!(expr.varnode(), &condition);
    }

    #[test]
    fn get_op_opcode_and_num_inputs_delegate_to_the_base_context() {
        let space = ram_space();
        let op = cbranch_op(vec![varnode(&space, 0x2000, 4), varnode(&space, 0x10, 1)]);
        let op_clone = op.clone();
        let ctx = ConditionContext::new(op);

        assert_eq!(ctx.get_op(), &op_clone);
        assert_eq!(ctx.opcode(), OpCode::CBranch);
        assert_eq!(ctx.get_num_inputs(), 2);
    }

    #[test]
    #[should_panic(expected = "assert (op.getOpcode() == PcodeOp.CBRANCH)")]
    fn constructor_panics_in_debug_builds_for_a_non_cbranch_op() {
        let space = ram_space();
        let op = PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(Address::new(space.clone(), 0x1000), 0),
            vec![varnode(&space, 0x10, 4)],
            None,
        );
        let _ = ConditionContext::new(op);
    }

    #[test]
    #[should_panic(expected = "op has no input at index 1")]
    fn expression_panics_when_there_is_no_second_input() {
        let space = ram_space();
        let op = cbranch_op(vec![varnode(&space, 0x2000, 4)]);
        let ctx = ConditionContext::new(op);
        let _ = ctx.expression();
    }
}
