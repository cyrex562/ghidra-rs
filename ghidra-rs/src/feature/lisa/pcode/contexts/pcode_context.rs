//! Port of `ghidra.lisa.pcode.contexts.PcodeContext`.

use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::PcodeOp;

/// Wraps a [`PcodeOp`], exposing the properties the LiSA analysis framework needs when reasoning
/// about a p-code operation's context.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.PcodeContext` in the Java source, the shared base of
/// (currently unported) siblings `CallContext`/`ConditionContext`/`StatementContext`, and the
/// direct base [`VarDefContext`](super::var_def_context::VarDefContext) composes over instead
/// (that class extends `VarnodeContext`, not this one -- see its own module docs).
///
/// # Deviations from Java
///
/// Java's `op` field is a plain (nullable) `PcodeOp op;`, and [`PcodeContext::location`] defends
/// against `op == null` by returning `SyntheticLocation.INSTANCE`. Every real construction path in
/// this codebase -- the sole public constructor here, and every subclass's `super(op)` call --
/// always supplies a real op, so that defensive branch is unreachable in practice. This port
/// therefore stores `op` directly (not `Option<PcodeOp>`) and always returns a real
/// [`PcodeLocation`]; `it.unive.lisa.program.SyntheticLocation` has no port in this crate (nothing
/// else needs it), so the null-`op` branch is not modeled. A future subclass that legitimately
/// needs a context with no op would need both `op: Option<PcodeOp>` here and a `SyntheticLocation`
/// port.
#[derive(Clone, Debug)]
pub struct PcodeContext {
    /// The wrapped p-code operation. Mirrors the Java class's protected `op` field.
    op: PcodeOp,
}

impl PcodeContext {
    /// Java: `PcodeContext(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Java: `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        &self.op
    }

    /// Java: `location()`. See the struct docs for why the `op == null` branch is not modeled.
    pub fn location(&self) -> PcodeLocation {
        PcodeLocation::new(self.op.clone())
    }

    /// Java: `basicExpr()`.
    ///
    /// # Panics
    ///
    /// If this op has no input at index 0. Java's `op.getInput(0)` instead returns `null` there
    /// (out-of-range indices are not an error in this crate's
    /// [`PcodeOp::get_input`](crate::program::model::pcode::PcodeOp::get_input)), which
    /// `VarnodeContext`'s constructor would then wrap as a `VarnodeContext` around a `null`
    /// varnode -- every later call on it would throw a `NullPointerException` in Java. This port
    /// panics immediately instead, at the point Java's `null` would first become unusable.
    pub fn basic_expr(&self) -> VarnodeContext {
        VarnodeContext::new(
            self.op
                .get_input(0)
                .cloned()
                .expect("PcodeContext::basic_expr: op has no input at index 0"),
        )
    }

    /// Java: `opcode()`.
    pub fn opcode(&self) -> crate::program::model::pcode::OpCode {
        self.op.get_opcode()
    }

    /// Java: `getNumInputs()`.
    pub fn get_num_inputs(&self) -> i32 {
        self.op.get_num_inputs() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &std::sync::Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn op_with_inputs(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, inputs, output)
    }

    #[test]
    fn get_op_returns_the_wrapped_op() {
        let op = op_with_inputs(OpCode::Copy, vec![], None);
        let ctx = PcodeContext::new(op.clone());
        assert_eq!(ctx.get_op(), &op);
    }

    #[test]
    fn opcode_and_num_inputs_read_through_the_op() {
        let space = ram_space();
        let a = varnode(&space, 0x10, 4);
        let b = varnode(&space, 0x14, 4);
        let op = op_with_inputs(OpCode::IntAdd, vec![a, b], None);
        let ctx = PcodeContext::new(op);

        assert_eq!(ctx.opcode(), OpCode::IntAdd);
        assert_eq!(ctx.get_num_inputs(), 2);
    }

    #[test]
    fn location_wraps_the_op_in_a_pcode_location_keyed_by_its_seqnum() {
        let op = op_with_inputs(OpCode::Copy, vec![], None);
        let ctx = PcodeContext::new(op.clone());

        let loc = ctx.location();
        assert_eq!(loc.get_opcode(), op.get_opcode());
        assert_eq!(loc, PcodeLocation::new(op));
    }

    #[test]
    fn basic_expr_wraps_the_first_input_varnode() {
        let space = ram_space();
        let input0 = varnode(&space, 0x20, 4);
        let op = op_with_inputs(OpCode::Copy, vec![input0.clone()], None);
        let ctx = PcodeContext::new(op);

        let expr = ctx.basic_expr();
        assert_eq!(expr.varnode(), &input0);
    }

    #[test]
    #[should_panic(expected = "op has no input at index 0")]
    fn basic_expr_panics_when_there_is_no_input_0() {
        let op = op_with_inputs(OpCode::Copy, vec![], None);
        let ctx = PcodeContext::new(op);
        let _ = ctx.basic_expr();
    }
}
