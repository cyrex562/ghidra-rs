//! Port of `ghidra.lisa.pcode.contexts.VarargsExprContext`.

use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// All operands of a variadic-input p-code operation.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.VarargsExprContext` in the Java source. As with
/// [`TernaryExprContext`](super::ternary_expr_context::TernaryExprContext) and
/// [`UnaryExprContext`](super::unary_expr_context::UnaryExprContext), Java's class does not
/// `extend PcodeContext` -- it merely takes one in its constructor and copies its `op` field out
/// -- so this is a plain struct with public fields mirroring Java's own public fields, not a
/// composition wrapper.
#[derive(Clone, Debug)]
pub struct VarargsExprContext {
    /// The wrapped p-code operation. Mirrors the Java class's public `op` field.
    pub op: PcodeOp,
    /// One [`VarnodeContext`] per input of `op`, in order. Mirrors the Java class's public
    /// `varargs` array field (Java: `VarnodeContext[] varargs`).
    pub varargs: Vec<VarnodeContext>,
}

impl VarargsExprContext {
    /// Java: `VarargsExprContext(PcodeContext ctx)`.
    pub fn new(ctx: &PcodeContext) -> Self {
        let op = ctx.get_op().clone();
        let varargs = (0..op.get_num_inputs())
            .map(|i| {
                VarnodeContext::new(
                    op.get_input(i)
                        .cloned()
                        .expect("VarargsExprContext::new: op input index out of range"),
                )
            })
            .collect();
        Self { op, varargs }
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

    fn call_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::Call, seq, inputs, None)
    }

    #[test]
    fn wraps_every_input_in_order() {
        let space = ram_space();
        let a = varnode(&space, 0x10, 4);
        let b = varnode(&space, 0x14, 4);
        let c = varnode(&space, 0x18, 8);
        let op = call_op(vec![a.clone(), b.clone(), c.clone()]);
        let pcode_ctx = PcodeContext::new(op);

        let varargs_ctx = VarargsExprContext::new(&pcode_ctx);

        let rendered: Vec<&Varnode> = varargs_ctx.varargs.iter().map(|v| v.varnode()).collect();
        assert_eq!(rendered, vec![&a, &b, &c]);
    }

    #[test]
    fn zero_inputs_yields_an_empty_varargs_list() {
        let op = call_op(vec![]);
        let pcode_ctx = PcodeContext::new(op);

        let varargs_ctx = VarargsExprContext::new(&pcode_ctx);

        assert!(varargs_ctx.varargs.is_empty());
    }

    #[test]
    fn opcode_mnemonic_and_location_read_through_the_op() {
        let space = ram_space();
        let op = call_op(vec![varnode(&space, 0x10, 4)]);
        let op_clone = op.clone();
        let pcode_ctx = PcodeContext::new(op);

        let varargs_ctx = VarargsExprContext::new(&pcode_ctx);

        assert_eq!(varargs_ctx.opcode(), OpCode::Call);
        assert_eq!(varargs_ctx.mnemonic(), op_clone.get_mnemonic());
        assert_eq!(varargs_ctx.location(), PcodeLocation::new(op_clone));
    }
}
