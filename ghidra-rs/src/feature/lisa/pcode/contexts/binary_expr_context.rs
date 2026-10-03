//! Port of `ghidra.lisa.pcode.contexts.BinaryExprContext`.

use std::fmt;

use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::statement_context::StatementContext;
use crate::feature::lisa::pcode::contexts::var_def_context::VarDefContext;
use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::program::model::pcode::{OpCode, PcodeOp};

/// Stand-in for Java's static-type erasure in `BinaryExprContext.left`/`.right`: both fields are
/// declared `VarnodeContext`, but [`BinaryExprContext::from_statement_context`] (Java's
/// `BinaryExprContext(StatementContext ctx)`, used "for TypeConv" per the Java source's own
/// comment) actually stores a [`VarDefContext`] into `left` via `ctx.target()`. Java relies on
/// runtime polymorphism there: a later `left.isConstant()` call dispatches to `VarDefContext`'s
/// override (always `false`), not `VarnodeContext`'s own space-derived answer.
///
/// This trait captures the handful of members both [`VarnodeContext`] and [`VarDefContext`]
/// already expose under identical names, so `left`/`right` can be boxed trait objects that
/// preserve this override dispatch rather than a single concrete type that would lose it.
pub trait VarnodeLike: fmt::Debug {
    /// Dispatches to [`VarnodeContext::is_constant`] or [`VarDefContext::is_constant`] (always
    /// `false`), depending on which concrete type is boxed.
    fn is_constant(&self) -> bool;
    /// Dispatches to [`VarnodeContext::get_size`] or [`VarDefContext::get_size`].
    fn get_size(&self) -> i32;
    /// Dispatches to [`VarnodeContext::get_offset`] or [`VarDefContext::get_offset`].
    fn get_offset(&self) -> i64;
    /// Dispatches to [`VarnodeContext::get_text`] or [`VarDefContext::get_text`].
    fn get_text(&self) -> String;
}

impl VarnodeLike for VarnodeContext {
    fn is_constant(&self) -> bool {
        VarnodeContext::is_constant(self)
    }
    fn get_size(&self) -> i32 {
        VarnodeContext::get_size(self)
    }
    fn get_offset(&self) -> i64 {
        VarnodeContext::get_offset(self)
    }
    fn get_text(&self) -> String {
        VarnodeContext::get_text(self)
    }
}

impl VarnodeLike for VarDefContext {
    fn is_constant(&self) -> bool {
        VarDefContext::is_constant(self)
    }
    fn get_size(&self) -> i32 {
        VarDefContext::get_size(self)
    }
    fn get_offset(&self) -> i64 {
        VarDefContext::get_offset(self)
    }
    fn get_text(&self) -> String {
        VarDefContext::get_text(self)
    }
}

/// The two operands of a binary p-code operation, split out into named `left`/`right` operand
/// contexts.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.BinaryExprContext` in the Java source. As with
/// [`TernaryExprContext`](super::ternary_expr_context::TernaryExprContext) and
/// [`UnaryExprContext`](super::unary_expr_context::UnaryExprContext), Java's class does not
/// `extend PcodeContext` -- it merely takes one in its constructor and copies its `op` field out
/// -- so this is a plain struct, not a composition wrapper. Unlike those siblings, Java gives
/// this class *two* constructors (see [`BinaryExprContext::new`]/
/// [`BinaryExprContext::from_statement_context`]), and `left`/`right` are declared `VarnodeContext`
/// rather than an always-fresh `VarnodeContext`; see [`VarnodeLike`]'s docs for why they are boxed
/// trait objects here instead.
#[derive(Debug)]
pub struct BinaryExprContext {
    /// The wrapped p-code operation. Mirrors the Java class's public `op` field.
    pub op: PcodeOp,
    /// The left operand. Mirrors the Java class's public `left` field.
    pub left: Box<dyn VarnodeLike>,
    /// The right operand. Mirrors the Java class's public `right` field.
    pub right: Box<dyn VarnodeLike>,
}

impl BinaryExprContext {
    /// Java: `BinaryExprContext(PcodeContext ctx)`.
    ///
    /// # Panics
    ///
    /// If `ctx`'s op has fewer than two inputs. Java's `op.getInput(i)` instead returns `null`
    /// there; see
    /// [`PcodeContext::basic_expr`](crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext::basic_expr)'s
    /// docs for why this port panics immediately instead, at the point Java's `null` would first
    /// become unusable.
    pub fn new(ctx: &PcodeContext) -> Self {
        let op = ctx.get_op().clone();
        let left = VarnodeContext::new(
            op.get_input(0).cloned().expect("BinaryExprContext::new: op has no input at index 0"),
        );
        let right = VarnodeContext::new(
            op.get_input(1).cloned().expect("BinaryExprContext::new: op has no input at index 1"),
        );
        Self { op, left: Box::new(left), right: Box::new(right) }
    }

    /// Java: `BinaryExprContext(StatementContext ctx)`, with the Java source's own comment `//
    /// Used for TypeConv`.
    ///
    /// # Panics
    ///
    /// If `ctx`'s target is unavailable (see
    /// [`StatementContext::target`](crate::feature::lisa::pcode::contexts::statement_context::StatementContext::target)'s
    /// docs) or `ctx`'s op has no input at index 0.
    pub fn from_statement_context(ctx: &StatementContext) -> Self {
        let op = ctx.get_op().clone();
        let left = ctx.target().clone();
        let right = VarnodeContext::new(
            op.get_input(0)
                .cloned()
                .expect("BinaryExprContext::from_statement_context: op has no input at index 0"),
        );
        Self { op, left: Box::new(left), right: Box::new(right) }
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

    fn const_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    fn varnode(space: &std::sync::Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn binary_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::IntAdd, seq, inputs, None)
    }

    #[test]
    fn new_splits_the_first_two_inputs_into_left_and_right() {
        let space = ram_space();
        let a = varnode(&space, 0x10, 4);
        let b = varnode(&space, 0x14, 4);
        let op = binary_op(vec![a.clone(), b.clone()]);
        let pcode_ctx = PcodeContext::new(op);

        let binary = BinaryExprContext::new(&pcode_ctx);

        assert_eq!(binary.left.get_offset(), a.get_offset());
        assert_eq!(binary.right.get_offset(), b.get_offset());
    }

    #[test]
    fn new_left_is_constant_reflects_the_underlying_varnode_space() {
        let space = const_space();
        let ram = ram_space();
        let a = varnode(&space, 7, 4);
        let b = varnode(&ram, 0x14, 4);
        let op = binary_op(vec![a, b]);
        let pcode_ctx = PcodeContext::new(op);

        let binary = BinaryExprContext::new(&pcode_ctx);

        assert!(binary.left.is_constant());
        assert!(!binary.right.is_constant());
    }

    #[test]
    fn opcode_mnemonic_and_location_read_through_the_op() {
        let space = ram_space();
        let op = binary_op(vec![varnode(&space, 0x10, 4), varnode(&space, 0x14, 4)]);
        let op_clone = op.clone();
        let pcode_ctx = PcodeContext::new(op);

        let binary = BinaryExprContext::new(&pcode_ctx);

        assert_eq!(binary.opcode(), OpCode::IntAdd);
        assert_eq!(binary.mnemonic(), op_clone.get_mnemonic());
        assert_eq!(binary.location(), PcodeLocation::new(op_clone));
    }

    #[test]
    #[should_panic(expected = "op has no input at index 1")]
    fn new_panics_when_there_is_no_second_input() {
        let space = ram_space();
        let op = binary_op(vec![varnode(&space, 0x10, 4)]);
        let pcode_ctx = PcodeContext::new(op);
        let _ = BinaryExprContext::new(&pcode_ctx);
    }

    #[test]
    fn from_statement_context_uses_the_targets_constant_override() {
        // The STORE op's "defined" varnode (its target, via StatementContext::target()) is input
        // 2, which we deliberately place in the constant space here. Even though its underlying
        // varnode sits in the constant space, `VarDefContext::is_constant()` unconditionally
        // returns `false` -- the same override Java's runtime polymorphism preserves when
        // `ctx.target()` (a `VarDefContext`) is assigned into the `VarnodeContext`-typed `left`
        // field. See the `VarnodeLike` docs.
        let space = ram_space();
        let const_sp = const_space();
        let in0 = varnode(&space, 0x10, 4);
        let in1 = varnode(&space, 0x14, 4);
        let target = varnode(&const_sp, 3, 4);
        let op = PcodeOp::new(
            OpCode::Store,
            SequenceNumber::new(Address::new(space.clone(), 0x1000), 0),
            vec![in0.clone(), in1, target.clone()],
            None,
        );
        let stmt_ctx = StatementContext::from_op(op);

        let binary = BinaryExprContext::from_statement_context(&stmt_ctx);

        assert_eq!(binary.left.get_offset(), target.get_offset());
        assert!(!binary.left.is_constant(), "VarDefContext::is_constant() is always false");
        assert_eq!(binary.right.get_offset(), in0.get_offset());
        assert!(!binary.right.is_constant());
    }

    #[test]
    #[should_panic(expected = "StatementContext::target")]
    fn from_statement_context_panics_when_there_is_no_target() {
        let space = ram_space();
        let op = PcodeOp::new(
            OpCode::Store,
            SequenceNumber::new(Address::new(space.clone(), 0x1000), 0),
            vec![varnode(&space, 0x10, 4)],
            None,
        );
        let stmt_ctx = StatementContext::from_op(op);
        let _ = BinaryExprContext::from_statement_context(&stmt_ctx);
    }
}
