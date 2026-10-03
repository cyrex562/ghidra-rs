//! Port of `ghidra.lisa.pcode.expressions.PcodeUnaryExpression`.

use crate::feature::lisa::pcode::contexts::unary_expr_context::UnaryExprContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::feature::lisa::pcode::statements::pcode_unary_operator::PcodeUnaryOperator;

/// A unary p-code expression usable as a LiSA `UnaryExpression` node.
///
/// Corresponds to `ghidra.lisa.pcode.expressions.PcodeUnaryExpression` in the Java source, which
/// `extends it.unive.lisa.program.cfg.statement.UnaryExpression`. As with
/// [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)'s
/// docs describe for its own `NaryExpression` base, the full LiSA CFG/analysis framework this
/// class's base and its `fwdUnarySemantics` override are built on has no Rust port in this crate.
/// Following that established convention:
///
/// * This struct holds the data Java's `UnaryExpression` constructor call (`super(cfg,
///   ctx.location(), ctx.mnemonic(), expression)`) actually computes and stores, rather than
///   re-deriving a `UnaryExpression` base class. Unlike
///   [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)
///   (whose `NaryExpression` 4-arg superclass constructor overload takes an explicit static
///   type), this particular `UnaryExpression` superclass constructor overload does not -- so
///   there is no `static_type` field here.
/// * Java's `CFG cfg` is stored purely as an identity/owning-graph reference, mirrored here as a
///   bare `cfg_id: u64` opaque handle, the same simplification
///   [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)
///   already applies to the same field.
/// * Java's `Expression expression` (the sole operand) is of LiSA's unported `Expression` type;
///   this struct is generic over `E`, the caller's chosen stand-in for it.
/// * `fwdUnarySemantics` (the class's only real logic, beyond simple plumbing) is ported as
///   [`PcodeUnaryExpression::fwd_unary_semantics`] against a small local [`UnaryAnalysisState`]
///   trait that narrows LiSA's `AnalysisState`/`AbstractState` down to exactly the one operation
///   it actually invokes (`state.smallStepSemantics(...)`) -- see that trait's own docs.
#[derive(Clone, Debug)]
pub struct PcodeUnaryExpression<E> {
    /// Opaque handle standing in for the owning `CFG`. See the struct docs.
    pub cfg_id: u64,
    /// Java: `ctx.location()`, passed to the `UnaryExpression` superclass constructor.
    pub location: PcodeLocation,
    /// Java: `ctx.mnemonic()`, passed to the `UnaryExpression` superclass constructor as this
    /// expression's name.
    pub mnemonic: String,
    /// Java: `this.operator = new PcodeUnaryOperator(ctx.op);`.
    pub operator: PcodeUnaryOperator,
    /// Java: `Expression expression`, passed to the `UnaryExpression` superclass constructor as
    /// this expression's sole operand.
    pub expression: E,
}

impl<E> PcodeUnaryExpression<E> {
    /// Java: `PcodeUnaryExpression(CFG cfg, UnaryExprContext ctx, Expression expression)`.
    pub fn new(cfg_id: u64, ctx: &UnaryExprContext, expression: E) -> Self {
        Self {
            cfg_id,
            location: ctx.location(),
            mnemonic: ctx.mnemonic().to_string(),
            operator: PcodeUnaryOperator::new(ctx.op.clone()),
            expression,
        }
    }

    /// Java: `protected int compareSameClassAndParams(Statement o)`, `return 0; // no extra
    /// fields to compare`. Always `0`, regardless of `other` -- mirrored exactly, including the
    /// (unused) parameter, per this crate's convention of faithfully reproducing such trivial
    /// overrides (see
    /// [`PcodeVarargsExpression::compare_same_class_and_params`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression::compare_same_class_and_params)'s
    /// own docs for the same pattern).
    pub fn compare_same_class_and_params(&self, other: &Self) -> i32 {
        let _ = other;
        0
    }
}

/// Stand-in for the subset of LiSA's `AnalysisState<A>` that
/// [`PcodeUnaryExpression::fwd_unary_semantics`] actually touches: evaluating a unary expression
/// (operand, operator, location) against a state. See [`PcodeUnaryExpression`]'s own docs for why
/// the full LiSA framework isn't ported.
///
/// Generic over `Expr`, the same operand stand-in [`PcodeUnaryExpression<E>`] is generic over
/// (LiSA's `SymbolicExpression`).
pub trait UnaryAnalysisState<Expr>: Sized {
    /// Mirrors evaluating `state.smallStepSemantics(new UnaryExpression(expr.getStaticType(),
    /// expr, operator, location), this)` -- i.e. the abstract semantics of `operator(expr)`
    /// against this state. Java's `expr.getStaticType()` is folded into this contract (the
    /// implementor is expected to derive it from `expr` itself, same as Java does).
    fn small_step_unary(&self, expr: &Expr, operator: &PcodeUnaryOperator, location: &PcodeLocation) -> Self;
}

impl<E> PcodeUnaryExpression<E> {
    /// Java: `<A extends AbstractState<A>> AnalysisState<A> fwdUnarySemantics(
    /// InterproceduralAnalysis<A> interprocedural, AnalysisState<A> state, SymbolicExpression
    /// expr, StatementStore<A> expressions) throws SemanticException`.
    ///
    /// Java's `interprocedural`/`expressions` parameters (and `expr.getStaticType()`/
    /// `getLocation()`, folded into [`UnaryAnalysisState::small_step_unary`]'s contract) are not
    /// needed by this narrowed port -- see [`UnaryAnalysisState`]'s docs.
    pub fn fwd_unary_semantics<S>(&self, state: &S, expr: &E) -> S
    where
        S: UnaryAnalysisState<E>,
    {
        state.small_step_unary(expr, &self.operator, &self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};

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

    fn unary_ctx(inputs: Vec<Varnode>) -> UnaryExprContext {
        let op = unary_op(inputs);
        let pcode_ctx = PcodeContext::new(op);
        UnaryExprContext::new(&pcode_ctx)
    }

    #[test]
    fn new_captures_location_mnemonic_operator_and_expression() {
        let space = ram_space();
        let ctx = unary_ctx(vec![varnode(&space, 0x10, 4)]);
        let expected_location = ctx.location();
        let expected_mnemonic = ctx.mnemonic().to_string();
        let expected_operator = PcodeUnaryOperator::new(ctx.op.clone());

        let expr = PcodeUnaryExpression::new(3, &ctx, "operand");

        assert_eq!(expr.cfg_id, 3);
        assert_eq!(expr.location, expected_location);
        assert_eq!(expr.mnemonic, expected_mnemonic);
        assert_eq!(expr.operator, expected_operator);
        assert_eq!(expr.expression, "operand");
    }

    #[test]
    fn compare_same_class_and_params_is_always_zero() {
        let ctx = unary_ctx(vec![varnode(&ram_space(), 0x10, 4)]);
        let a = PcodeUnaryExpression::new(1, &ctx, 10);
        let b = PcodeUnaryExpression::new(2, &ctx, 20);
        assert_eq!(a.compare_same_class_and_params(&b), 0);
        assert_eq!(b.compare_same_class_and_params(&a), 0);
    }

    /// A tiny abstract-state double recording the last unary evaluation it was asked to perform,
    /// enough to prove `fwd_unary_semantics` threads `expr`/`operator`/`location` through
    /// correctly.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LogState(Option<(String, String, String)>);

    impl UnaryAnalysisState<String> for LogState {
        fn small_step_unary(
            &self,
            expr: &String,
            operator: &PcodeUnaryOperator,
            location: &PcodeLocation,
        ) -> Self {
            LogState(Some((expr.clone(), operator.to_string(), location.to_string())))
        }
    }

    #[test]
    fn fwd_unary_semantics_evaluates_operator_of_expr_against_the_state() {
        let space = ram_space();
        let ctx = unary_ctx(vec![varnode(&space, 0x10, 4)]);
        let expr: PcodeUnaryExpression<String> = PcodeUnaryExpression::new(1, &ctx, "irrelevant".to_string());
        let state = LogState(None);

        let result = expr.fwd_unary_semantics(&state, &"operand".to_string());

        assert_eq!(
            result,
            LogState(Some(("operand".to_string(), expr.operator.to_string(), expr.location.to_string())))
        );
    }
}
