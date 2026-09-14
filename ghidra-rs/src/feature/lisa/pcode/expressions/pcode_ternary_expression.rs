//! Port of `ghidra.lisa.pcode.expressions.PcodeTernaryExpression`.

use crate::feature::lisa::pcode::contexts::ternary_expr_context::TernaryExprContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::feature::lisa::pcode::statements::pcode_ternary_operator::PcodeTernaryOperator;
use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};

/// A ternary p-code expression usable as a LiSA `TernaryExpression` node.
///
/// Corresponds to `ghidra.lisa.pcode.expressions.PcodeTernaryExpression` in the Java source,
/// which `extends it.unive.lisa.program.cfg.statement.TernaryExpression`. As with
/// [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)'s
/// docs describe for its own `NaryExpression` base, the full LiSA CFG/analysis framework this
/// class's base and its `fwdTernarySemantics` override are built on has no Rust port in this
/// crate. Following that established convention:
///
/// * This struct holds the data Java's `TernaryExpression` constructor call (`super(cfg,
///   ctx.location(), ctx.mnemonic(),
///   cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), left, middle,
///   right)`) actually computes and stores, rather than re-deriving a `TernaryExpression` base
///   class -- the same pattern
///   [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)
///   follows for its own (also explicitly-typed) `NaryExpression` superclass constructor.
/// * Java's `CFG cfg` is stored purely as an identity/owning-graph reference, mirrored here as a
///   bare `cfg_id: u64` opaque handle, the same simplification
///   [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)
///   already applies to the same field.
/// * Java's `Expression left`/`middle`/`right` operands are of LiSA's unported `Expression` type;
///   this struct is generic over `E`, the caller's chosen stand-in for it.
/// * `fwdTernarySemantics` (the class's only real logic, beyond simple plumbing) is ported as
///   [`PcodeTernaryExpression::fwd_ternary_semantics`] against a small local
///   [`TernaryAnalysisState`] trait that narrows LiSA's `AnalysisState`/`AbstractState` down to
///   exactly the one operation it actually invokes (`state.smallStepSemantics(...)`) -- see that
///   trait's own docs.
#[derive(Clone, Debug)]
pub struct PcodeTernaryExpression<E> {
    /// Opaque handle standing in for the owning `CFG`. See the struct docs.
    pub cfg_id: u64,
    /// Java: `ctx.location()`, passed to the `TernaryExpression` superclass constructor.
    pub location: PcodeLocation,
    /// Java: `ctx.mnemonic()`, passed to the `TernaryExpression` superclass constructor as this
    /// expression's name.
    pub mnemonic: String,
    /// Java: `cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType()`, passed to
    /// the `TernaryExpression` superclass constructor as this expression's static type. Always
    /// the integer type, matching Java's hardcoded `getIntegerType()` call.
    pub static_type: PcodeType,
    /// Java: `this.operator = switch (ctx.op.getOpcode()) { default -> new
    /// PcodeTernaryOperator(ctx.op); };`. See [`PcodeTernaryExpression::new`]'s docs for the
    /// switch-with-only-a-default-arm quirk this preserves.
    pub operator: PcodeTernaryOperator,
    /// Java: `Expression left`, passed to the `TernaryExpression` superclass constructor as this
    /// expression's first operand.
    pub left: E,
    /// Java: `Expression middle`, passed to the `TernaryExpression` superclass constructor as
    /// this expression's second operand.
    pub middle: E,
    /// Java: `Expression right`, passed to the `TernaryExpression` superclass constructor as this
    /// expression's third operand.
    pub right: E,
}

impl<E> PcodeTernaryExpression<E> {
    /// Java: `PcodeTernaryExpression(CFG cfg, TernaryExprContext ctx, Expression left, Expression
    /// middle, Expression right)`.
    ///
    /// # Java quirk preserved
    ///
    /// Java's constructor body assigns `operator` via `switch (ctx.op.getOpcode()) { default ->
    /// new PcodeTernaryOperator(ctx.op); }` -- a switch expression with *only* a `default` arm
    /// and no other case labels at all. Since every possible opcode value falls through to
    /// `default`, `operator` is unconditionally `new PcodeTernaryOperator(ctx.op)` regardless of
    /// `ctx.op.getOpcode()`; the switch is effectively dead code (presumably a stub left in place
    /// for future opcode-specific operators that were never added). This port preserves that
    /// unconditional behavior faithfully rather than simplifying it away -- see
    /// [`operator_is_unconditionally_a_plain_ternary_operator`](tests::operator_is_unconditionally_a_plain_ternary_operator)
    /// below.
    pub fn new(cfg_id: u64, ctx: &TernaryExprContext, left: E, middle: E, right: E) -> Self {
        Self {
            cfg_id,
            location: ctx.location(),
            mnemonic: ctx.mnemonic().to_string(),
            static_type: PcodeTypeSystem.integer_type(),
            operator: PcodeTernaryOperator::new(ctx.op.clone()),
            left,
            middle,
            right,
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
/// [`PcodeTernaryExpression::fwd_ternary_semantics`] actually touches: evaluating a ternary
/// expression (three operands, operator, static type, location) against a state. See
/// [`PcodeTernaryExpression`]'s own docs for why the full LiSA framework isn't ported.
///
/// Generic over `Expr`, the same operand stand-in [`PcodeTernaryExpression<E>`] is generic over
/// (LiSA's `SymbolicExpression`).
pub trait TernaryAnalysisState<Expr>: Sized {
    /// Mirrors evaluating `state.smallStepSemantics(new TernaryExpression(getStaticType(), left,
    /// middle, right, operator, getLocation()), this)` -- i.e. the abstract semantics of
    /// `operator(left, middle, right)` against this state.
    fn small_step_ternary(
        &self,
        static_type: &PcodeType,
        left: &Expr,
        middle: &Expr,
        right: &Expr,
        operator: &PcodeTernaryOperator,
        location: &PcodeLocation,
    ) -> Self;
}

impl<E> PcodeTernaryExpression<E> {
    /// Java: `<A extends AbstractState<A>> AnalysisState<A> fwdTernarySemantics(
    /// InterproceduralAnalysis<A> interprocedural, AnalysisState<A> state, SymbolicExpression
    /// left, SymbolicExpression middle, SymbolicExpression right, StatementStore<A> expressions)
    /// throws SemanticException`.
    ///
    /// Java's `interprocedural`/`expressions` parameters are not needed by this narrowed port --
    /// see [`TernaryAnalysisState`]'s docs.
    pub fn fwd_ternary_semantics<S>(&self, state: &S, left: &E, middle: &E, right: &E) -> S
    where
        S: TernaryAnalysisState<E>,
    {
        state.small_step_ternary(&self.static_type, left, middle, right, &self.operator, &self.location)
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

    fn ternary_op(opcode: OpCode, inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, inputs, None)
    }

    fn ternary_ctx(opcode: OpCode, inputs: Vec<Varnode>) -> TernaryExprContext {
        let op = ternary_op(opcode, inputs);
        let pcode_ctx = PcodeContext::new(op);
        TernaryExprContext::new(&pcode_ctx)
    }

    fn three_inputs(space: &std::sync::Arc<AddressSpace>) -> Vec<Varnode> {
        vec![varnode(space, 0x10, 4), varnode(space, 0x14, 4), varnode(space, 0x18, 4)]
    }

    #[test]
    fn new_captures_location_mnemonic_type_operator_and_operands() {
        let space = ram_space();
        let ctx = ternary_ctx(OpCode::PtrAdd, three_inputs(&space));
        let expected_location = ctx.location();
        let expected_mnemonic = ctx.mnemonic().to_string();

        let expr = PcodeTernaryExpression::new(5, &ctx, "l", "m", "r");

        assert_eq!(expr.cfg_id, 5);
        assert_eq!(expr.location, expected_location);
        assert_eq!(expr.mnemonic, expected_mnemonic);
        assert_eq!(expr.static_type, PcodeType::Int32);
        assert_eq!(expr.left, "l");
        assert_eq!(expr.middle, "m");
        assert_eq!(expr.right, "r");
    }

    #[test]
    fn operator_is_unconditionally_a_plain_ternary_operator() {
        // Java's `switch (ctx.op.getOpcode()) { default -> new PcodeTernaryOperator(ctx.op); }`
        // has no case labels other than `default`, so `operator` is always
        // `PcodeTernaryOperator::new(ctx.op)` no matter what opcode the op actually has. Checked
        // across several different opcodes here to confirm none of them take a different path.
        let space = ram_space();
        for opcode in [OpCode::PtrAdd, OpCode::IntEqual, OpCode::CBranch, OpCode::Copy] {
            let ctx = ternary_ctx(opcode, three_inputs(&space));
            let expected_operator = PcodeTernaryOperator::new(ctx.op.clone());

            let expr = PcodeTernaryExpression::new(1, &ctx, "l", "m", "r");

            assert_eq!(expr.operator, expected_operator, "opcode {opcode:?} took a different path");
        }
    }

    #[test]
    fn compare_same_class_and_params_is_always_zero() {
        let ctx = ternary_ctx(OpCode::PtrAdd, three_inputs(&ram_space()));
        let a = PcodeTernaryExpression::new(1, &ctx, 1, 2, 3);
        let b = PcodeTernaryExpression::new(2, &ctx, 4, 5, 6);
        assert_eq!(a.compare_same_class_and_params(&b), 0);
        assert_eq!(b.compare_same_class_and_params(&a), 0);
    }

    /// A tiny abstract-state double recording the last ternary evaluation it was asked to
    /// perform, enough to prove `fwd_ternary_semantics` threads its arguments through correctly.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LogState(Option<(PcodeType, String, String, String, String, String)>);

    impl TernaryAnalysisState<String> for LogState {
        fn small_step_ternary(
            &self,
            static_type: &PcodeType,
            left: &String,
            middle: &String,
            right: &String,
            operator: &PcodeTernaryOperator,
            location: &PcodeLocation,
        ) -> Self {
            LogState(Some((
                *static_type,
                left.clone(),
                middle.clone(),
                right.clone(),
                operator.to_string(),
                location.to_string(),
            )))
        }
    }

    #[test]
    fn fwd_ternary_semantics_evaluates_operator_of_left_middle_right_against_the_state() {
        let space = ram_space();
        let ctx = ternary_ctx(OpCode::PtrAdd, three_inputs(&space));
        let expr: PcodeTernaryExpression<String> =
            PcodeTernaryExpression::new(1, &ctx, "unused-l".to_string(), "unused-m".to_string(), "unused-r".to_string());
        let state = LogState(None);

        let result = expr.fwd_ternary_semantics(
            &state,
            &"L".to_string(),
            &"M".to_string(),
            &"R".to_string(),
        );

        assert_eq!(
            result,
            LogState(Some((
                expr.static_type,
                "L".to_string(),
                "M".to_string(),
                "R".to_string(),
                expr.operator.to_string(),
                expr.location.to_string(),
            )))
        );
    }
}
