//! Port of `ghidra.lisa.pcode.expressions.PcodeBinaryExpression`.

use crate::feature::lisa::pcode::contexts::binary_expr_context::BinaryExprContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator;
use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};
use crate::program::model::pcode::OpCode;

/// The binary-operator tag a [`PcodeBinaryExpression`] carries.
///
/// Mirrors the Java constructor's `switch (ctx.op.getOpcode())`, which selects among several of
/// LiSA's built-in `it.unive.lisa.symbolic.value.operator.binary.BinaryOperator` singletons, or
/// falls back to a fresh [`PcodeBinaryOperator`] for every opcode not specifically recognized.
/// LiSA's `LogicalAnd`/`LogicalOr`/`ComparisonEq`/`ComparisonNe`/`ComparisonLe`/`ComparisonLt`
/// singleton classes are an external third-party dependency with no Rust port anywhere in this
/// crate (the same situation [`PcodeBinaryOperator`]'s own docs describe), so each is represented
/// here as a unit variant instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PcodeBinaryExpressionOperator {
    /// Java: `LogicalAnd.INSTANCE`, for `PcodeOp.BOOL_AND`.
    LogicalAnd,
    /// Java: `LogicalOr.INSTANCE`, for `PcodeOp.BOOL_OR`.
    LogicalOr,
    /// Java: `ComparisonEq.INSTANCE`, for `PcodeOp.INT_EQUAL`/`PcodeOp.FLOAT_EQUAL`.
    ComparisonEq,
    /// Java: `ComparisonNe.INSTANCE`, for `PcodeOp.INT_NOTEQUAL`/`PcodeOp.FLOAT_NOTEQUAL`.
    ComparisonNe,
    /// Java: `ComparisonLe.INSTANCE`, for `PcodeOp.INT_LESSEQUAL`/`PcodeOp.INT_SLESSEQUAL`/
    /// `PcodeOp.FLOAT_LESSEQUAL`.
    ComparisonLe,
    /// Java: `ComparisonLt.INSTANCE`, for `PcodeOp.INT_LESS`/`PcodeOp.INT_SLESS`/
    /// `PcodeOp.INT_SBORROW`/`PcodeOp.FLOAT_LESS`.
    ///
    /// # Java quirk preserved
    ///
    /// `PcodeOp.INT_SBORROW` maps to the same `ComparisonLt` operator as the genuine less-than
    /// opcodes, per the Java source's own comment: `// NB: Some chance we're going to get burned
    /// by including SBORROW here`. `INT_SBORROW` actually computes signed-overflow-on-subtract,
    /// not "less than" -- a deliberately flagged, not-yet-resolved approximation in the original
    /// Java, reproduced here as-is rather than silently fixed.
    ComparisonLt,
    /// Java: `new PcodeBinaryOperator(ctx.op)`, the `default` arm -- every opcode not specifically
    /// matched above.
    Other(PcodeBinaryOperator),
}

/// A binary p-code expression usable as a LiSA `BinaryExpression` node.
///
/// Corresponds to `ghidra.lisa.pcode.expressions.PcodeBinaryExpression` in the Java source, which
/// `extends it.unive.lisa.program.cfg.statement.BinaryExpression`. As with
/// [`PcodeVarargsExpression`](crate::feature::lisa::pcode::expressions::pcode_varargs_expression::PcodeVarargsExpression)'s
/// docs describe for its own `NaryExpression` base, the full LiSA CFG/analysis framework this
/// class's base and its `fwdBinarySemantics` override are built on has no Rust port in this crate.
/// Following that established convention:
///
/// * This struct holds the data Java's `BinaryExpression` constructor call (`super(cfg,
///   ctx.location(), ctx.mnemonic(),
///   cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), left, right)`)
///   actually computes and stores, rather than re-deriving a `BinaryExpression` base class.
/// * Java's `CFG cfg` is stored purely as an identity/owning-graph reference, mirrored here as a
///   bare `cfg_id: u64` opaque handle, the same simplification
///   [`PcodeTernaryExpression`](crate::feature::lisa::pcode::expressions::pcode_ternary_expression::PcodeTernaryExpression)
///   already applies to the same field.
/// * Java's `Expression left`/`right` operands are of LiSA's unported `Expression` type; this
///   struct is generic over `E`, the caller's chosen stand-in for it.
/// * `fwdBinarySemantics` (the class's only real logic, beyond simple plumbing) is ported as
///   [`PcodeBinaryExpression::fwd_binary_semantics`] against a small local
///   [`BinaryAnalysisState`] trait that narrows LiSA's `AnalysisState`/`AbstractState` down to
///   exactly the one operation it actually invokes (`state.smallStepSemantics(...)`) -- see that
///   trait's own docs.
#[derive(Clone, Debug)]
pub struct PcodeBinaryExpression<E> {
    /// Opaque handle standing in for the owning `CFG`. See the struct docs.
    pub cfg_id: u64,
    /// Java: `ctx.location()`, passed to the `BinaryExpression` superclass constructor.
    pub location: PcodeLocation,
    /// Java: `ctx.mnemonic()`, passed to the `BinaryExpression` superclass constructor as this
    /// expression's name.
    pub mnemonic: String,
    /// Java: `cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType()`, passed to
    /// the `BinaryExpression` superclass constructor as this expression's static type. Always the
    /// integer type, matching Java's hardcoded `getIntegerType()` call.
    pub static_type: PcodeType,
    /// Java: `this.operator = switch (ctx.op.getOpcode()) { ... };`. See [`PcodeBinaryExpression::new`]'s
    /// docs.
    pub operator: PcodeBinaryExpressionOperator,
    /// Java: `Expression left`, passed to the `BinaryExpression` superclass constructor as this
    /// expression's first operand.
    pub left: E,
    /// Java: `Expression right`, passed to the `BinaryExpression` superclass constructor as this
    /// expression's second operand.
    pub right: E,
}

impl<E> PcodeBinaryExpression<E> {
    /// Java: `PcodeBinaryExpression(CFG cfg, BinaryExprContext ctx, Expression left, Expression
    /// right)`.
    ///
    /// Selects [`PcodeBinaryExpressionOperator`] per `ctx.op.getOpcode()`, matching Java's
    /// `switch` exactly -- see the enum's own per-variant docs (especially
    /// [`PcodeBinaryExpressionOperator::ComparisonLt`]'s preserved `INT_SBORROW` quirk).
    pub fn new(cfg_id: u64, ctx: &BinaryExprContext, left: E, right: E) -> Self {
        let operator = match ctx.op.get_opcode() {
            OpCode::BoolAnd => PcodeBinaryExpressionOperator::LogicalAnd,
            OpCode::BoolOr => PcodeBinaryExpressionOperator::LogicalOr,
            OpCode::IntEqual | OpCode::FloatEqual => PcodeBinaryExpressionOperator::ComparisonEq,
            OpCode::IntNotEqual | OpCode::FloatNotEqual => {
                PcodeBinaryExpressionOperator::ComparisonNe
            }
            OpCode::IntLessEqual | OpCode::IntSlessEqual | OpCode::FloatLessEqual => {
                PcodeBinaryExpressionOperator::ComparisonLe
            }
            OpCode::IntLess | OpCode::IntSless | OpCode::IntSborrow | OpCode::FloatLess => {
                PcodeBinaryExpressionOperator::ComparisonLt
            }
            _ => PcodeBinaryExpressionOperator::Other(PcodeBinaryOperator::new(ctx.op.clone())),
        };

        Self {
            cfg_id,
            location: ctx.location(),
            mnemonic: ctx.mnemonic().to_string(),
            static_type: PcodeTypeSystem.integer_type(),
            operator,
            left,
            right,
        }
    }

    /// Java: `protected int compareSameClassAndParams(Statement o)`, `return 0; // no extra
    /// fields to compare`. Always `0`, regardless of `other` -- mirrored exactly, including the
    /// (unused) parameter, per this crate's convention of faithfully reproducing such trivial
    /// overrides (see
    /// [`PcodeTernaryExpression::compare_same_class_and_params`](crate::feature::lisa::pcode::expressions::pcode_ternary_expression::PcodeTernaryExpression::compare_same_class_and_params)'s
    /// own docs for the same pattern).
    pub fn compare_same_class_and_params(&self, other: &Self) -> i32 {
        let _ = other;
        0
    }

    /// Java: `public BinaryOperator getOperator()`.
    pub fn get_operator(&self) -> &PcodeBinaryExpressionOperator {
        &self.operator
    }
}

/// Stand-in for the subset of LiSA's `AnalysisState<A>` that
/// [`PcodeBinaryExpression::fwd_binary_semantics`] actually touches: evaluating a binary
/// expression (two operands, operator, static type, location) against a state. See
/// [`PcodeBinaryExpression`]'s own docs for why the full LiSA framework isn't ported.
///
/// Generic over `Expr`, the same operand stand-in [`PcodeBinaryExpression<E>`] is generic over
/// (LiSA's `SymbolicExpression`).
pub trait BinaryAnalysisState<Expr>: Sized {
    /// Mirrors evaluating `state.smallStepSemantics(new BinaryExpression(getStaticType(), left,
    /// right, getOperator(), getLocation()), this)` -- i.e. the abstract semantics of
    /// `operator(left, right)` against this state.
    fn small_step_binary(
        &self,
        static_type: &PcodeType,
        left: &Expr,
        right: &Expr,
        operator: &PcodeBinaryExpressionOperator,
        location: &PcodeLocation,
    ) -> Self;
}

impl<E> PcodeBinaryExpression<E> {
    /// Java: `<A extends AbstractState<A>> AnalysisState<A> fwdBinarySemantics(
    /// InterproceduralAnalysis<A> interprocedural, AnalysisState<A> state, SymbolicExpression
    /// left, SymbolicExpression right, StatementStore<A> expressions) throws SemanticException`.
    ///
    /// Java's `interprocedural`/`expressions` parameters are not needed by this narrowed port --
    /// see [`BinaryAnalysisState`]'s docs.
    pub fn fwd_binary_semantics<S>(&self, state: &S, left: &E, right: &E) -> S
    where
        S: BinaryAnalysisState<E>,
    {
        state.small_step_binary(&self.static_type, left, right, &self.operator, &self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{PcodeOp, SequenceNumber, Varnode};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &std::sync::Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn binary_op(opcode: OpCode, inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, inputs, None)
    }

    fn two_inputs(space: &std::sync::Arc<AddressSpace>) -> Vec<Varnode> {
        vec![varnode(space, 0x10, 4), varnode(space, 0x14, 4)]
    }

    fn binary_ctx(opcode: OpCode, inputs: Vec<Varnode>) -> BinaryExprContext {
        let op = binary_op(opcode, inputs);
        let pcode_ctx = PcodeContext::new(op);
        BinaryExprContext::new(&pcode_ctx)
    }

    #[test]
    fn new_captures_location_mnemonic_type_and_operands() {
        let space = ram_space();
        let ctx = binary_ctx(OpCode::IntAdd, two_inputs(&space));
        let expected_location = ctx.location();
        let expected_mnemonic = ctx.mnemonic().to_string();

        let expr = PcodeBinaryExpression::new(9, &ctx, "l", "r");

        assert_eq!(expr.cfg_id, 9);
        assert_eq!(expr.location, expected_location);
        assert_eq!(expr.mnemonic, expected_mnemonic);
        assert_eq!(expr.static_type, PcodeType::Int32);
        assert_eq!(expr.left, "l");
        assert_eq!(expr.right, "r");
    }

    #[test]
    fn operator_selects_logical_and_for_bool_and() {
        let ctx = binary_ctx(OpCode::BoolAnd, two_inputs(&ram_space()));
        let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
        assert_eq!(*expr.get_operator(), PcodeBinaryExpressionOperator::LogicalAnd);
    }

    #[test]
    fn operator_selects_logical_or_for_bool_or() {
        let ctx = binary_ctx(OpCode::BoolOr, two_inputs(&ram_space()));
        let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
        assert_eq!(*expr.get_operator(), PcodeBinaryExpressionOperator::LogicalOr);
    }

    #[test]
    fn operator_selects_comparison_eq_for_int_and_float_equal() {
        for opcode in [OpCode::IntEqual, OpCode::FloatEqual] {
            let ctx = binary_ctx(opcode, two_inputs(&ram_space()));
            let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
            assert_eq!(
                *expr.get_operator(),
                PcodeBinaryExpressionOperator::ComparisonEq,
                "opcode {opcode:?} took a different path"
            );
        }
    }

    #[test]
    fn operator_selects_comparison_ne_for_int_and_float_notequal() {
        for opcode in [OpCode::IntNotEqual, OpCode::FloatNotEqual] {
            let ctx = binary_ctx(opcode, two_inputs(&ram_space()));
            let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
            assert_eq!(
                *expr.get_operator(),
                PcodeBinaryExpressionOperator::ComparisonNe,
                "opcode {opcode:?} took a different path"
            );
        }
    }

    #[test]
    fn operator_selects_comparison_le_for_lessequal_variants() {
        for opcode in [OpCode::IntLessEqual, OpCode::IntSlessEqual, OpCode::FloatLessEqual] {
            let ctx = binary_ctx(opcode, two_inputs(&ram_space()));
            let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
            assert_eq!(
                *expr.get_operator(),
                PcodeBinaryExpressionOperator::ComparisonLe,
                "opcode {opcode:?} took a different path"
            );
        }
    }

    #[test]
    fn operator_selects_comparison_lt_for_less_variants_including_sborrow() {
        // Preserved Java quirk: INT_SBORROW maps to ComparisonLt alongside the genuine
        // less-than opcodes -- see PcodeBinaryExpressionOperator::ComparisonLt's docs.
        for opcode in [OpCode::IntLess, OpCode::IntSless, OpCode::IntSborrow, OpCode::FloatLess] {
            let ctx = binary_ctx(opcode, two_inputs(&ram_space()));
            let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
            assert_eq!(
                *expr.get_operator(),
                PcodeBinaryExpressionOperator::ComparisonLt,
                "opcode {opcode:?} took a different path"
            );
        }
    }

    #[test]
    fn operator_falls_back_to_a_plain_pcode_binary_operator_for_unmatched_opcodes() {
        let ctx = binary_ctx(OpCode::IntAdd, two_inputs(&ram_space()));
        let expected = PcodeBinaryOperator::new(ctx.op.clone());
        let expr = PcodeBinaryExpression::new(1, &ctx, 0, 0);
        assert_eq!(*expr.get_operator(), PcodeBinaryExpressionOperator::Other(expected));
    }

    #[test]
    fn compare_same_class_and_params_is_always_zero() {
        let ctx = binary_ctx(OpCode::IntAdd, two_inputs(&ram_space()));
        let a = PcodeBinaryExpression::new(1, &ctx, 1, 2);
        let b = PcodeBinaryExpression::new(2, &ctx, 3, 4);
        assert_eq!(a.compare_same_class_and_params(&b), 0);
        assert_eq!(b.compare_same_class_and_params(&a), 0);
    }

    /// A tiny abstract-state double recording the last binary evaluation it was asked to perform,
    /// enough to prove `fwd_binary_semantics` threads its arguments through correctly.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LogState(Option<(PcodeType, String, String, PcodeBinaryExpressionOperator, String)>);

    impl BinaryAnalysisState<String> for LogState {
        fn small_step_binary(
            &self,
            static_type: &PcodeType,
            left: &String,
            right: &String,
            operator: &PcodeBinaryExpressionOperator,
            location: &PcodeLocation,
        ) -> Self {
            LogState(Some((
                *static_type,
                left.clone(),
                right.clone(),
                operator.clone(),
                location.to_string(),
            )))
        }
    }

    #[test]
    fn fwd_binary_semantics_evaluates_operator_of_left_right_against_the_state() {
        let ctx = binary_ctx(OpCode::BoolAnd, two_inputs(&ram_space()));
        let expr: PcodeBinaryExpression<String> =
            PcodeBinaryExpression::new(1, &ctx, "unused-l".to_string(), "unused-r".to_string());
        let state = LogState(None);

        let result =
            expr.fwd_binary_semantics(&state, &"L".to_string(), &"R".to_string());

        assert_eq!(
            result,
            LogState(Some((
                expr.static_type,
                "L".to_string(),
                "R".to_string(),
                expr.operator.clone(),
                expr.location.to_string(),
            )))
        );
    }
}
