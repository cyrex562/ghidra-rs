//! Port of `ghidra.lisa.pcode.expressions.PcodeVarargsExpression`.

use crate::feature::lisa::pcode::contexts::varargs_expr_context::VarargsExprContext;
use crate::feature::lisa::pcode::locations::pcode_location::PcodeLocation;
use crate::feature::lisa::pcode::types::pcode_type_system::{PcodeType, PcodeTypeSystem};

/// A variadic p-code expression usable as a LiSA `NaryExpression` node, with an "any one of my
/// operands may be true" (logical-OR) forward semantics.
///
/// Corresponds to `ghidra.lisa.pcode.expressions.PcodeVarargsExpression` in the Java source, which
/// `extends it.unive.lisa.program.cfg.statement.NaryExpression`. The full LiSA CFG/analysis
/// framework that base class (and this class's `fwdBinarySemantics`/`forwardSemanticsAux`
/// overrides) are built on -- `it.unive.lisa.program.cfg.CFG`,
/// `it.unive.lisa.program.cfg.statement.{Expression,Statement,NaryExpression}`,
/// `it.unive.lisa.analysis.{AbstractState,AnalysisState,StatementStore,SemanticException}`,
/// `it.unive.lisa.interprocedural.InterproceduralAnalysis`, `it.unive.lisa.symbolic.*` -- is an
/// external third-party dependency with no Rust port anywhere in this crate (the same situation
/// [`PcodeBinaryOperator`](crate::feature::lisa::pcode::statements::pcode_binary_operator::PcodeBinaryOperator)
/// and
/// [`PcodeNonRelationalValueDomain`](crate::feature::lisa::pcode::analyses::pcode_non_relational_value_domain::PcodeNonRelationalValueDomain)'s
/// docs describe). Following that established convention:
///
/// * Following this crate's composition-over-inheritance convention, this struct holds the data
///   Java's `NaryExpression` constructor call (`super(cfg, ctx.location(), ctx.mnemonic(),
///   cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType(), exps)`) actually
///   computes and stores, rather than re-deriving a `NaryExpression` base class.
/// * Java's `CFG cfg` is stored by the (unported) `NaryExpression` base purely as an identity/
///   owning-graph reference, never inspected by this class's own logic; mirrored here as a bare
///   `cfg_id: u64` opaque handle, the same simplification
///   [`PcodeNop`](crate::feature::lisa::pcode::statements::pcode_nop::PcodeNop) already applies to
///   the same field.
/// * Java's `Expression[] exps` (the vararg operands) are of LiSA's unported `Expression` type;
///   this struct is generic over `E`, the caller's chosen stand-in for a sub-expression, so the
///   structural shape (an ordered list of operands) is preserved without depending on LiSA.
/// * `fwdBinarySemantics`/`forwardSemanticsAux` (the class's only real logic, beyond simple
///   plumbing) are ported as [`PcodeVarargsExpression::fwd_binary_semantics`]/
///   [`PcodeVarargsExpression::forward_semantics_aux`] against a small local
///   [`VarargsAnalysisState`] trait that narrows LiSA's `AnalysisState`/`AbstractState` down to
///   exactly the three operations these two methods actually invoke (`state.bottom()`,
///   `state.smallStepSemantics(...)`, `AnalysisState.lub(...)`) -- see that trait's own docs.
#[derive(Clone, Debug)]
pub struct PcodeVarargsExpression<E> {
    /// Opaque handle standing in for the owning `CFG`. See the struct docs.
    pub cfg_id: u64,
    /// Java: `ctx.location()`, passed to the `NaryExpression` superclass constructor.
    pub location: PcodeLocation,
    /// Java: `ctx.mnemonic()`, passed to the `NaryExpression` superclass constructor as this
    /// expression's name.
    pub mnemonic: String,
    /// Java: `cfg.getDescriptor().getUnit().getProgram().getTypes().getIntegerType()`, passed to
    /// the `NaryExpression` superclass constructor as this expression's static type. Always the
    /// integer type, matching Java's hardcoded `getIntegerType()` call.
    pub static_type: PcodeType,
    /// Java: `Expression[] exps`, passed to the `NaryExpression` superclass constructor as this
    /// expression's operands, in order.
    pub exps: Vec<E>,
}

impl<E> PcodeVarargsExpression<E> {
    /// Java: `PcodeVarargsExpression(CFG cfg, VarargsExprContext ctx, Expression[] exps)`.
    pub fn new(cfg_id: u64, ctx: &VarargsExprContext, exps: Vec<E>) -> Self {
        Self {
            cfg_id,
            location: ctx.location(),
            mnemonic: ctx.mnemonic().to_string(),
            static_type: PcodeTypeSystem.integer_type(),
            exps,
        }
    }

    /// Java: `protected int compareSameClassAndParams(Statement o)`, `return 0; // no extra
    /// fields to compare`. Always `0`, regardless of `other` -- mirrored exactly, including the
    /// (unused) parameter, per this crate's convention of faithfully reproducing such trivial
    /// overrides (see
    /// [`PcodeNop`](crate::feature::lisa::pcode::statements::pcode_nop::PcodeNop)'s own
    /// `compare_same_class_no_extra_fields` test for the same pattern).
    pub fn compare_same_class_and_params(&self, other: &Self) -> i32 {
        let _ = other;
        0
    }
}

/// Stand-in for the subset of LiSA's `AnalysisState<A>` (and, transitively, `AbstractState<A>`)
/// that [`PcodeVarargsExpression::fwd_binary_semantics`]/
/// [`PcodeVarargsExpression::forward_semantics_aux`] actually touch: producing a bottom state,
/// evaluating "left OR right" against a state, and computing the least upper bound of two states.
/// See [`PcodeVarargsExpression`]'s own docs for why the full LiSA framework isn't ported.
///
/// Generic over `Expr`, the same operand stand-in [`PcodeVarargsExpression<E>`] is generic over
/// (LiSA's `SymbolicExpression`).
pub trait VarargsAnalysisState<Expr>: Sized {
    /// Mirrors `AbstractState::bottom()`, reached in Java via `state.bottom()`.
    fn bottom(&self) -> Self;

    /// Mirrors `AnalysisState::lub(AnalysisState<A>)`.
    fn lub(&self, other: &Self) -> Self;

    /// Mirrors evaluating `state.smallStepSemantics(new BinaryExpression(type, left, right,
    /// LogicalOr.INSTANCE, location), this)` -- i.e. the abstract semantics of "left OR right"
    /// against this state.
    fn small_step_or(&self, left: &Expr, right: &Expr) -> Self;
}

impl<E> PcodeVarargsExpression<E> {
    /// Java: `<A extends AbstractState<A>> AnalysisState<A> fwdBinarySemantics(
    /// InterproceduralAnalysis<A> interprocedural, AnalysisState<A> state, SymbolicExpression
    /// left, SymbolicExpression right, StatementStore<A> expressions) throws SemanticException`.
    ///
    /// Java's `interprocedural`/`expressions` parameters (and `getStaticType()`/`getLocation()`,
    /// folded into [`VarargsAnalysisState::small_step_or`]'s contract) are not needed by this
    /// narrowed port -- see [`VarargsAnalysisState`]'s docs.
    pub fn fwd_binary_semantics<S>(&self, state: &S, left: &E, right: &E) -> S
    where
        S: VarargsAnalysisState<E>,
    {
        state.small_step_or(left, right)
    }

    /// Java: `<A extends AbstractState<A>> AnalysisState<A> forwardSemanticsAux(
    /// InterproceduralAnalysis<A> interprocedural, AnalysisState<A> state, ExpressionSet[] params,
    /// StatementStore<A> expressions) throws SemanticException`.
    ///
    /// `params` mirrors Java's `ExpressionSet[] params` -- one set of candidate expressions per
    /// operand of this vararg expression, as resolved by the analysis framework. Every element of
    /// `params[0]` is paired (via [`Self::fwd_binary_semantics`]) against every element of every
    /// *other* `params[i]` (`i` from `1` to `params.len() - 1`), and the results are combined with
    /// [`VarargsAnalysisState::lub`], starting from `state.bottom()`.
    ///
    /// # Deviations from Java
    ///
    /// If `params` is empty, Java's `params[0]` throws `ArrayIndexOutOfBoundsException` (an
    /// unchecked exception outside this method's declared `throws SemanticException`). This port
    /// instead returns `state.bottom()`, the same value the accumulator would hold if `params[0]`
    /// existed but were itself empty (i.e. the loop's vacuous starting value) -- avoiding a panic
    /// for a shape (`params` with no elements at all) that in practice never arises: the analysis
    /// framework always supplies one `ExpressionSet` per operand of this expression, and a
    /// `PcodeVarargsExpression` always has at least the operands it was constructed with.
    pub fn forward_semantics_aux<S>(&self, state: &S, params: &[Vec<E>]) -> S
    where
        S: VarargsAnalysisState<E>,
    {
        let mut result = state.bottom();
        let Some(first) = params.first() else {
            return result;
        };
        for exp_base in first {
            for param_set in &params[1..] {
                for exp in param_set {
                    let step = self.fwd_binary_semantics(state, exp_base, exp);
                    result = result.lub(&step);
                }
            }
        }
        result
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

    fn call_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::Call, seq, inputs, None)
    }

    fn varargs_ctx(inputs: Vec<Varnode>) -> VarargsExprContext {
        let op = call_op(inputs);
        let pcode_ctx = PcodeContext::new(op);
        VarargsExprContext::new(&pcode_ctx)
    }

    #[test]
    fn new_captures_location_mnemonic_type_and_operands() {
        let space = ram_space();
        let ctx = varargs_ctx(vec![varnode(&space, 0x10, 4), varnode(&space, 0x14, 4)]);
        let expected_location = ctx.location();
        let expected_mnemonic = ctx.mnemonic().to_string();

        let expr = PcodeVarargsExpression::new(7, &ctx, vec!["a", "b", "c"]);

        assert_eq!(expr.cfg_id, 7);
        assert_eq!(expr.location, expected_location);
        assert_eq!(expr.mnemonic, expected_mnemonic);
        assert_eq!(expr.static_type, PcodeType::Int32);
        assert_eq!(expr.exps, vec!["a", "b", "c"]);
    }

    #[test]
    fn new_with_no_operands_yields_an_empty_exps_list() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<i32> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        assert!(expr.exps.is_empty());
    }

    #[test]
    fn compare_same_class_and_params_is_always_zero() {
        let ctx = varargs_ctx(vec![]);
        let a = PcodeVarargsExpression::new(1, &ctx, vec![1, 2]);
        let b = PcodeVarargsExpression::new(2, &ctx, vec![3]);
        assert_eq!(a.compare_same_class_and_params(&b), 0);
        assert_eq!(b.compare_same_class_and_params(&a), 0);
    }

    /// A tiny abstract-state double: an accumulated log of `"{left}|{right}"` OR-evaluations,
    /// combined by plain concatenation (not idempotent -- deliberately, so the test can assert the
    /// exact cross-product order `forward_semantics_aux` visits).
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LogState(Vec<String>);

    impl VarargsAnalysisState<String> for LogState {
        fn bottom(&self) -> Self {
            LogState(Vec::new())
        }

        fn lub(&self, other: &Self) -> Self {
            let mut v = self.0.clone();
            v.extend(other.0.iter().cloned());
            LogState(v)
        }

        fn small_step_or(&self, left: &String, right: &String) -> Self {
            LogState(vec![format!("{left}|{right}")])
        }
    }

    fn s(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn fwd_binary_semantics_evaluates_left_or_right_against_the_state() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<String> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        let state = LogState(Vec::new());

        let result = expr.fwd_binary_semantics(&state, &"a".to_string(), &"b".to_string());

        assert_eq!(result, LogState(vec!["a|b".to_string()]));
    }

    #[test]
    fn forward_semantics_aux_crosses_the_first_param_set_against_every_other_set() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<String> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        let state = LogState(Vec::new());

        let params = vec![s(&["a", "b"]), s(&["x", "y"]), s(&["z"])];
        let result = expr.forward_semantics_aux(&state, &params);

        // params[0] = [a, b]; crossed against params[1] = [x, y] and params[2] = [z], in order.
        assert_eq!(
            result,
            LogState(vec![
                "a|x".to_string(),
                "a|y".to_string(),
                "a|z".to_string(),
                "b|x".to_string(),
                "b|y".to_string(),
                "b|z".to_string(),
            ])
        );
    }

    #[test]
    fn forward_semantics_aux_with_a_single_param_set_never_pairs_anything() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<String> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        let state = LogState(Vec::new());

        // No i in 1..params.len() exists, so the loop body never runs -- result stays bottom.
        let result = expr.forward_semantics_aux(&state, &[s(&["a", "b"])]);

        assert_eq!(result, LogState(Vec::new()));
    }

    #[test]
    fn forward_semantics_aux_with_no_param_sets_returns_bottom_instead_of_panicking() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<String> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        let state = LogState(Vec::new());

        let result = expr.forward_semantics_aux(&state, &[]);

        assert_eq!(result, LogState(Vec::new()));
    }

    #[test]
    fn forward_semantics_aux_with_an_empty_first_set_never_pairs_anything() {
        let ctx = varargs_ctx(vec![]);
        let expr: PcodeVarargsExpression<String> = PcodeVarargsExpression::new(1, &ctx, vec![]);
        let state = LogState(Vec::new());

        let params = vec![Vec::new(), s(&["x"])];
        let result = expr.forward_semantics_aux(&state, &params);

        assert_eq!(result, LogState(Vec::new()));
    }
}
