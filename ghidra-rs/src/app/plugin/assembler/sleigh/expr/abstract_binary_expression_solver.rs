//! Mirrors `ghidra.app.plugin.assembler.sleigh.expr.AbstractBinaryExpressionSolver`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{AbstractExpressionSolver, NeedsBackfillException, SolverException, SolverHint};
use crate::app::plugin::assembler::sleigh::sem::{
    AbstractAssemblyResolutionFactory, AssemblyResolution,
};
use crate::app::seam_stubs::{AssemblyResolvedPatterns, MaskedLong, RecursiveDescentSolver};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// The error a solve attempt for one side of a binary expression can fail with: either a missing
/// symbol (propagates out of the overall solve, mirroring Java's `throws NeedsBackfillException`)
/// or an unsolvable expression (caught by the overall solve and turned into an error resolution,
/// mirroring Java's `throws SolverException` being caught in `AbstractBinaryExpressionSolver.solve`'s
/// own `catch (SolverException e)` block). Rust has no equivalent of catching one checked
/// exception type while letting a sibling propagate, so [`solve_left_side`](
/// AbstractBinaryExpressionSolver::solve_left_side)/[`solve_right_side`](
/// AbstractBinaryExpressionSolver::solve_right_side)/[`solve_two_sided`](
/// AbstractBinaryExpressionSolver::solve_two_sided) return this combined error for
/// [`solve_binary`](AbstractBinaryExpressionSolver::solve_binary) to pull apart itself.
#[derive(Debug)]
pub enum BinarySolveError {
    NeedsBackfill(NeedsBackfillException),
    Solver(SolverException),
}

impl From<NeedsBackfillException> for BinarySolveError {
    fn from(e: NeedsBackfillException) -> Self {
        Self::NeedsBackfill(e)
    }
}

impl From<SolverException> for BinarySolveError {
    fn from(e: SolverException) -> Self {
        Self::Solver(e)
    }
}

/// A solver that handles expressions of the form `A [OP] B`.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.AbstractBinaryExpressionSolver<T extends
/// BinaryExpression>`. As with [`AbstractExpressionSolver`], Java's `T extends BinaryExpression`
/// type parameter is dropped: every method below takes the flattened
/// [`PatternExpression`] enum directly and uses [`PatternExpression::binary_operands`] to reach
/// the left/right operands `BinaryExpression.getLeft()`/`getRight()` would have provided.
///
/// This trait mirrors the Java class's *inheritance*, not just its own new members: `extends
/// AbstractExpressionSolver<T>` becomes a supertrait bound, since every concrete binary solver
/// (`PlusExpressionSolver`, `AndExpressionSolver`, ...) genuinely is-a `AbstractExpressionSolver`
/// and gets registered into [`RecursiveDescentSolver`]'s registry as one. However, Rust cannot let
/// one trait supply a default body for a *different* (super)trait's required method the way a
/// Java subclass overrides an abstract superclass method -- `solve`/`getValue`/
/// `getInstructionLength`/`valueForResolution` are still required, separately, on
/// `AbstractExpressionSolver` itself. This trait instead exposes the four Java overrides as
/// distinctly-named template methods ([`solve_binary`](Self::solve_binary), etc.) with real
/// default bodies; a concrete solver implements both traits and has its
/// `AbstractExpressionSolver` methods delegate to these (e.g. `fn solve(&self, ...) {
/// self.solve_binary(...) }`), exactly reproducing the Java override wiring at the cost of that
/// one-line-per-method delegation Rust's separate-trait model requires.
///
/// The private `solver` field Java's parent class silently inherits (see
/// [`AbstractExpressionSolver`]'s own doc comment) is, unlike there, genuinely read by this
/// class's overrides -- every one of them recurses into a left/right subexpression via `solver`.
/// It is modeled as the required [`general_solver`](Self::general_solver) hook: implementors
/// return whatever [`RecursiveDescentSolver`] they were constructed/registered with.
pub trait AbstractBinaryExpressionSolver: AbstractExpressionSolver {
    /// The general solver this binary solver recurses into for its left/right subexpressions.
    ///
    /// Models the protected `solver` field assigned by `AbstractExpressionSolver.register`.
    fn general_solver(&self) -> &dyn RecursiveDescentSolver;

    /// Compute the left-hand-side value given that the result and the right are known.
    ///
    /// Mirrors `AbstractBinaryExpressionSolver.computeLeft(MaskedLong, MaskedLong)`, `abstract` in
    /// Java, so a required method here too.
    fn compute_left(&self, rval: MaskedLong, goal: MaskedLong) -> Result<MaskedLong, SolverException>;

    /// Compute the right-hand-side value given that the result and the left are known.
    ///
    /// Mirrors `AbstractBinaryExpressionSolver.computeRight(MaskedLong, MaskedLong)`. A real
    /// default method: Java's concrete (non-abstract) default body assumes commutativity and just
    /// delegates to [`compute_left`](Self::compute_left).
    fn compute_right(&self, lval: MaskedLong, goal: MaskedLong) -> Result<MaskedLong, SolverException> {
        self.compute_left(lval, goal)
    }

    /// Compute the result of applying the operator to the two given values.
    ///
    /// Mirrors `AbstractBinaryExpressionSolver.compute(MaskedLong, MaskedLong)`, `abstract` in
    /// Java, so a required method here too.
    fn compute(&self, lval: MaskedLong, rval: MaskedLong) -> MaskedLong;

    /// Solve the left operand, given that the right operand and goal are (fully) known.
    ///
    /// Mirrors the protected `AbstractBinaryExpressionSolver.solveLeftSide`. A real default
    /// method: computes the left operand's own goal via [`compute_left`](Self::compute_left), then
    /// recurses via [`general_solver`](Self::general_solver).
    fn solve_left_side(
        &self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        lexp: &PatternExpression,
        rval: MaskedLong,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        hints: &HashSet<Arc<dyn SolverHint>>,
        description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, BinarySolveError> {
        let target = self.compute_left(rval, goal)?;
        self.general_solver()
            .solve(factory, lexp, target, vals, cur, hints, description)
            .map_err(BinarySolveError::from)
    }

    /// Solve the right operand, given that the left operand and goal are (fully) known.
    ///
    /// Mirrors the protected `AbstractBinaryExpressionSolver.solveRightSide`. A real default
    /// method, symmetric to [`solve_left_side`](Self::solve_left_side).
    fn solve_right_side(
        &self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        rexp: &PatternExpression,
        lval: MaskedLong,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        hints: &HashSet<Arc<dyn SolverHint>>,
        description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, BinarySolveError> {
        let target = self.compute_right(lval, goal)?;
        self.general_solver()
            .solve(factory, rexp, target, vals, cur, hints, description)
            .map_err(BinarySolveError::from)
    }

    /// Attempt to solve an expression where both sides are variable.
    ///
    /// Mirrors the protected `AbstractBinaryExpressionSolver.solveTwoSided`. A real default
    /// method: Java's default body always throws, deferring to a solution via backfill; solvers
    /// for operators with a two-sided strategy (e.g. `(A << 4) | B` field concatenation) override
    /// it.
    fn solve_two_sided(
        &self,
        _factory: &dyn AbstractAssemblyResolutionFactory,
        _exp: &PatternExpression,
        _goal: MaskedLong,
        _vals: &HashMap<String, i64>,
        _cur: &dyn AssemblyResolvedPatterns,
        _hints: &HashSet<Arc<dyn SolverHint>>,
        _description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, BinarySolveError> {
        Err(BinarySolveError::NeedsBackfill(NeedsBackfillException::new("_two_sided_")))
    }

    /// Template method for `AbstractExpressionSolver.solve`'s override in
    /// `AbstractBinaryExpressionSolver`: folds constants where possible, otherwise recurses into
    /// whichever side is unknown (or both, via [`solve_two_sided`](Self::solve_two_sided)).
    ///
    /// A concrete solver's own `AbstractExpressionSolver::solve` should delegate here.
    fn solve_binary(
        &self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        exp: &PatternExpression,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        hints: &HashSet<Arc<dyn SolverHint>>,
        description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
        let (lexp, rexp) = exp
            .binary_operands()
            .expect("AbstractBinaryExpressionSolver requires a binary-operator expression");

        let mut lval = self.general_solver().get_value(lexp, vals, cur)?;
        let mut rval = self.general_solver().get_value(rexp, vals, cur)?;

        if lval.is_some_and(|v| !v.is_fully_defined()) {
            lval = None;
        }
        if rval.is_some_and(|v| !v.is_fully_defined()) {
            rval = None;
        }

        let outcome = match (lval, rval) {
            (Some(l), Some(r)) => {
                let cval = self.compute(l, r);
                Ok(check_const_agrees(factory, cval, goal, description))
            }
            (Some(l), None) => self.solve_right_side(factory, rexp, l, goal, vals, cur, hints, description),
            (None, Some(r)) => self.solve_left_side(factory, lexp, r, goal, vals, cur, hints, description),
            (None, None) => self.solve_two_sided(factory, exp, goal, vals, cur, hints, description),
        };

        match outcome {
            Ok(res) => Ok(res),
            Err(BinarySolveError::NeedsBackfill(e)) => Err(e),
            Err(BinarySolveError::Solver(e)) => Ok(error_resolution(factory, &e.message().to_string(), description)),
        }
    }

    /// Template method for `AbstractExpressionSolver.getValue`'s override in
    /// `AbstractBinaryExpressionSolver`: folds the expression to a constant only if both sides
    /// are.
    ///
    /// A concrete solver's own `AbstractExpressionSolver::get_value` should delegate here.
    fn get_value_binary(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
    ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
        let (lexp, rexp) = exp
            .binary_operands()
            .expect("AbstractBinaryExpressionSolver requires a binary-operator expression");

        let lval = self.general_solver().get_value(lexp, vals, cur)?;
        let rval = self.general_solver().get_value(rexp, vals, cur)?;

        Ok(match (lval, rval) {
            (Some(l), Some(r)) => Some(self.compute(l, r)),
            _ => None,
        })
    }

    /// Template method for `AbstractExpressionSolver.getInstructionLength`'s override in
    /// `AbstractBinaryExpressionSolver`: the longer of the two sides' instruction lengths.
    ///
    /// A concrete solver's own `AbstractExpressionSolver::get_instruction_length` should delegate
    /// here.
    fn get_instruction_length_binary(&self, exp: &PatternExpression) -> i32 {
        let (lexp, rexp) = exp
            .binary_operands()
            .expect("AbstractBinaryExpressionSolver requires a binary-operator expression");
        let ll = self.general_solver().get_instruction_length(lexp);
        let lr = self.general_solver().get_instruction_length(rexp);
        ll.max(lr)
    }

    /// Template method for `AbstractExpressionSolver.valueForResolution`'s override in
    /// `AbstractBinaryExpressionSolver`: combines both sides' values under the operator.
    ///
    /// A concrete solver's own `AbstractExpressionSolver::value_for_resolution` should delegate
    /// here.
    fn value_for_resolution_binary(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        rc: &dyn AssemblyResolvedPatterns,
    ) -> MaskedLong {
        let (lexp, rexp) = exp
            .binary_operands()
            .expect("AbstractBinaryExpressionSolver requires a binary-operator expression");
        let lval = self.general_solver().value_for_resolution(lexp, vals, rc);
        let rval = self.general_solver().value_for_resolution(rexp, vals, rc);
        self.compute(lval, rval)
    }
}

/// Mirrors `ConstantValueSolver.checkConstAgrees(AbstractAssemblyResolutionFactory, MaskedLong,
/// MaskedLong, String)`, called from `AbstractBinaryExpressionSolver.solve` when both operands
/// fold to constants. `ConstantValueSolver` itself is not yet ported (it is a full
/// `AbstractExpressionSolver` implementation, not merely a referenced value/collection type, so it
/// does not fit this crate's placeholder-trait convention for unported dependencies); this
/// four-line static helper is reproduced directly instead of standing up a placeholder for the
/// whole class.
fn check_const_agrees(
    factory: &dyn AbstractAssemblyResolutionFactory,
    value: MaskedLong,
    goal: MaskedLong,
    description: &str,
) -> Box<dyn AssemblyResolution> {
    if !value.agrees(goal) {
        return error_resolution(
            factory,
            &format!("Constant value {value} does not agree with child requirements"),
            description,
        );
    }
    factory.nop(description)
}

/// Mirrors the `factory.newErrorBuilder().error(message).description(description).build()`
/// pattern used both by `checkConstAgrees` and by `AbstractBinaryExpressionSolver.solve`'s own
/// `catch (SolverException e)` block. The Rust [`AbstractAssemblyResolutionFactory`] trait exposes
/// no raw builder (only [`error`](AbstractAssemblyResolutionFactory::error), which derives its
/// base description/children/right from an existing resolution) so a blank
/// [`nop`](AbstractAssemblyResolutionFactory::nop) record for `description` -- carrying the same
/// empty children/right the Java builder would default to -- stands in as that base.
fn error_resolution(
    factory: &dyn AbstractAssemblyResolutionFactory,
    message: &str,
    description: &str,
) -> Box<dyn AssemblyResolution> {
    let base = factory.nop(description);
    factory.error(message, base.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{AssemblyPatternBlock, AssemblyResolutionResults, Constructor};
    use crate::program::model::lang::sleigh::pattern::DisjointPattern;
    use std::cmp::Ordering;

    #[derive(Clone, Debug)]
    struct MockRes {
        desc: String,
        error: bool,
    }

    impl std::fmt::Display for MockRes {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl AssemblyResolution for MockRes {
        fn get_description(&self) -> String {
            self.desc.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            vec![]
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.desc.clone()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            self.error
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes {
                desc: format!("{description}[{op_count}]<-{}", self.desc),
                error: false,
            })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    #[derive(Clone)]
    struct MockPatternBlock;
    impl AssemblyPatternBlock for MockPatternBlock {
        fn get_vals(&self) -> Vec<i8> {
            Vec::new()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(self.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct MockPatterns {
        desc: String,
    }
    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }
    impl AssemblyResolution for MockPatterns {
        fn get_description(&self) -> String {
            self.desc.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            vec![]
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.desc.clone()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockPatterns { desc: format!("{description}[{op_count}]") })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }
    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction_length(&self) -> i32 {
            0
        }
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
    }

    /// A factory whose only ever-invoked members ([`nop`](AbstractAssemblyResolutionFactory::nop)
    /// and [`error`](AbstractAssemblyResolutionFactory::error)) are stubbed with real bodies;
    /// every other member is left `unimplemented!()` since these tests never reach them.
    struct MockFactory;

    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!()
        }
        fn nop(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn nop_with_children(
            &self,
            _description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn error(&self, error: &str, res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: format!("{}: {error}", res.get_description()), error: true })
        }
        fn backfill(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _inslen: i32,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!()
        }
        fn resolved(
            &self,
            _ins: Box<dyn AssemblyPatternBlock>,
            _ctx: Box<dyn AssemblyPatternBlock>,
            _description: &str,
            _cons: Option<Arc<dyn Constructor>>,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn instr_only(
            &self,
            _ins: Box<dyn AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn context_only(
            &self,
            _ctx: Box<dyn AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn from_pattern(
            &self,
            _pat: &DisjointPattern,
            _min_len: i32,
            _description: &str,
            _cons: Option<Arc<dyn Constructor>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn from_string(
            &self,
            _str: &str,
            _description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
        ) -> Result<Box<dyn AssemblyResolvedPatterns>, String> {
            unimplemented!()
        }
        fn solve_or_backfill_masked(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!()
        }
    }

    /// A minimal general solver: resolves `Constant` expressions to their value and treats every
    /// other expression as an as-yet-undetermined variable, `solve`-ing it by reporting the goal
    /// baked into the description (close enough to exercise real recursion without a real
    /// `TokenFieldSolver`).
    struct MockGeneral;

    impl RecursiveDescentSolver for MockGeneral {
        fn solve(
            &self,
            _factory: &dyn AbstractAssemblyResolutionFactory,
            _exp: &PatternExpression,
            goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _hints: &HashSet<Arc<dyn SolverHint>>,
            description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
            Ok(Box::new(MockRes { desc: format!("{description}={}", goal.val), error: false }))
        }

        fn get_value(
            &self,
            exp: &PatternExpression,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
            match exp {
                PatternExpression::Constant(v) => Ok(Some(MaskedLong::from_long(*v))),
                _ => Ok(None),
            }
        }

        fn get_instruction_length(&self, exp: &PatternExpression) -> i32 {
            match exp {
                PatternExpression::Constant(_) => 0,
                _ => 4,
            }
        }

        fn value_for_resolution(
            &self,
            exp: &PatternExpression,
            _vals: &HashMap<String, i64>,
            _rc: &dyn AssemblyResolvedPatterns,
        ) -> MaskedLong {
            match exp {
                PatternExpression::Constant(v) => MaskedLong::from_long(*v),
                _ => MaskedLong::from_long(0),
            }
        }
    }

    /// A minimal solver for `PatternExpression::Plus`, mirroring the shape of
    /// `PlusExpressionSolver` closely enough to exercise real binary-solve behavior.
    struct PlusSolver {
        general: MockGeneral,
    }

    impl AbstractBinaryExpressionSolver for PlusSolver {
        fn general_solver(&self) -> &dyn RecursiveDescentSolver {
            &self.general
        }

        fn compute_left(&self, rval: MaskedLong, goal: MaskedLong) -> Result<MaskedLong, SolverException> {
            Ok(MaskedLong::from_long(goal.val - rval.val))
        }

        fn compute(&self, lval: MaskedLong, rval: MaskedLong) -> MaskedLong {
            MaskedLong::from_long(lval.val + rval.val)
        }
    }

    impl AbstractExpressionSolver for PlusSolver {
        fn solve(
            &self,
            factory: &dyn AbstractAssemblyResolutionFactory,
            exp: &PatternExpression,
            goal: MaskedLong,
            vals: &HashMap<String, i64>,
            cur: &dyn AssemblyResolvedPatterns,
            hints: &HashSet<Arc<dyn SolverHint>>,
            description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
            self.solve_binary(factory, exp, goal, vals, cur, hints, description)
        }

        fn get_value(
            &self,
            exp: &PatternExpression,
            vals: &HashMap<String, i64>,
            cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
            self.get_value_binary(exp, vals, cur)
        }

        fn get_instruction_length(&self, exp: &PatternExpression) -> i32 {
            self.get_instruction_length_binary(exp)
        }

        fn value_for_resolution(
            &self,
            exp: &PatternExpression,
            vals: &HashMap<String, i64>,
            rc: &dyn AssemblyResolvedPatterns,
        ) -> MaskedLong {
            self.value_for_resolution_binary(exp, vals, rc)
        }

        fn register(&self, _general: &dyn RecursiveDescentSolver) {}
    }

    fn plus(l: PatternExpression, r: PatternExpression) -> PatternExpression {
        PatternExpression::Plus(Box::new(l), Box::new(r))
    }

    fn cur() -> MockPatterns {
        MockPatterns { desc: "cur".to_string() }
    }

    #[test]
    fn solve_both_constants_agree() {
        let solver = PlusSolver { general: MockGeneral };
        let factory = MockFactory;
        let exp = plus(PatternExpression::Constant(2), PatternExpression::Constant(3));
        let goal = MaskedLong::from_long(5);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(!result.is_error());
        assert_eq!(result.get_description(), "solving");
    }

    #[test]
    fn solve_both_constants_disagree() {
        let solver = PlusSolver { general: MockGeneral };
        let factory = MockFactory;
        let exp = plus(PatternExpression::Constant(2), PatternExpression::Constant(3));
        let goal = MaskedLong::from_long(6);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(result.is_error());
    }

    #[test]
    fn solve_left_unknown_recurses_via_solve_left_side() {
        let solver = PlusSolver { general: MockGeneral };
        let factory = MockFactory;
        // Left is unknown (not a constant); right is known -> solve_left_side.
        let exp = plus(PatternExpression::StartInstruction, PatternExpression::Constant(3));
        let goal = MaskedLong::from_long(10);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(!result.is_error());
        // compute_left(rval=3, goal=10) = 7, echoed by MockGeneral::solve.
        assert_eq!(result.get_description(), "solving=7");
    }

    #[test]
    fn solve_right_unknown_recurses_via_solve_right_side() {
        let solver = PlusSolver { general: MockGeneral };
        let factory = MockFactory;
        // Left is known; right is unknown -> solve_right_side.
        let exp = plus(PatternExpression::Constant(4), PatternExpression::StartInstruction);
        let goal = MaskedLong::from_long(10);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(!result.is_error());
        // compute_right defaults to compute_left(lval=4, goal=10) = 6.
        assert_eq!(result.get_description(), "solving=6");
    }

    #[test]
    fn solve_two_sided_needs_backfill_by_default() {
        let solver = PlusSolver { general: MockGeneral };
        let factory = MockFactory;
        let exp = plus(PatternExpression::StartInstruction, PatternExpression::EndInstruction);
        let goal = MaskedLong::from_long(0);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let err = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap_err();

        assert_eq!(err.symbol(), "_two_sided_");
    }

    #[test]
    fn get_value_folds_when_both_sides_constant() {
        let solver = PlusSolver { general: MockGeneral };
        let exp = plus(PatternExpression::Constant(2), PatternExpression::Constant(3));
        let vals = HashMap::new();
        let cur = cur();

        let value = solver.get_value(&exp, &vals, &cur).unwrap();

        assert_eq!(value, Some(MaskedLong::from_long(5)));
    }

    #[test]
    fn get_value_none_when_a_side_is_variable() {
        let solver = PlusSolver { general: MockGeneral };
        let exp = plus(PatternExpression::StartInstruction, PatternExpression::Constant(3));
        let vals = HashMap::new();
        let cur = cur();

        let value = solver.get_value(&exp, &vals, &cur).unwrap();

        assert_eq!(value, None);
    }

    #[test]
    fn instruction_length_is_max_of_both_sides() {
        let solver = PlusSolver { general: MockGeneral };
        let exp = plus(PatternExpression::Constant(1), PatternExpression::StartInstruction);

        assert_eq!(solver.get_instruction_length(&exp), 4);
    }

    #[test]
    fn value_for_resolution_computes_sum() {
        let solver = PlusSolver { general: MockGeneral };
        let exp = plus(PatternExpression::Constant(2), PatternExpression::Constant(5));
        let vals = HashMap::new();
        let rc = cur();

        assert_eq!(solver.value_for_resolution(&exp, &vals, &rc), MaskedLong::from_long(7));
    }

    #[test]
    fn compute_right_defaults_to_compute_left_for_commutativity() {
        let solver = PlusSolver { general: MockGeneral };
        let lval = MaskedLong::from_long(3);
        let goal = MaskedLong::from_long(5);

        assert_eq!(
            solver.compute_right(lval, goal).unwrap(),
            solver.compute_left(lval, goal).unwrap()
        );
    }

    #[test]
    fn trait_is_object_safe() {
        let solver = PlusSolver { general: MockGeneral };
        let as_dyn: &dyn AbstractBinaryExpressionSolver = &solver;
        assert_eq!(
            as_dyn.compute(MaskedLong::from_long(2), MaskedLong::from_long(3)),
            MaskedLong::from_long(5)
        );
    }
}
