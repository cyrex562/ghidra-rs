//! Mirrors `ghidra.app.plugin.assembler.sleigh.expr.AbstractExpressionSolver`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{NeedsBackfillException, SolverHint};
use crate::app::plugin::assembler::sleigh::sem::{
    AbstractAssemblyResolutionFactory, AssemblyResolution,
};
use crate::app::seam_stubs::{AssemblyResolvedPatterns, MaskedLong, RecursiveDescentSolver};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// The root type of an expression solver: attempts to find, or fold, the value(s) that satisfy a
/// [`PatternExpression`] for a desired encoded goal.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.AbstractExpressionSolver<T extends
/// PatternExpression>`, chosen as a cut-point for the two-way dependency cycle it forms with
/// `RecursiveDescentSolver`: every concrete solver (`PlusExpressionSolver`, `ConstantValueSolver`,
/// ...) is constructed and `register`ed with a `RecursiveDescentSolver` singleton, while that same
/// singleton's own `solve`/`getValue`/`getInstructionLength`/`valueForResolution` methods look the
/// appropriate solver back up (by the expression's runtime class) and call back into it. Java's `T
/// extends PatternExpression` type parameter is dropped: this crate's
/// [`PatternExpression`] is already a single flat, closed enum covering every subclass the Java
/// hierarchy specializes over (`BinaryExpression`, `UnaryExpression`, `TokenField`,
/// `ConstantValue`, ...), so there is no narrower type for `T` to range over -- every method below
/// takes the enum directly, mirroring how
/// [`AbstractAssemblyResolutionFactory`]'s own `PatternExpression`-typed parameters do the same.
///
/// The private `tcls` field (the `Class<T>` token identifying which expression subtype this
/// solver handles, used only by [`register`](Self::register) as the registry key) and the
/// protected `solver` field (the general solver this one was registered with, assigned by
/// [`register`](Self::register) but never read anywhere in this class -- only by the not-yet-ported
/// concrete solver subclasses) are not modeled as hook accessors: nothing in this trait's own body
/// needs to read either one back.
///
/// All four public methods are `abstract` in Java (no body to give a default), so all become
/// required trait methods, including [`register`](Self::register): its Java body (`this.solver =
/// general; general.register(tcls, this);`) needs a registry-keyed-by-class-token `register`
/// capability this crate's minimal [`RecursiveDescentSolver`] placeholder does not model -- the
/// same reasoning
/// [`AbstractAssemblyResolutionFactory::solve_or_backfill_masked`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyResolutionFactory::solve_or_backfill_masked)
/// already gives for leaving its own `RecursiveDescentSolver`-dependent body unfilled.
pub trait AbstractExpressionSolver {
    /// Attempt to solve an expression for a given value.
    ///
    /// `hints` describes techniques already applied by calling solvers.
    ///
    /// Mirrors `AbstractExpressionSolver.solve(AbstractAssemblyResolutionFactory, T, MaskedLong,
    /// Map<String, Long>, AssemblyResolvedPatterns, Set<SolverHint>, String)`. Returns `Err` of
    /// [`NeedsBackfillException`] if the expression refers to an undefined symbol, mirroring the
    /// Java `throws` clause.
    fn solve(
        &self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        exp: &PatternExpression,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        hints: &HashSet<Arc<dyn SolverHint>>,
        description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException>;

    /// Attempt to get a constant value for the expression.
    ///
    /// Mirrors `AbstractExpressionSolver.getValue(T, Map<String, Long>,
    /// AssemblyResolvedPatterns)`. Returns `Ok(None)` if the expression depends on a variable,
    /// mirroring Java's nullable return; returns `Err` of [`NeedsBackfillException`] if the
    /// expression refers to an undefined symbol, mirroring the Java `throws` clause.
    fn get_value(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
    ) -> Result<Option<MaskedLong>, NeedsBackfillException>;

    /// Determines the length of the subconstructor that would be returned had the expression not
    /// depended on an undefined symbol.
    ///
    /// This is used by the backfilling process to ensure values are written to the correct
    /// offset.
    ///
    /// Mirrors `AbstractExpressionSolver.getInstructionLength(T)`.
    fn get_instruction_length(&self, exp: &PatternExpression) -> i32;

    /// Compute the value of the expression given the (possibly-intermediate) resolution.
    ///
    /// Mirrors `AbstractExpressionSolver.valueForResolution(T, Map<String, Long>,
    /// AssemblyResolvedPatterns)`.
    fn value_for_resolution(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        rc: &dyn AssemblyResolvedPatterns,
    ) -> MaskedLong;

    /// Register this particular solver with the general expression solver.
    ///
    /// Mirrors the protected `AbstractExpressionSolver.register(RecursiveDescentSolver)`. Left as
    /// a required method for the reason given in this trait's own doc comment.
    fn register(&self, general: &dyn RecursiveDescentSolver);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        AssemblyPatternBlock, AssemblyResolutionResults, Constructor,
    };
    use crate::program::model::lang::sleigh::pattern::DisjointPattern;
    use std::cell::Cell;
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

    /// A factory whose only ever-invoked members are stubbed with real (trivial) bodies; every
    /// other member is left `unimplemented!()` since [`ConstantSolver`] below never reaches them.
    struct MockFactory;

    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!()
        }
        fn nop(&self, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn nop_with_children(
            &self,
            _description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!()
        }
        fn error(&self, _error: &str, _res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            unimplemented!()
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

    #[derive(Debug)]
    struct MockGeneralSolver;
    impl RecursiveDescentSolver for MockGeneralSolver {
        fn solve(
            &self,
            _factory: &dyn AbstractAssemblyResolutionFactory,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _hints: &HashSet<Arc<dyn SolverHint>>,
            _description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
            unimplemented!("not exercised by these tests")
        }

        fn get_value(
            &self,
            _exp: &PatternExpression,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
            unimplemented!("not exercised by these tests")
        }

        fn get_instruction_length(&self, _exp: &PatternExpression) -> i32 {
            unimplemented!("not exercised by these tests")
        }

        fn value_for_resolution(
            &self,
            _exp: &PatternExpression,
            _vals: &HashMap<String, i64>,
            _rc: &dyn AssemblyResolvedPatterns,
        ) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A minimal solver for `PatternExpression::Constant`, mirroring the shape of
    /// `ConstantValueSolver` closely enough to exercise real solve/get_value/register behavior.
    struct ConstantSolver {
        registered: Cell<bool>,
    }

    impl ConstantSolver {
        fn new() -> Self {
            Self { registered: Cell::new(false) }
        }
    }

    impl AbstractExpressionSolver for ConstantSolver {
        fn solve(
            &self,
            _factory: &dyn AbstractAssemblyResolutionFactory,
            exp: &PatternExpression,
            goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _hints: &HashSet<Arc<dyn SolverHint>>,
            description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
            match exp {
                PatternExpression::Constant(v) => {
                    if v & goal.mask == goal.val & goal.mask {
                        Ok(Box::new(MockRes { desc: description.to_string(), error: false }))
                    } else {
                        Ok(Box::new(MockRes {
                            desc: format!("mismatch: {description}"),
                            error: true,
                        }))
                    }
                }
                _ => Err(NeedsBackfillException::new("non_constant_expression")),
            }
        }

        fn get_value(
            &self,
            exp: &PatternExpression,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
            match exp {
                PatternExpression::Constant(v) => Ok(Some(MaskedLong::from_long(*v))),
                _ => Err(NeedsBackfillException::new("non_constant_expression")),
            }
        }

        fn get_instruction_length(&self, _exp: &PatternExpression) -> i32 {
            0
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

        fn register(&self, _general: &dyn RecursiveDescentSolver) {
            self.registered.set(true);
        }
    }

    fn cur() -> MockPatterns {
        MockPatterns { desc: "cur".to_string() }
    }

    #[test]
    fn solve_matches_constant_to_goal() {
        let solver = ConstantSolver::new();
        let factory = MockFactory;
        let exp = PatternExpression::Constant(5);
        let goal = MaskedLong::from_long(5);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result =
            solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(!result.is_error());
        assert_eq!(result.get_description(), "solving");
    }

    #[test]
    fn solve_reports_error_when_constant_mismatches_goal() {
        let solver = ConstantSolver::new();
        let factory = MockFactory;
        let exp = PatternExpression::Constant(5);
        let goal = MaskedLong::from_long(6);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let result =
            solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "solving").unwrap();

        assert!(result.is_error());
    }

    #[test]
    fn solve_needs_backfill_for_non_constant_expression() {
        let solver = ConstantSolver::new();
        let factory = MockFactory;
        let exp = PatternExpression::StartInstruction;
        let goal = MaskedLong::from_long(0);
        let vals = HashMap::new();
        let hints: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        let cur = cur();

        let err = solver.solve(&factory, &exp, goal, &vals, &cur, &hints, "x").unwrap_err();

        assert_eq!(err.symbol(), "non_constant_expression");
    }

    #[test]
    fn get_value_returns_constant() {
        let solver = ConstantSolver::new();
        let exp = PatternExpression::Constant(42);
        let vals = HashMap::new();
        let cur = cur();

        let value = solver.get_value(&exp, &vals, &cur).unwrap();

        assert_eq!(value, Some(MaskedLong::from_long(42)));
    }

    #[test]
    fn get_value_none_case_is_distinguished_from_error_case() {
        let solver = ConstantSolver::new();
        let vals = HashMap::new();
        let cur = cur();

        let non_constant = PatternExpression::StartInstruction;
        assert!(solver.get_value(&non_constant, &vals, &cur).is_err());
    }

    #[test]
    fn value_for_resolution_computes_constant() {
        let solver = ConstantSolver::new();
        let exp = PatternExpression::Constant(7);
        let vals = HashMap::new();
        let rc = cur();

        assert_eq!(solver.value_for_resolution(&exp, &vals, &rc), MaskedLong::from_long(7));
    }

    #[test]
    fn register_marks_solver_as_registered() {
        let solver = ConstantSolver::new();
        assert!(!solver.registered.get());

        solver.register(&MockGeneralSolver);

        assert!(solver.registered.get());
    }

    #[test]
    fn trait_is_object_safe() {
        let solver = ConstantSolver::new();
        let as_dyn: &dyn AbstractExpressionSolver = &solver;
        assert_eq!(as_dyn.get_instruction_length(&PatternExpression::Constant(1)), 0);
    }
}
