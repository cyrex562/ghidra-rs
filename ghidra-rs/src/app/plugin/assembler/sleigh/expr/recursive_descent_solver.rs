//! Mirrors `ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{NeedsBackfillException, SolverHint};
use crate::app::plugin::assembler::sleigh::sem::{
    AbstractAssemblyResolutionFactory, AssemblyResolution, AssemblyResolvedPatterns,
};
use crate::app::seam_stubs::MaskedLong;
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// Seeks solutions to [`PatternExpression`]s.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver`, chosen as a
/// cut-point for the two-way dependency cycle it forms with
/// [`AbstractExpressionSolver`](super::AbstractExpressionSolver): every concrete solver
/// (`PlusExpressionSolver`, `ConstantValueSolver`, ...) is constructed and `register`ed with a
/// `RecursiveDescentSolver` singleton, while that same singleton's own
/// `solve`/`getValue`/`getInstructionLength`/`valueForResolution` methods look the appropriate
/// solver back up (by the expression's runtime class) and call back into it.
///
/// Java's class is a singleton (`private static final RecursiveDescentSolver INSTANCE`, exposed
/// via the static `getSolver()`) whose instance-initializer block constructs and registers one of
/// each concrete `AbstractExpressionSolver` subclass into a `Map<Class<?>,
/// AbstractExpressionSolver<?>>` registry, and whose four public/protected `solve`/`getValue`/
/// `getInstructionLength`/`valueForResolution` methods all funnel through that
/// registry-by-runtime-class (`getRegistered`) to re-dispatch to the concrete solver for the
/// expression at hand. None of `getSolver()`, `register(Class, AbstractExpressionSolver)`, or the
/// backing `registry`/`getRegistered` machinery are modeled here: this crate's
/// [`PatternExpression`] is already a single flat, closed enum covering every subclass the Java
/// hierarchy specializes over (`BinaryExpression`, `UnaryExpression`, `TokenField`,
/// `ConstantValue`, ...) rather than an open class hierarchy needing a `Class`-keyed registry, so
/// an implementor of this trait is expected to dispatch on the enum directly (e.g. via a `match`)
/// instead of consulting a registry built from a set of registered solver objects -- and no
/// concrete `AbstractExpressionSolver` subclass is ported yet to register in the first place.
/// Callers needing a `RecursiveDescentSolver` already receive one as a `&dyn RecursiveDescentSolver`
/// parameter (dependency injection) rather than reaching for a global singleton, so `getSolver()`
/// has no current call site either.
///
/// All four methods are concrete (non-`abstract`) in Java, but every one of their bodies is just
/// `getRegistered(exp.getClass()).xxx(...)` -- a call into machinery this trait deliberately
/// doesn't model, per the above -- so there is no way to give any of them a real default body
/// here. All four remain required trait methods, exactly as they were on the placeholder trait
/// this file replaces.
pub trait RecursiveDescentSolver {
    /// Solve a given expression, passing hints.
    ///
    /// `hints` describes techniques already applied by calling solvers.
    ///
    /// Mirrors the protected `RecursiveDescentSolver.solve(AbstractAssemblyResolutionFactory,
    /// PatternExpression, MaskedLong, Map<String, Long>, AssemblyResolvedPatterns,
    /// Set<SolverHint>, String)`. Returns `Err` of [`NeedsBackfillException`] if a solution may
    /// exist but a required symbol is missing, mirroring the Java `throws` clause.
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

    /// Solve a given expression, given a masked-value goal, with no hints.
    ///
    /// Mirrors the public `RecursiveDescentSolver.solve(AbstractAssemblyResolutionFactory,
    /// PatternExpression, MaskedLong, Map<String, Long>, AssemblyResolvedPatterns, String)`. A
    /// real default method: its Java body is exactly `solve(factory, exp, goal, vals, cur,
    /// Set.of(), description)`.
    fn solve_top_level(
        &self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        exp: &PatternExpression,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        description: &str,
    ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
        self.solve(factory, exp, goal, vals, cur, &HashSet::new(), description)
    }

    /// Attempt to fold a given expression (or sub-expression) into a single constant.
    ///
    /// Mirrors the protected `RecursiveDescentSolver.getValue(PatternExpression, Map<String,
    /// Long>, AssemblyResolvedPatterns)`. Returns `Ok(None)` if the expression depends on a
    /// variable, mirroring Java's nullable return; returns `Err` of [`NeedsBackfillException`] if
    /// the expression refers to an undefined symbol, mirroring the Java `throws` clause.
    fn get_value(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
    ) -> Result<Option<MaskedLong>, NeedsBackfillException>;

    /// Determine the length of the instruction part of the encoded solution to the given
    /// expression.
    ///
    /// This is used to keep operands in their appropriate position when backfilling becomes
    /// applicable. Normally, the instruction length is taken from the encoding of a solution, but
    /// if the solution cannot be determined yet, the instruction length must still be obtained.
    ///
    /// Mirrors `RecursiveDescentSolver.getInstructionLength(PatternExpression)`.
    fn get_instruction_length(&self, exp: &PatternExpression) -> i32;

    /// Compute the value of an expression given a (possibly-intermediate) resolution.
    ///
    /// Mirrors `RecursiveDescentSolver.valueForResolution(PatternExpression, Map<String, Long>,
    /// AssemblyResolvedPatterns)`.
    fn value_for_resolution(
        &self,
        exp: &PatternExpression,
        vals: &HashMap<String, i64>,
        rc: &dyn AssemblyResolvedPatterns,
    ) -> MaskedLong;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        AssemblyPatternBlock, AssemblyResolutionResults, Constructor,
    };
    use crate::program::model::lang::sleigh::pattern::DisjointPattern;
    use std::cell::RefCell;

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
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: description.to_string(), error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> std::cmp::Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    #[derive(Clone)]
    struct MockBlock;
    impl AssemblyPatternBlock for MockBlock {
        fn get_vals(&self) -> Vec<i8> {
            Vec::new()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(self.clone())
        }
    }

    #[derive(Clone, Debug)]
    struct MockPatterns;
    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "cur")
        }
    }
    impl AssemblyResolution for MockPatterns {
        fn get_description(&self) -> String {
            "cur".to_string()
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
            "cur".to_string()
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
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: description.to_string(), error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}cur", indent)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> std::cmp::Ordering {
            "cur".cmp(&other.get_description())
        }
    }
    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock)
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock)
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn get_instruction_length(&self) -> i32 {
            4
        }
        fn get_defined_instruction_length(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_backfills(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill>> {
            unimplemented!("not exercised by these tests")
        }
        fn has_backfills(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_forbids(&self) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn read_instruction(&self, _byte_start: i32, _size: i32) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context(&self, _start: i32, _len: i32) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context_op(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
        ) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn bits_equal(&self, _that: &dyn AssemblyResolvedPatterns) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn equivalent_construct_state(
            &self,
            _state: &crate::program::model::lang::sleigh::walker::ConstructState,
        ) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn shift_patterns(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_description(&self, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_right_patterns(
            &self,
            _right: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_constructor(
            &self,
            _cons: std::sync::Arc<dyn crate::app::seam_stubs::Constructor>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine(
            &self,
            _pat: &dyn AssemblyResolvedPatterns,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_backfill(
            &self,
            _bf: &dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_less_backfill(
            &self,
            _that: &dyn AssemblyResolvedPatterns,
            _bf: &dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn parent_patterns(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn backfill(
            &self,
            _solver: &dyn RecursiveDescentSolver,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn check_not_forbidden(&self) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn nop_left_sibling(&self) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn solve_context_changes_for_forbids(
            &self,
            _sem: &dyn crate::app::seam_stubs::AssemblyConstructorSemantic,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn possible_ins_vals(&self, _for_ctx: &dyn AssemblyPatternBlock) -> Vec<Vec<u8>> {
            unimplemented!("not exercised by these tests")
        }
        fn dump_constructor_tree(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn truncate(&self, _shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn with_forbids(
            &self,
            _more: Vec<Box<dyn AssemblyResolvedPatterns>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn mask_out(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn write_context_op(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
            _val: MaskedLong,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockFactory;
    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn nop(&self, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn nop_with_children(
            &self,
            _description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn error(&self, _error: &str, _res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn backfill(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _inslen: i32,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
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
            unimplemented!("not exercised by these tests")
        }
        fn instr_only(&self, _ins: Box<dyn AssemblyPatternBlock>, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn context_only(&self, _ctx: Box<dyn AssemblyPatternBlock>, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn from_pattern(
            &self,
            _pat: &DisjointPattern,
            _min_len: i32,
            _description: &str,
            _cons: Option<Arc<dyn Constructor>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn from_string(
            &self,
            _str: &str,
            _description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
        ) -> Result<Box<dyn AssemblyResolvedPatterns>, String> {
            unimplemented!("not exercised by these tests")
        }
        fn solve_or_backfill_masked(
            &self,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A minimal solver that dispatches on whether the sole tracked symbol `"x"` is defined.
    /// Enough to prove [`RecursiveDescentSolver`] is object-safe and that
    /// [`solve_top_level`](RecursiveDescentSolver::solve_top_level) really does delegate to
    /// [`solve`](RecursiveDescentSolver::solve) with empty hints.
    struct MockSolver {
        solve_hint_counts: RefCell<Vec<usize>>,
    }

    impl RecursiveDescentSolver for MockSolver {
        fn solve(
            &self,
            _factory: &dyn AbstractAssemblyResolutionFactory,
            _exp: &PatternExpression,
            _goal: MaskedLong,
            vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            hints: &HashSet<Arc<dyn SolverHint>>,
            description: &str,
        ) -> Result<Box<dyn AssemblyResolution>, NeedsBackfillException> {
            self.solve_hint_counts.borrow_mut().push(hints.len());
            if vals.contains_key("x") {
                Ok(Box::new(MockRes { desc: description.to_string(), error: false }))
            } else {
                Err(NeedsBackfillException::new("x"))
            }
        }

        fn get_value(
            &self,
            _exp: &PatternExpression,
            vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
        ) -> Result<Option<MaskedLong>, NeedsBackfillException> {
            match vals.get("x") {
                Some(v) => Ok(Some(MaskedLong::from_long(*v))),
                None => Ok(None),
            }
        }

        fn get_instruction_length(&self, _exp: &PatternExpression) -> i32 {
            4
        }

        fn value_for_resolution(
            &self,
            _exp: &PatternExpression,
            vals: &HashMap<String, i64>,
            _rc: &dyn AssemblyResolvedPatterns,
        ) -> MaskedLong {
            MaskedLong::from_long(*vals.get("x").unwrap_or(&0))
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let solver: Box<dyn RecursiveDescentSolver> =
            Box::new(MockSolver { solve_hint_counts: RefCell::new(Vec::new()) });
        assert_eq!(solver.get_instruction_length(&PatternExpression::Constant(1)), 4);
    }

    #[test]
    fn get_value_resolves_when_symbol_is_defined() {
        let solver = MockSolver { solve_hint_counts: RefCell::new(Vec::new()) };
        let mut vals = HashMap::new();
        vals.insert("x".to_string(), 42i64);
        let cur = MockPatterns;

        let result = solver.get_value(&PatternExpression::Constant(1), &vals, &cur);

        assert_eq!(result.unwrap(), Some(MaskedLong::from_long(42)));
    }

    #[test]
    fn get_value_is_none_when_symbol_is_undefined() {
        let solver = MockSolver { solve_hint_counts: RefCell::new(Vec::new()) };
        let vals = HashMap::new();
        let cur = MockPatterns;

        let result = solver.get_value(&PatternExpression::Constant(1), &vals, &cur);

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn solve_top_level_delegates_to_solve_with_empty_hints() {
        let solver = MockSolver { solve_hint_counts: RefCell::new(Vec::new()) };
        let factory = MockFactory;
        let mut vals = HashMap::new();
        vals.insert("x".to_string(), 1i64);
        let cur = MockPatterns;

        let result = solver.solve_top_level(
            &factory,
            &PatternExpression::Constant(1),
            MaskedLong::from_long(1),
            &vals,
            &cur,
            "top",
        );

        assert!(result.is_ok());
        assert_eq!(solver.solve_hint_counts.borrow().as_slice(), &[0usize]);
    }

    #[test]
    fn solve_needs_backfill_for_missing_symbol() {
        let solver = MockSolver { solve_hint_counts: RefCell::new(Vec::new()) };
        let factory = MockFactory;
        let vals = HashMap::new();
        let cur = MockPatterns;

        let result = solver.solve(
            &factory,
            &PatternExpression::Constant(1),
            MaskedLong::from_long(0),
            &vals,
            &cur,
            &HashSet::new(),
            "desc",
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().symbol(), "x");
    }
}
