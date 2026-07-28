//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory`.

use std::collections::HashMap;
use std::sync::Arc;

use super::AssemblyResolution;
use crate::app::seam_stubs::{
    AssemblyPatternBlock, AssemblyResolutionResults, AssemblyResolvedPatterns, Constructor,
    MaskedLong,
};
use crate::program::model::lang::sleigh::expression::PatternExpression;
use crate::program::model::lang::sleigh::pattern::DisjointPattern;

/// Builds the assembly resolution records (successful patterns, backfills, and errors) produced
/// while resolving a SLEIGH constructor.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory<RP extends
/// AssemblyResolvedPatterns, BF extends AssemblyResolvedBackfill>`, chosen as a cut-point for the
/// dependency cycle running through [`AbstractAssemblyTreeResolver`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver) and
/// [`AbstractAssemblyState`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyState) --
/// both of which hold a `factory: AbstractAssemblyResolutionFactory<?, ?>` field and call back
/// into it. Java's `RP`/`BF` type parameters are dropped in favor of this crate's existing
/// [`AssemblyResolvedPatterns`](crate::app::seam_stubs::AssemblyResolvedPatterns) placeholder and
/// already-ported [`AssemblyResolvedBackfill`](
/// crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill) trait, referenced
/// directly via trait objects -- the same pattern `AbstractAssemblyTreeResolver` itself uses for
/// `RP` (see its own doc comment).
///
/// Java's private nested builder classes (`AbstractAssemblyResolutionBuilder`,
/// `AbstractAssemblyResolvedPatternsBuilder`, `AbstractAssemblyResolvedBackfillBuilder`,
/// `DefaultAssemblyResolvedPatternBuilder`, `DefaultAssemblyResolvedBackfillBuilder`,
/// `AssemblyResolvedErrorBuilder`) and the abstract `newPatternsBuilder`/`newBackfillBuilder` and
/// `newErrorBuilder`/`*Builder`-suffixed methods that drive them are internal construction
/// machinery -- each ultimately produces a `DefaultAssemblyResolvedPatterns`,
/// `DefaultAssemblyResolvedBackfill`, or `DefaultAssemblyResolvedError`, none of which are ported
/// as concrete, constructible Rust types yet -- and are left out of this trait's public surface,
/// mirroring how [`DefaultAssemblyResolvedBackfill`](
/// crate::app::plugin::assembler::sleigh::sem::DefaultAssemblyResolvedBackfill)'s own doc comment
/// already excludes that same machinery. What remains is the class's terminal, `.build()`-calling
/// public API (`nop`, `error`, `backfill`, `resolved`, `instrOnly`, `contextOnly`, `fromPattern`,
/// `fromString`, `newAssemblyResolutionResults`) plus its `protected` helpers (`singleton`,
/// `results`, the `solveOrBackfill` family) that same-package collaborators call directly.
///
/// Every terminal builder-backed method is left as a required (bodyless) trait method: each
/// Java body ultimately constructs a `Default*` record via one of the unported builder types
/// above, so there is no way to give it a real default body here. [`results`](Self::results) and
/// [`singleton`](Self::singleton) are the exception -- each is a pure function of
/// [`new_assembly_resolution_results`](Self::new_assembly_resolution_results) (itself required)
/// plus [`AssemblyResolutionResults::add`], so they get real default bodies. Likewise, of the
/// three `solveOrBackfill` overloads, only the `MaskedLong`-taking one
/// ([`solve_or_backfill_masked`](Self::solve_or_backfill_masked)) is required -- its Java body
/// needs the static `RecursiveDescentSolver.getSolver()` singleton and its own `solve`/
/// `getInstructionLength` methods, neither modeled on this crate's minimal
/// [`RecursiveDescentSolver`](crate::app::seam_stubs::RecursiveDescentSolver) placeholder -- while
/// the other two ([`solve_or_backfill_bits`](Self::solve_or_backfill_bits) and
/// [`solve_or_backfill`](Self::solve_or_backfill)) just convert their arguments to a `MaskedLong`
/// and delegate, so they're real default methods.
pub trait AbstractAssemblyResolutionFactory {
    /// Obtain a new, empty resolution results set.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.newAssemblyResolutionResults()`.
    fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults>;

    /// Construct a resolution results set containing exactly `entries`.
    ///
    /// Mirrors the protected `AbstractAssemblyResolutionFactory.results(Set<AssemblyResolution>)`.
    fn results(&self, entries: Vec<Box<dyn AssemblyResolution>>) -> Box<dyn AssemblyResolutionResults> {
        let mut set = self.new_assembly_resolution_results();
        for entry in entries {
            set.add(entry);
        }
        set
    }

    /// Construct an immutable single-entry result set consisting of the one given resolution.
    ///
    /// Mirrors the protected `AbstractAssemblyResolutionFactory.singleton(AssemblyResolution)`.
    fn singleton(&self, one: Box<dyn AssemblyResolution>) -> Box<dyn AssemblyResolutionResults> {
        self.results(vec![one])
    }

    /// Obtain a new "blank" resolved SLEIGH constructor record.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.nop(String)`. Left as a required method: its
    /// Java body goes through the unported builder machinery (see this trait's own doc comment).
    fn nop(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns>;

    /// Obtain a new "blank" resolved SLEIGH constructor record with children and a right sibling.
    ///
    /// Named distinctly from [`nop`](Self::nop), which Rust cannot overload, mirroring
    /// `AbstractAssemblyResolutionFactory.nop(String, List<AssemblyResolution>,
    /// AssemblyResolution)`. `right` mirrors Java's nullable parameter as `None`. Left as a
    /// required method for the same reason as [`nop`](Self::nop).
    fn nop_with_children(
        &self,
        description: &str,
        children: Vec<Box<dyn AssemblyResolution>>,
        right: Option<Box<dyn AssemblyResolution>>,
    ) -> Box<dyn AssemblyResolvedPatterns>;

    /// Build an error resolution record, based on an intermediate SLEIGH constructor record.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.error(String, AssemblyResolution)`. Left as a
    /// required method for the same reason as [`nop`](Self::nop).
    fn error(&self, error: &str, res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution>;

    /// Build a backfill record to attach to a successful resolution result.
    ///
    /// `exp` is the expression depending on a missing symbol, `goal` the desired value of the
    /// expression, `inslen` the length of instruction portion expected in the future solution.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.backfill(PatternExpression, MaskedLong, int,
    /// String)`. Left as a required method for the same reason as [`nop`](Self::nop).
    fn backfill(
        &self,
        exp: &PatternExpression,
        goal: MaskedLong,
        inslen: i32,
        description: &str,
    ) -> Box<dyn AssemblyResolution>;

    /// Build the result of successfully resolving a SLEIGH constructor.
    ///
    /// This is not used strictly for resolved SLEIGH constructors: it may also be used to store
    /// intermediates, e.g., encoded operands, during constructor resolution. `cons` mirrors
    /// Java's nullable `Constructor` parameter as `None`, and `right` its nullable
    /// `AssemblyResolution` parameter likewise.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.resolved(AssemblyPatternBlock,
    /// AssemblyPatternBlock, String, Constructor, List<AssemblyResolution>, AssemblyResolution)`.
    /// Left as a required method for the same reason as [`nop`](Self::nop).
    fn resolved(
        &self,
        ins: Box<dyn AssemblyPatternBlock>,
        ctx: Box<dyn AssemblyPatternBlock>,
        description: &str,
        cons: Option<Arc<dyn Constructor>>,
        children: Vec<Box<dyn AssemblyResolution>>,
        right: Option<Box<dyn AssemblyResolution>>,
    ) -> Box<dyn AssemblyResolvedPatterns>;

    /// Build an instruction-only successful resolution result.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.instrOnly(AssemblyPatternBlock, String)`. Left
    /// as a required method for the same reason as [`nop`](Self::nop).
    fn instr_only(&self, ins: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns>;

    /// Build a context-only successful resolution result.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.contextOnly(AssemblyPatternBlock, String)`.
    /// Left as a required method for the same reason as [`nop`](Self::nop).
    fn context_only(&self, ctx: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns>;

    /// Build a successful resolution result from a SLEIGH constructor's patterns.
    ///
    /// `cons` mirrors Java's nullable `Constructor` parameter as `None`.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.fromPattern(DisjointPattern, int, String,
    /// Constructor)`. Left as a required method for the same reason as [`nop`](Self::nop).
    fn from_pattern(
        &self,
        pat: &DisjointPattern,
        min_len: i32,
        description: &str,
        cons: Option<Arc<dyn Constructor>>,
    ) -> Box<dyn AssemblyResolvedPatterns>;

    /// Build a new successful SLEIGH constructor resolution from a string representation.
    ///
    /// This was used primarily in testing, to specify expected results. `str` is the string
    /// representation: `"ins:[pattern],ctx:[pattern]"`. Mirrors Java's thrown
    /// `IllegalArgumentException(str)` (raised when `str` has leftover, unparsed content) as
    /// `Err` of the leftover string.
    ///
    /// Mirrors `AbstractAssemblyResolutionFactory.fromString(String, String,
    /// List<AssemblyResolution>)`. Left as a required method for the same reason as
    /// [`nop`](Self::nop) -- its Java body additionally needs the static
    /// `AssemblyPatternBlock.fromString(String)`, not modeled on this trait's minimal
    /// [`AssemblyPatternBlock`](crate::app::seam_stubs::AssemblyPatternBlock) placeholder.
    fn from_string(
        &self,
        str: &str,
        description: &str,
        children: Vec<Box<dyn AssemblyResolution>>,
    ) -> Result<Box<dyn AssemblyResolvedPatterns>, String>;

    /// Attempt to solve an expression, given its fully-specified goal.
    ///
    /// Mirrors the protected `AbstractAssemblyResolutionFactory.solveOrBackfill(PatternExpression,
    /// MaskedLong, Map<String, Long>, AssemblyResolvedPatterns, String)`: attempts
    /// `RecursiveDescentSolver.solve`, falling back to [`backfill`](Self::backfill) (with a field
    /// length from `RecursiveDescentSolver.getInstructionLength`) if that solve needs a symbol not
    /// yet in `vals`. Left as a required method: neither `solve` nor `getInstructionLength` are
    /// modeled on this trait's minimal [`RecursiveDescentSolver`](
    /// crate::app::seam_stubs::RecursiveDescentSolver) placeholder.
    fn solve_or_backfill_masked(
        &self,
        exp: &PatternExpression,
        goal: MaskedLong,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        description: &str,
    ) -> Box<dyn AssemblyResolution>;

    /// Attempt to solve an expression, given a goal and its bit width.
    ///
    /// Converts the given goal and bit count to a [`MaskedLong`] and then solves as before. As a
    /// special case, if `bits == 0`, the goal is considered fully-defined (as if `bits == 64`).
    ///
    /// Mirrors the protected `AbstractAssemblyResolutionFactory.solveOrBackfill(PatternExpression,
    /// long, int, Map<String, Long>, AssemblyResolvedPatterns, String)`. A real default method:
    /// unlike [`solve_or_backfill_masked`](Self::solve_or_backfill_masked), its Java body is pure
    /// bit-mask arithmetic plus a delegating call, needing nothing further.
    fn solve_or_backfill_bits(
        &self,
        exp: &PatternExpression,
        goal: i64,
        bits: i32,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        description: &str,
    ) -> Box<dyn AssemblyResolution> {
        let msk: i64 = if bits == 0 || bits >= 64 { -1 } else { !(-1i64 << bits) };
        self.solve_or_backfill_masked(
            exp,
            MaskedLong::from_mask_and_value(msk, goal),
            vals,
            cur,
            description,
        )
    }

    /// Attempt to solve an expression, given a fully-defined goal.
    ///
    /// Converts the given goal to a fully-defined [`MaskedLong`] and then solves.
    ///
    /// Mirrors the protected `AbstractAssemblyResolutionFactory.solveOrBackfill(PatternExpression,
    /// long, Map<String, Long>, AssemblyResolvedPatterns, String)`. A real default method, for the
    /// same reason as [`solve_or_backfill_bits`](Self::solve_or_backfill_bits).
    fn solve_or_backfill(
        &self,
        exp: &PatternExpression,
        goal: i64,
        vals: &HashMap<String, i64>,
        cur: &dyn AssemblyResolvedPatterns,
        description: &str,
    ) -> Box<dyn AssemblyResolution> {
        self.solve_or_backfill_masked(exp, MaskedLong::from_long(goal), vals, cur, description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::AssemblyResolutionEntry;
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
            Box::new(MockRes { desc: format!("{description}[{op_count}]<-{}", self.desc), error: false })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    #[derive(Default)]
    struct MockResults {
        items: Vec<Box<dyn AssemblyResolution>>,
    }

    impl AssemblyResolutionResults for MockResults {
        fn resolutions(&self) -> Vec<AssemblyResolutionEntry> {
            Vec::new()
        }
        fn iter_all(&self) -> Vec<Box<dyn AssemblyResolution>> {
            self.items.iter().map(|r| r.shift(0)).collect()
        }
        fn add(&mut self, ar: Box<dyn AssemblyResolution>) {
            self.items.push(ar);
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

    /// A factory that only ever solves goals already present in `vals`, tracking whether
    /// [`backfill`](AbstractAssemblyResolutionFactory::backfill) was reached -- enough to exercise
    /// the real default `solve_or_backfill*` bodies' delegation without needing a real
    /// `RecursiveDescentSolver`.
    struct MockFactory {
        backfill_calls: std::cell::RefCell<Vec<MaskedLong>>,
    }

    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            Box::new(MockResults::default())
        }
        fn nop(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn nop_with_children(
            &self,
            description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn error(&self, error: &str, _res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: error.to_string(), error: true })
        }
        fn backfill(
            &self,
            _exp: &PatternExpression,
            goal: MaskedLong,
            _inslen: i32,
            description: &str,
        ) -> Box<dyn AssemblyResolution> {
            self.backfill_calls.borrow_mut().push(goal);
            Box::new(MockRes { desc: description.to_string(), error: false })
        }
        fn resolved(
            &self,
            _ins: Box<dyn AssemblyPatternBlock>,
            _ctx: Box<dyn AssemblyPatternBlock>,
            description: &str,
            _cons: Option<Arc<dyn Constructor>>,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn instr_only(&self, _ins: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn context_only(&self, _ctx: Box<dyn AssemblyPatternBlock>, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn from_pattern(
            &self,
            _pat: &DisjointPattern,
            _min_len: i32,
            description: &str,
            _cons: Option<Arc<dyn Constructor>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string() })
        }
        fn from_string(
            &self,
            str: &str,
            description: &str,
            _children: Vec<Box<dyn AssemblyResolution>>,
        ) -> Result<Box<dyn AssemblyResolvedPatterns>, String> {
            if str.is_empty() {
                Ok(Box::new(MockPatterns { desc: description.to_string() }))
            } else {
                Err(str.to_string())
            }
        }
        fn solve_or_backfill_masked(
            &self,
            _exp: &PatternExpression,
            goal: MaskedLong,
            vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            description: &str,
        ) -> Box<dyn AssemblyResolution> {
            if vals.contains_key("known") {
                Box::new(MockRes { desc: description.to_string(), error: false })
            } else {
                self.backfill(&PatternExpression::Constant(0), goal, 4, description)
            }
        }
    }

    fn factory() -> MockFactory {
        MockFactory { backfill_calls: std::cell::RefCell::new(Vec::new()) }
    }

    #[test]
    fn results_collects_every_entry() {
        let f = factory();
        let set = f.results(vec![
            Box::new(MockRes { desc: "a".to_string(), error: false }),
            Box::new(MockRes { desc: "b".to_string(), error: false }),
        ]);
        let mut descs: Vec<String> = set.iter_all().iter().map(|r| r.get_description()).collect();
        descs.sort();
        assert_eq!(descs, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn singleton_wraps_exactly_one_entry() {
        let f = factory();
        let set = f.singleton(Box::new(MockRes { desc: "only".to_string(), error: false }));
        let items = set.iter_all();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get_description(), "only");
    }

    #[test]
    fn solve_or_backfill_masked_solves_when_symbol_known() {
        let f = factory();
        let mut vals = HashMap::new();
        vals.insert("known".to_string(), 1i64);
        let cur = MockPatterns { desc: "cur".to_string() };
        let exp = PatternExpression::Constant(0);

        let result =
            f.solve_or_backfill(&exp, 5, &vals, &cur, "solving");

        assert!(!result.is_error());
        assert_eq!(result.get_description(), "solving");
        assert!(f.backfill_calls.borrow().is_empty());
    }

    #[test]
    fn solve_or_backfill_falls_back_to_backfill_when_symbol_missing() {
        let f = factory();
        let vals = HashMap::new();
        let cur = MockPatterns { desc: "cur".to_string() };
        let exp = PatternExpression::Constant(0);

        let result = f.solve_or_backfill(&exp, 5, &vals, &cur, "backfilling");

        assert!(!result.is_error());
        assert_eq!(result.get_description(), "backfilling");
        assert_eq!(f.backfill_calls.borrow().len(), 1);
        assert_eq!(f.backfill_calls.borrow()[0], MaskedLong::from_long(5));
    }

    #[test]
    fn solve_or_backfill_bits_masks_partial_width() {
        let f = factory();
        let vals = HashMap::new();
        let cur = MockPatterns { desc: "cur".to_string() };
        let exp = PatternExpression::Constant(0);

        f.solve_or_backfill_bits(&exp, 0xFF, 4, &vals, &cur, "masked");

        // bits=4 => mask = ~(-1 << 4) = 0xF
        assert_eq!(
            f.backfill_calls.borrow()[0],
            MaskedLong::from_mask_and_value(0xF, 0xFF)
        );
    }

    #[test]
    fn solve_or_backfill_bits_zero_means_fully_defined() {
        let f = factory();
        let vals = HashMap::new();
        let cur = MockPatterns { desc: "cur".to_string() };
        let exp = PatternExpression::Constant(0);

        f.solve_or_backfill_bits(&exp, 0x1234, 0, &vals, &cur, "masked");

        assert_eq!(
            f.backfill_calls.borrow()[0],
            MaskedLong::from_mask_and_value(-1, 0x1234)
        );
    }

    #[test]
    fn from_string_ok_and_err_paths() {
        let f = factory();
        assert!(f.from_string("", "d", vec![]).is_ok());
        assert_eq!(f.from_string("garbage", "d", vec![]).unwrap_err(), "garbage");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let f = factory();
        let as_dyn: &dyn AbstractAssemblyResolutionFactory = &f;
        assert_eq!(as_dyn.nop("x").get_description(), "x");
    }
}
