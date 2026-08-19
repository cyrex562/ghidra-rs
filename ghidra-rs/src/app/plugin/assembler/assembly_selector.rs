//! Mirrors `ghidra.app.plugin.assembler.AssemblySelector`.

use std::cmp::Ordering;

use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;
use crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedPatterns;
use crate::app::plugin::assembler::sleigh::util::compare_arrays;
use crate::app::seam_stubs::{
    AssemblyPatternBlock, AssemblyResolutionEntry, AssemblyResolutionResults, AssemblySyntaxError,
    AssemblySyntaxException,
};

use super::AssemblySemanticException;

/// A resolved selection from the results given to [`AssemblySelector::select`].
///
/// `ins` holds the resolved instruction bytes, ideally with a full mask. `ctx` holds the resolved
/// context bytes for compatibility checks.
///
/// Mirrors `AssemblySelector.Selection`.
pub struct Selection {
    pub ins: Box<dyn AssemblyPatternBlock>,
    pub ctx: Box<dyn AssemblyPatternBlock>,
}

/// Provides a mechanism for pruning and selecting binary assembled instructions from the results
/// of parsing textual assembly instructions. There are two opportunities: after parsing, but
/// before prototype generation, and after machine code generation. In the first opportunity,
/// filtering is optional -- the implementor may discard any or all parse trees. The second is
/// required, since only one instruction may be placed at the desired address -- the implementor
/// must select one instruction among the many results, and if a mask is present, decide on a
/// value for the omitted bits.
///
/// Implementors of this trait are also suitable for collecting diagnostic information about
/// attempted assemblies. For example, an implementation may employ the syntax errors in order to
/// produce code completion suggestions in a GUI.
///
/// Mirrors `ghidra.app.plugin.assembler.AssemblySelector`, cut to a trait to break a dependency
/// cycle running through the assembler, parse-result, and resolution types. The class's
/// `syntaxErrors`/`semanticErrors` fields are dropped: Java never exposes them beyond the method
/// that populates them (no getter exists, and no subclass reads them directly), so each is kept
/// as a local variable inside the corresponding default method rather than promoted to a
/// trait-level accessor hook, matching their actual (method-scoped) usage.
///
/// [`AssemblyResolutionResults`], [`AssemblyPatternBlock`], and [`AssemblyResolvedPatterns`] are
/// not yet ported, so they're referenced through the minimal placeholder traits of the same name
/// in [`crate::app::seam_stubs`]. `AssemblySyntaxException` is likewise unported; its stand-in,
/// [`AssemblySyntaxError`], is a boxed `std::error::Error` (see
/// [`AssemblySyntaxException`](crate::app::seam_stubs::AssemblySyntaxException)'s docs).
pub trait AssemblySelector {
    /// Filter a collection of parse trees.
    ///
    /// Generally, the assembly resolver considers every possible parsing of an assembly
    /// instruction. If, for some reason, the implementor wishes to ignore certain trees (perhaps
    /// for efficiency, or perhaps because a certain form of instruction is desired), entire parse
    /// trees may be pruned here.
    ///
    /// It is possible that no trees pass the filter. In this case, this method returns an `Err`.
    /// Another option (for an override) is to pass the erroneous result on for semantic analysis,
    /// in which case, the error is simply copied into an erroneous semantic result. Depending on
    /// preferences, this may simplify the overall filtering and error-handling logic.
    ///
    /// By default, no filtering is applied. If all the trees produce syntax errors, an `Err` is
    /// returned.
    ///
    /// Mirrors `AssemblySelector.filterParse(Collection<AssemblyParseResult>)`.
    fn filter_parse(
        &self,
        parse: Vec<Box<dyn AssemblyParseResult>>,
    ) -> Result<Vec<Box<dyn AssemblyParseResult>>, Box<dyn AssemblySyntaxException>> {
        let mut error_messages = Vec::new();
        let mut got_one = false;
        for pr in &parse {
            if pr.is_error() {
                error_messages.push(pr.to_string());
            } else {
                got_one = true;
            }
        }
        if !got_one {
            return Err(Box::new(AssemblySyntaxError::new(error_messages.join("\n"))));
        }
        Ok(parse)
    }

    /// A comparator on instruction length (shortest first), then bits lexicographically.
    ///
    /// Mirrors `AssemblySelector.compareBySizeThenBits`.
    fn compare_by_size_then_bits(
        &self,
        a: &dyn AssemblyResolvedPatterns,
        b: &dyn AssemblyResolvedPatterns,
    ) -> Ordering {
        let len_cmp = a.get_instruction_length().cmp(&b.get_instruction_length());
        if len_cmp != Ordering::Equal {
            return len_cmp;
        }
        compare_arrays(&a.get_instruction().get_vals(), &b.get_instruction().get_vals())
    }

    /// Select only non-erroneous results whose contexts are compatible, sorted shortest-first
    /// then lexicographically.
    ///
    /// Mirrors `AssemblySelector.filterCompatibleAndSort(AssemblyResolutionResults,
    /// AssemblyPatternBlock)`. `ctx` is accepted for signature parity with the Java method, which
    /// likewise never reads its `ctx` parameter in this default implementation.
    fn filter_compatible_and_sort(
        &self,
        rr: &dyn AssemblyResolutionResults,
        _ctx: &dyn AssemblyPatternBlock,
    ) -> Result<Vec<Box<dyn AssemblyResolvedPatterns>>, AssemblySemanticException> {
        let mut semantic_errors = Vec::new();
        let mut sorted: Vec<Box<dyn AssemblyResolvedPatterns>> = Vec::new();
        for entry in rr.resolutions() {
            match entry {
                AssemblyResolutionEntry::Error(e) => semantic_errors.push(e),
                AssemblyResolutionEntry::Patterns(p) => sorted.push(p),
            }
        }
        if sorted.is_empty() {
            return Err(AssemblySemanticException::with_errors(semantic_errors));
        }
        sorted.sort_by(|a, b| self.compare_by_size_then_bits(a.as_ref(), b.as_ref()));
        Ok(sorted)
    }

    /// Select an instruction from the possible results.
    ///
    /// This must select precisely one resolved constructor from the results given back by the
    /// assembly resolver. This further implies the mask of the returned result must consist of
    /// all 1s. If no selection is suitable, this returns an `Err`.
    ///
    /// By default, this method selects the shortest instruction that is compatible with the
    /// given context and takes 0 for bits that fall outside the mask. If all possible resolutions
    /// produce errors, an `Err` is returned.
    ///
    /// Mirrors `AssemblySelector.select(AssemblyResolutionResults, AssemblyPatternBlock)`.
    fn select(
        &self,
        rr: &dyn AssemblyResolutionResults,
        ctx: &dyn AssemblyPatternBlock,
    ) -> Result<Selection, AssemblySemanticException> {
        let mut sorted = self.filter_compatible_and_sort(rr, ctx)?;
        let res = sorted.remove(0);
        Ok(Selection {
            ins: res.get_instruction().fill_mask(),
            ctx: res.get_context(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::sem::AssemblyResolution;
    use crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedError;

    /// The default `AssemblySelector`, exercising every method purely through defaults --
    /// mirrors instantiating the abstract Java class directly (its subclasses in Ghidra all do
    /// exactly this, overriding nothing).
    struct DefaultSelector;
    impl AssemblySelector for DefaultSelector {}

    // --- AssemblyParseResult mocks ---

    struct MockParse {
        text: &'static str,
        error: bool,
    }

    impl std::fmt::Display for MockParse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.text)
        }
    }

    impl AssemblyParseResult for MockParse {
        fn is_error(&self) -> bool {
            self.error
        }
    }

    // --- AssemblyPatternBlock mock ---

    #[derive(Clone)]
    struct MockBlock {
        vals: Vec<i8>,
    }

    impl AssemblyPatternBlock for MockBlock {
        fn get_vals(&self) -> Vec<i8> {
            self.vals.clone()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![-1; self.vals.len()] })
        }
    }

    // --- AssemblyResolvedPatterns mock ---

    #[derive(Clone)]
    struct MockPatterns {
        len: i32,
        instr: Vec<i8>,
        ctx: Vec<i8>,
    }

    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "patterns(len={})", self.len)
        }
    }

    impl std::fmt::Debug for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockPatterns({})", self.len)
        }
    }

    impl AssemblyResolution for MockPatterns {
        fn get_description(&self) -> String {
            self.to_string()
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
            self.get_description()
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
        fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.get_description())
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.get_description().cmp(&other.get_description())
        }
    }

    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: self.instr.clone() })
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: self.ctx.clone() })
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn get_instruction_length(&self) -> i32 {
            self.len
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
        fn read_instruction(&self, _byte_start: i32, _size: i32) -> crate::app::seam_stubs::MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context(&self, _start: i32, _len: i32) -> crate::app::seam_stubs::MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn read_context_op(
            &self,
            _cop: &crate::program::model::lang::sleigh::constructor::ContextOp,
        ) -> crate::app::seam_stubs::MaskedLong {
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
            _solver: &dyn crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver,
            _vals: &std::collections::HashMap<String, i64>,
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
            _vals: &std::collections::HashMap<String, i64>,
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
            _val: crate::app::seam_stubs::MaskedLong,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
    }

    // --- AssemblyResolvedError mock ---

    #[derive(Clone)]
    struct MockError {
        msg: String,
    }

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }

    impl std::fmt::Debug for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockError({})", self.msg)
        }
    }

    impl AssemblyResolution for MockError {
        fn get_description(&self) -> String {
            self.msg.clone()
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
            self.get_description()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            true
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{}{}", indent, self.get_description())
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.get_description().cmp(&other.get_description())
        }
    }

    impl AssemblyResolvedError for MockError {
        fn get_error(&self) -> String {
            self.msg.clone()
        }
    }

    // --- AssemblyResolutionResults mock ---

    struct MockResults {
        patterns: Vec<(i32, Vec<i8>, Vec<i8>)>,
        errors: Vec<String>,
    }

    impl AssemblyResolutionResults for MockResults {
        fn resolutions(&self) -> Vec<AssemblyResolutionEntry> {
            let mut out = Vec::new();
            for (len, instr, ctx) in &self.patterns {
                out.push(AssemblyResolutionEntry::Patterns(Box::new(MockPatterns {
                    len: *len,
                    instr: instr.clone(),
                    ctx: ctx.clone(),
                })));
            }
            for msg in &self.errors {
                out.push(AssemblyResolutionEntry::Error(Box::new(MockError { msg: msg.clone() })));
            }
            out
        }
        fn iter_all(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>> {
            unimplemented!("not exercised by these tests")
        }
        fn add(
            &mut self,
            _ar: Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>,
        ) {
            unimplemented!("not exercised by these tests")
        }
    }

    // --- filter_parse ---

    #[test]
    fn filter_parse_passes_through_when_at_least_one_accepted() {
        let sel = DefaultSelector;
        let parse: Vec<Box<dyn AssemblyParseResult>> = vec![
            Box::new(MockParse { text: "bad", error: true }),
            Box::new(MockParse { text: "good", error: false }),
        ];
        let result = sel.filter_parse(parse).expect("at least one accept, should not error");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_parse_errors_when_all_results_are_syntax_errors() {
        let sel = DefaultSelector;
        let parse: Vec<Box<dyn AssemblyParseResult>> = vec![
            Box::new(MockParse { text: "bad1", error: true }),
            Box::new(MockParse { text: "bad2", error: true }),
        ];
        let err = match sel.filter_parse(parse) {
            Err(e) => e,
            Ok(_) => panic!("all errors, should fail"),
        };
        assert_eq!(err.to_string(), "bad1\nbad2");
    }

    // --- compare_by_size_then_bits ---

    #[test]
    fn compare_by_size_then_bits_prefers_shorter_instruction() {
        let sel = DefaultSelector;
        let short = MockPatterns { len: 2, instr: vec![9], ctx: vec![] };
        let long = MockPatterns { len: 4, instr: vec![0], ctx: vec![] };
        assert_eq!(sel.compare_by_size_then_bits(&short, &long), Ordering::Less);
        assert_eq!(sel.compare_by_size_then_bits(&long, &short), Ordering::Greater);
    }

    #[test]
    fn compare_by_size_then_bits_breaks_ties_lexicographically() {
        let sel = DefaultSelector;
        let a = MockPatterns { len: 2, instr: vec![1, 1], ctx: vec![] };
        let b = MockPatterns { len: 2, instr: vec![1, 2], ctx: vec![] };
        assert_eq!(sel.compare_by_size_then_bits(&a, &b), Ordering::Less);
    }

    // --- filter_compatible_and_sort / select ---

    #[test]
    fn select_picks_shortest_compatible_resolution() {
        let sel = DefaultSelector;
        let rr = MockResults {
            patterns: vec![
                (4, vec![3, 3], vec![9, 9]),
                (2, vec![1, 1], vec![8, 8]),
            ],
            errors: vec![],
        };
        let ctx = MockBlock { vals: vec![] };
        let selection = sel.select(&rr, &ctx).expect("has a compatible resolution");
        // Chosen resolution is the length-2 one; its instruction is fully masked (all -1 bytes).
        assert_eq!(selection.ins.get_vals(), vec![-1, -1]);
        assert_eq!(selection.ctx.get_vals(), vec![8, 8]);
    }

    #[test]
    fn select_ignores_error_records_and_picks_among_the_rest() {
        let sel = DefaultSelector;
        let rr = MockResults {
            patterns: vec![(2, vec![5, 5], vec![1, 1])],
            errors: vec!["incompatible context".to_string()],
        };
        let ctx = MockBlock { vals: vec![] };
        let selection = sel.select(&rr, &ctx).expect("one non-error resolution remains");
        assert_eq!(selection.ctx.get_vals(), vec![1, 1]);
    }

    #[test]
    fn select_errors_when_every_resolution_is_an_error() {
        let sel = DefaultSelector;
        let rr = MockResults { patterns: vec![], errors: vec!["bad ctx".to_string()] };
        let ctx = MockBlock { vals: vec![] };
        let err = match sel.select(&rr, &ctx) {
            Err(e) => e,
            Ok(_) => panic!("no compatible resolution, should fail"),
        };
        assert_eq!(err.message(), "bad ctx");
    }

    #[test]
    fn filter_compatible_and_sort_orders_shortest_first() {
        let sel = DefaultSelector;
        let rr = MockResults {
            patterns: vec![
                (6, vec![0], vec![]),
                (2, vec![0], vec![]),
                (4, vec![0], vec![]),
            ],
            errors: vec![],
        };
        let ctx = MockBlock { vals: vec![] };
        let sorted = sel.filter_compatible_and_sort(&rr, &ctx).expect("non-empty");
        let lengths: Vec<i32> = sorted.iter().map(|p| p.get_instruction_length()).collect();
        assert_eq!(lengths, vec![2, 4, 6]);
    }

    // --- object safety ---

    #[test]
    fn trait_is_object_safe() {
        let sel: Box<dyn AssemblySelector> = Box::new(DefaultSelector);
        let rr = MockResults { patterns: vec![(2, vec![7], vec![3])], errors: vec![] };
        let ctx = MockBlock { vals: vec![] };
        let selection = sel.select(&rr, &ctx).expect("has a compatible resolution");
        assert_eq!(selection.ins.get_vals(), vec![-1]);
    }
}
