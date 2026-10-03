//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyGeneratedPrototype`.

use super::{AbstractAssemblyState, AssemblyResolvedPatterns};

/// A tree of generated assembly node states, paired with the resulting patterns.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyGeneratedPrototype`.
///
/// This is used as the intermediate result when generating states, since the patterns must be
/// propagated to each operand as generation proceeds. Usually, the patterns in the final output
/// are discarded, and machine code generation proceeds using only the state tree.
///
/// Java's `protected final` fields have no accessors of their own (same-package code, e.g. the
/// state-generator family, reads them directly); since nothing in this crate does that yet, they
/// are exposed here as plain `pub` fields, the closest match to Java's package-plus-subclass
/// visibility that Rust's module system offers without extra accessor boilerplate.
pub struct AssemblyGeneratedPrototype {
    /// The generated node state.
    pub state: Box<dyn AbstractAssemblyState>,
    /// The patterns resulting from generating `state`.
    pub patterns: Box<dyn AssemblyResolvedPatterns>,
}

impl AssemblyGeneratedPrototype {
    /// Construct a new generated prototype record.
    ///
    /// Mirrors `AssemblyGeneratedPrototype(AbstractAssemblyState, AssemblyResolvedPatterns)`.
    pub fn new(
        state: Box<dyn AbstractAssemblyState>,
        patterns: Box<dyn AssemblyResolvedPatterns>,
    ) -> Self {
        Self { state, patterns }
    }
}

impl std::fmt::Display for AssemblyGeneratedPrototype {
    /// Mirrors `AssemblyGeneratedPrototype.toString()`: `state + " [" + patterns + "]"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]", self.state, self.patterns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::sem::{
        AbstractAssemblyResolutionFactory, AbstractAssemblyTreeResolver, AssemblyResolution,
        AssemblyResolvedBackfill,
    };
    use crate::app::seam_stubs::{
        AssemblyConstructorSemantic, AssemblyContextGraph, AssemblyPatternBlock,
        AssemblyResolutionResults, Constructor, MaskedLong,
    };
    use std::cell::Cell;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::sync::Arc;

    // --- A minimal `AbstractAssemblyState` mock, real enough to prove `Display`/field access
    // work end-to-end. Every hook beyond what `Display`/construction touch just panics if
    // reached, following the convention `abstract_assembly_state.rs`'s own tests use for their
    // `MockFactory`/`MockTreeResolver`. ---

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
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
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
        fn instr_only(
            &self,
            _ins: Box<dyn AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn context_only(
            &self,
            _ctx: Box<dyn AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn from_pattern(
            &self,
            _pat: &crate::program::model::lang::sleigh::pattern::DisjointPattern,
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
            _exp: &crate::program::model::lang::sleigh::expression::PatternExpression,
            _goal: MaskedLong,
            _vals: &HashMap<String, i64>,
            _cur: &dyn AssemblyResolvedPatterns,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockTreeResolver {
        factory: Arc<dyn AbstractAssemblyResolutionFactory>,
    }

    impl AbstractAssemblyTreeResolver for MockTreeResolver {
        fn factory(&self) -> Arc<dyn AbstractAssemblyResolutionFactory> {
            self.factory.clone()
        }
        fn lang(&self) -> &crate::program::model::lang::sleigh::SleighLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn at(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by these tests")
        }
        fn tree(&self) -> Arc<dyn crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch> {
            unimplemented!("not exercised by these tests")
        }
        fn grammar(&self) -> Arc<dyn crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar> {
            unimplemented!("not exercised by these tests")
        }
        fn context(&self) -> Arc<dyn AssemblyPatternBlock> {
            unimplemented!("not exercised by these tests")
        }
        fn ctx_graph(&self) -> Arc<dyn AssemblyContextGraph> {
            unimplemented!("not exercised by these tests")
        }
        fn vals(&self) -> &HashMap<String, i64> {
            unimplemented!("not exercised by these tests")
        }
        fn vals_mut(&mut self) -> &mut HashMap<String, i64> {
            unimplemented!("not exercised by these tests")
        }
        fn resolve(&mut self) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn resolve_root_recursion(
            &self,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn resolve_pending_backfills(
            &mut self,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn select_context(
            &self,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn filter_forbidden(
            &self,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn filter_by_disassembly(
            &self,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn get_state_generator(
            &self,
            _op_sym: &dyn crate::app::seam_stubs::OperandSymbol,
            _node: Option<&dyn crate::app::seam_stubs::AssemblyParseTreeNode>,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn crate::app::seam_stubs::AbstractAssemblyStateGenerator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_hidden_state_generator(
            &self,
            _op_sym: &dyn crate::app::seam_stubs::OperandSymbol,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn crate::app::seam_stubs::AbstractAssemblyStateGenerator> {
            unimplemented!("not exercised by these tests")
        }
        fn resolve_patterns(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _shift: i32,
            _from_children: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn apply_mutations(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn apply_patterns(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _shift: i32,
            _temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn apply_recursion_path(
            &self,
            _path: &mut std::collections::VecDeque<Arc<dyn AssemblyConstructorSemantic>>,
            _branch: &dyn crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch,
            _rec: &dyn crate::app::seam_stubs::AssemblyProduction,
            _child: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
        fn try_resolve_backfills(
            &self,
            _results: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockState {
        shift: i32,
        length: i32,
        resolver: Arc<dyn AbstractAssemblyTreeResolver>,
    }

    impl std::fmt::Display for MockState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "state(shift:{},length:{})", self.shift, self.length)
        }
    }

    impl AbstractAssemblyState for MockState {
        fn resolver(&self) -> Arc<dyn AbstractAssemblyTreeResolver> {
            self.resolver.clone()
        }
        fn path(&self) -> &[Arc<dyn AssemblyConstructorSemantic>] {
            &[]
        }
        fn shift(&self) -> i32 {
            self.shift
        }
        fn length(&self) -> i32 {
            self.length
        }
        fn hash_cache(&self) -> &Cell<Option<i32>> {
            unimplemented!("not exercised by these tests")
        }
        fn compute_hash(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn equals(&self, _other: &dyn AbstractAssemblyState) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn resolve(
            &self,
            _from_right: &dyn AssemblyResolvedPatterns,
            _errors: &mut Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedError>>,
        ) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockPatterns {
        desc: String,
    }

    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }
    impl std::fmt::Debug for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockPatterns({})", self.desc)
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
            unimplemented!("not exercised by these tests")
        }
        fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
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
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            unimplemented!("not exercised by these tests")
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            unimplemented!("not exercised by these tests")
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn get_instruction_length(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_defined_instruction_length(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_backfills(&self) -> Vec<Box<dyn AssemblyResolvedBackfill>> {
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
        fn with_constructor(&self, _cons: Arc<dyn Constructor>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine(
            &self,
            _pat: &dyn AssemblyResolvedPatterns,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_backfill(&self, _bf: &dyn AssemblyResolvedBackfill) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine_less_backfill(
            &self,
            _that: &dyn AssemblyResolvedPatterns,
            _bf: &dyn AssemblyResolvedBackfill,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            unimplemented!("not exercised by these tests")
        }
        fn parent_patterns(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn backfill(
            &self,
            _solver: &dyn crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver,
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
            _sem: &dyn AssemblyConstructorSemantic,
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

    fn make_prototype(shift: i32, length: i32, desc: &str) -> AssemblyGeneratedPrototype {
        let resolver = Arc::new(MockTreeResolver { factory: Arc::new(MockFactory) });
        let state: Box<dyn AbstractAssemblyState> = Box::new(MockState { shift, length, resolver });
        let patterns: Box<dyn AssemblyResolvedPatterns> =
            Box::new(MockPatterns { desc: desc.to_string() });
        AssemblyGeneratedPrototype::new(state, patterns)
    }

    #[test]
    fn new_stores_state_and_patterns_by_field() {
        let proto = make_prototype(1, 4, "ins:00");
        assert_eq!(proto.state.get_shift(), 1);
        assert_eq!(proto.state.get_length(), 4);
        assert_eq!(proto.patterns.get_description(), "ins:00");
    }

    #[test]
    fn display_matches_java_to_string_format() {
        // Mirrors `AssemblyGeneratedPrototype.toString()`: `state + " [" + patterns + "]"`.
        let proto = make_prototype(2, 3, "ins:ff");
        assert_eq!(proto.to_string(), "state(shift:2,length:3) [ins:ff]");
    }
}
