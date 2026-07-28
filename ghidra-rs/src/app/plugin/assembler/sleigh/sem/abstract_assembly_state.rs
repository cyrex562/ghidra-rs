//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyState`.

use std::cell::Cell;
use std::sync::Arc;

use super::{AbstractAssemblyResolutionFactory, AbstractAssemblyTreeResolver, AssemblyResolvedError};
use crate::app::seam_stubs::{AssemblyConstructorSemantic, AssemblyResolvedPatterns};

/// Base for a node in an assembly prototype.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyState`, chosen (alongside
/// [`AbstractAssemblyTreeResolver`]) as a cut-point for the same dependency cycle: every concrete
/// subclass (`AssemblyConstructState`, `AssemblyOperandState`, `AssemblyNopState`,
/// `AssemblyStringState`, `AssemblyHiddenConstructState`, ...) holds a `resolver:
/// AbstractAssemblyTreeResolver<?>` field assigned straight from this class's own constructor
/// parameter and calls back into it, while `AbstractAssemblyTreeResolver` itself constructs and
/// returns instances of those same subclasses (via its state-generator family,
/// `getStateGenerator`/`getHiddenStateGenerator`) -- a genuine two-way cycle. See
/// [`AbstractAssemblyTreeResolver`]'s own doc comment for the fuller account of that cycle and why
/// it's cut here.
///
/// The four `protected final` constructor-assigned fields (`resolver`, `path`, `shift`, `length`)
/// are modeled as required hook accessors ([`resolver`](Self::resolver), [`path`](Self::path),
/// [`shift`](Self::shift), [`length`](Self::length)), mirroring the same pattern
/// [`AbstractAssemblyTreeResolver`] uses for its own constructor-assigned fields, since a trait has
/// no fields of its own. The fifth, `factory` (assigned in the Java constructor from
/// `resolver.factory`), is instead a default method ([`factory`](Self::factory)) that simply
/// delegates to [`resolver`](Self::resolver) -- there is nothing for an implementer to store beyond
/// the resolver itself.
///
/// The `hasHash`/`hash` pair of `volatile` fields backing `hashCode()`'s lazy, thread-safe cache is
/// modeled as a single required hook, [`hash_cache`](Self::hash_cache), returning a
/// `&Cell<Option<i32>>` rather than a get/set accessor pair -- this keeps [`hash_code`](Self::hash_code)
/// a `&self` method (as Java's `hashCode()` is), matching the original's call shape, instead of
/// forcing every caller of a lazily-cached hash to hold a `&mut` reference.
///
/// `computeHash()` and `equals(Object)` are ported as required (bodyless) trait methods --
/// [`compute_hash`](Self::compute_hash) and [`equals`](Self::equals) -- since each concrete
/// subclass defines its own notion of structural equality/hash over its own additional fields,
/// which this trait cannot see. `equals`'s `Object` parameter becomes `&dyn AbstractAssemblyState`,
/// mirroring the pattern already used for
/// [`AssemblyResolution::compare_to`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolution::compare_to)'s
/// own `Comparable<AssemblyResolution>` parameter.
///
/// The protected abstract `resolve(AssemblyResolvedPatterns, Collection<AssemblyResolvedError>)` is
/// likewise a required trait method, [`resolve`](Self::resolve): each subclass's body drives real
/// SLEIGH pattern resolution over collaborators (`AssemblyConstructorSemantic.solveContextChanges`,
/// `AssemblyResolvedPatterns.combine`, child `AbstractAssemblyState`s, ...) that this crate has not
/// ported yet -- exactly the other half of the cycle this trait exists to defer. Java's
/// `Stream<AssemblyResolvedPatterns>` return and `Collection<AssemblyResolvedError>` out-parameter
/// become a returned `Vec<Box<dyn AssemblyResolvedPatterns>>` and a `&mut Vec<Box<dyn
/// AssemblyResolvedError>>`, respectively, matching this crate's existing collection conventions
/// (e.g. [`AssemblyResolutionResults::iter_all`](crate::app::seam_stubs::AssemblyResolutionResults::iter_all)).
///
/// `getResolver`, `getPath`, `getShift`, `getLength`, and `hashCode` are ported as default methods,
/// since each is a pure function of the hooks above.
pub trait AbstractAssemblyState {
    /// The resolver driving this node's resolution.
    ///
    /// Mirrors the constructor-assigned `resolver` field.
    fn resolver(&self) -> Arc<dyn AbstractAssemblyTreeResolver>;

    /// The path to this node, for diagnostics.
    ///
    /// Mirrors the constructor-assigned `path` field.
    fn path(&self) -> &[Arc<dyn AssemblyConstructorSemantic>];

    /// The (right) shift in bytes for this operand.
    ///
    /// Mirrors the constructor-assigned `shift` field.
    fn shift(&self) -> i32;

    /// The length of this operand.
    ///
    /// Mirrors the constructor-assigned `length` field.
    fn length(&self) -> i32;

    /// Lazily-computed cache backing [`hash_code`](Self::hash_code).
    ///
    /// Mirrors the pair of `volatile` fields `hasHash`/`hash`: `None` means not yet computed
    /// (`hasHash == false`), `Some(h)` means computed (`hasHash == true`, `hash == h`).
    fn hash_cache(&self) -> &Cell<Option<i32>>;

    /// The factory used to build assembly results.
    ///
    /// Mirrors the constructor-assigned `factory` field, assigned in the Java constructor from
    /// `resolver.factory`.
    fn factory(&self) -> Arc<dyn AbstractAssemblyResolutionFactory> {
        self.resolver().factory()
    }

    /// Pre-compute this node's hash.
    ///
    /// Mirrors the public abstract `AbstractAssemblyState.computeHash()`.
    fn compute_hash(&self) -> i32;

    /// Structural equality with another node.
    ///
    /// Mirrors the public abstract `AbstractAssemblyState.equals(Object)`.
    fn equals(&self, other: &dyn AbstractAssemblyState) -> bool;

    /// Generate machine (partial) code for this node.
    ///
    /// Mirrors the protected abstract `AbstractAssemblyState.resolve(AssemblyResolvedPatterns,
    /// Collection<AssemblyResolvedError>)`: `from_right` is the accumulated patterns thus far, from
    /// the right sibling or left-most child; `errors` collects error reports as resolution
    /// proceeds. Left as a required method: reproducing any concrete subclass's body needs the
    /// collaborator graph this trait was cut to defer (see this trait's own doc comment).
    fn resolve(
        &self,
        from_right: &dyn AssemblyResolvedPatterns,
        errors: &mut Vec<Box<dyn AssemblyResolvedError>>,
    ) -> Vec<Box<dyn AssemblyResolvedPatterns>>;

    /// Get the resolver driving this node's resolution.
    ///
    /// Mirrors `AbstractAssemblyState.getResolver()`.
    fn get_resolver(&self) -> Arc<dyn AbstractAssemblyTreeResolver> {
        self.resolver()
    }

    /// Get the path to this node, for diagnostics.
    ///
    /// Mirrors `AbstractAssemblyState.getPath()`.
    fn get_path(&self) -> &[Arc<dyn AssemblyConstructorSemantic>] {
        self.path()
    }

    /// Get the (right) shift in bytes for this operand.
    ///
    /// Mirrors `AbstractAssemblyState.getShift()`.
    fn get_shift(&self) -> i32 {
        self.shift()
    }

    /// Get the length in bytes of the operand represented by this node.
    ///
    /// Mirrors `AbstractAssemblyState.getLength()`.
    fn get_length(&self) -> i32 {
        self.length()
    }

    /// Get this node's hash, computing and caching it on first call.
    ///
    /// Mirrors `AbstractAssemblyState.hashCode()`.
    fn hash_code(&self) -> i32 {
        if let Some(h) = self.hash_cache().get() {
            return h;
        }
        let h = self.compute_hash();
        self.hash_cache().set(Some(h));
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
    use crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch;
    use crate::app::seam_stubs::{
        AbstractAssemblyStateGenerator, AssemblyContextGraph, AssemblyParseTreeNode,
        AssemblyPatternBlock, AssemblyProduction, AssemblyResolutionResults, OperandSymbol,
    };
    use super::super::AssemblyResolution;
    use crate::program::model::address::Address;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use std::collections::{HashMap, VecDeque};

    // --- A minimal `AbstractAssemblyTreeResolver` mock. Only `factory()` is ever exercised by
    // the tests below (via `AbstractAssemblyState::factory`'s default delegation), so every other
    // hook/required method just panics if called -- no need to construct a real `SleighLanguage`,
    // `Address`, or any of the other collaborator mocks that `AbstractAssemblyTreeResolver`'s own
    // test suite builds for its fuller set of exercised methods. ---

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
            _goal: crate::app::seam_stubs::MaskedLong,
            _inslen: i32,
            _description: &str,
        ) -> Box<dyn AssemblyResolution> {
            unimplemented!("not exercised by these tests")
        }
        fn resolved(
            &self,
            _ins: Box<dyn crate::app::seam_stubs::AssemblyPatternBlock>,
            _ctx: Box<dyn crate::app::seam_stubs::AssemblyPatternBlock>,
            _description: &str,
            _cons: Option<Arc<dyn crate::app::seam_stubs::Constructor>>,
            _children: Vec<Box<dyn AssemblyResolution>>,
            _right: Option<Box<dyn AssemblyResolution>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn instr_only(
            &self,
            _ins: Box<dyn crate::app::seam_stubs::AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn context_only(
            &self,
            _ctx: Box<dyn crate::app::seam_stubs::AssemblyPatternBlock>,
            _description: &str,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn from_pattern(
            &self,
            _pat: &crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _min_len: i32,
            _description: &str,
            _cons: Option<Arc<dyn crate::app::seam_stubs::Constructor>>,
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
            _goal: crate::app::seam_stubs::MaskedLong,
            _vals: &std::collections::HashMap<String, i64>,
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
        fn lang(&self) -> &SleighLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn at(&self) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn tree(&self) -> Arc<dyn AssemblyParseBranch> {
            unimplemented!("not exercised by these tests")
        }
        fn grammar(&self) -> Arc<dyn AssemblyGrammar> {
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
            _op_sym: &dyn OperandSymbol,
            _node: Option<&dyn AssemblyParseTreeNode>,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AbstractAssemblyStateGenerator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_hidden_state_generator(
            &self,
            _op_sym: &dyn OperandSymbol,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AbstractAssemblyStateGenerator> {
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
            _path: &mut VecDeque<Arc<dyn AssemblyConstructorSemantic>>,
            _branch: &dyn AssemblyParseBranch,
            _rec: &dyn AssemblyProduction,
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

    // --- The `AbstractAssemblyState` mock itself: real enough to exercise the default methods
    // under test (`factory`, `get_resolver`, `get_path`, `get_shift`, `get_length`, `hash_code`)
    // against genuine, non-trivial hook behavior, and to prove object safety. ---

    struct MockState {
        resolver: Arc<dyn AbstractAssemblyTreeResolver>,
        path: Vec<Arc<dyn AssemblyConstructorSemantic>>,
        shift: i32,
        length: i32,
        hash_cache: Cell<Option<i32>>,
        hash_value: i32,
        compute_hash_calls: Cell<u32>,
    }

    impl AbstractAssemblyState for MockState {
        fn resolver(&self) -> Arc<dyn AbstractAssemblyTreeResolver> {
            self.resolver.clone()
        }
        fn path(&self) -> &[Arc<dyn AssemblyConstructorSemantic>] {
            &self.path
        }
        fn shift(&self) -> i32 {
            self.shift
        }
        fn length(&self) -> i32 {
            self.length
        }
        fn hash_cache(&self) -> &Cell<Option<i32>> {
            &self.hash_cache
        }
        fn compute_hash(&self) -> i32 {
            self.compute_hash_calls.set(self.compute_hash_calls.get() + 1);
            self.hash_value
        }
        fn equals(&self, other: &dyn AbstractAssemblyState) -> bool {
            self.get_shift() == other.get_shift() && self.get_length() == other.get_length()
        }
        fn resolve(
            &self,
            _from_right: &dyn AssemblyResolvedPatterns,
            _errors: &mut Vec<Box<dyn AssemblyResolvedError>>,
        ) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            Vec::new()
        }
    }

    fn make_state(shift: i32, length: i32, hash_value: i32) -> MockState {
        MockState {
            resolver: Arc::new(MockTreeResolver { factory: Arc::new(MockFactory) }),
            path: Vec::new(),
            shift,
            length,
            hash_cache: Cell::new(None),
            hash_value,
            compute_hash_calls: Cell::new(0),
        }
    }

    #[test]
    fn hash_code_computes_and_caches_on_first_call() {
        let state = make_state(0, 4, 0xCAFE);
        assert_eq!(state.compute_hash_calls.get(), 0);

        assert_eq!(state.hash_code(), 0xCAFE);
        assert_eq!(state.compute_hash_calls.get(), 1);
    }

    #[test]
    fn hash_code_does_not_recompute_once_cached() {
        let state = make_state(0, 4, 0xCAFE);

        assert_eq!(state.hash_code(), 0xCAFE);
        assert_eq!(state.hash_code(), 0xCAFE);
        assert_eq!(state.hash_code(), 0xCAFE);

        // computeHash() only ran once, on the first call, mirroring the `hasHash`-guarded lazy
        // cache in the Java `hashCode()` body.
        assert_eq!(state.compute_hash_calls.get(), 1);
    }

    #[test]
    fn equals_true_for_matching_shift_and_length() {
        let a = make_state(2, 4, 1);
        let b = make_state(2, 4, 2);
        assert!(a.equals(&b));
    }

    #[test]
    fn equals_false_for_differing_length() {
        let a = make_state(2, 4, 1);
        let b = make_state(2, 8, 1);
        assert!(!a.equals(&b));
    }

    #[test]
    fn get_shift_and_get_length_delegate_to_hooks() {
        let state = make_state(3, 6, 0);
        assert_eq!(state.get_shift(), 3);
        assert_eq!(state.get_length(), 6);
    }

    #[test]
    fn get_path_delegates_to_hook() {
        let state = make_state(0, 0, 0);
        assert!(state.get_path().is_empty());
    }

    #[test]
    fn factory_delegates_through_resolver() {
        let state = make_state(0, 0, 0);
        let via_default = state.factory();
        let via_resolver = state.get_resolver().factory();
        assert!(Arc::ptr_eq(&via_default, &via_resolver));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let state = make_state(1, 2, 0x1234);
        let as_dyn: &dyn AbstractAssemblyState = &state;
        assert_eq!(as_dyn.get_shift(), 1);
        assert_eq!(as_dyn.get_length(), 2);
        assert_eq!(as_dyn.hash_code(), 0x1234);
    }
}
