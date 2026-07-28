//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyTreeResolver`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::AssemblyResolution;
use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch;
use crate::app::seam_stubs::{
    AbstractAssemblyResolutionFactory, AbstractAssemblyStateGenerator, AssemblyConstructorSemantic,
    AssemblyContextGraph, AssemblyParseTreeNode, AssemblyPatternBlock, AssemblyProduction,
    AssemblyResolutionResults, AssemblyResolvedPatterns, Constructor, OperandSymbol,
};
use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::SleighLanguage;

/// The name under which the address (in addressable words) of the instruction's start is bound,
/// for use by SLEIGH expressions like `inst_start`.
///
/// Mirrors `AbstractAssemblyTreeResolver.INST_START`.
pub const INST_START: &str = "inst_start";

/// The name under which the address (in addressable words) immediately following the instruction
/// is bound, once its length is known.
///
/// Mirrors `AbstractAssemblyTreeResolver.INST_NEXT`.
pub const INST_NEXT: &str = "inst_next";

/// The name under which the address (in addressable words) immediately following the next
/// instruction would be bound. Mirrors `AbstractAssemblyTreeResolver.INST_NEXT2`; per the Java
/// class's own comment, `inst_next2` use is not really supported.
pub const INST_NEXT2: &str = "inst_next2";

/// The workhorse of semantic resolution for the assembler.
///
/// Takes a parse tree and some additional information (start address, context, etc.) and attempts
/// to determine possible encodings using the semantics associated with each branch of the given
/// parse tree.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyTreeResolver<RP extends
/// AssemblyResolvedPatterns>`, chosen as the cut-point for a dependency cycle running through the
/// tree resolver and the family of `AbstractAssemblyStateGenerator`/`AbstractAssemblyState`
/// subclasses (`AssemblyConstructStateGenerator`, `AssemblyOperandStateGenerator`,
/// `AssemblyHiddenConstructStateGenerator`, `AssemblyNopStateGenerator`,
/// `AssemblyStringStateGenerator`, and their `*State` counterparts): those classes each hold a
/// `resolver: AbstractAssemblyTreeResolver<?>` field and call back into it (`getStateGenerator`,
/// `resolvePatterns`, `parent`, ...), while `AbstractAssemblyTreeResolver` itself constructs and
/// returns instances of them (`getStateGenerator`/`getHiddenStateGenerator`) -- a genuine two-way
/// cycle. Java's `RP` type parameter is dropped in favor of the crate's existing
/// [`AssemblyResolvedPatterns`](crate::app::seam_stubs::AssemblyResolvedPatterns) placeholder,
/// referenced directly via `Box<dyn AssemblyResolvedPatterns>`, mirroring how
/// [`AbstractAssemblyProduction`](crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction)
/// dropped its own `NT` parameter for the same reason.
///
/// The seven `protected final` constructor-assigned fields (`factory`, `lang`, `at`, `tree`,
/// `grammar`, `context`, `ctxGraph`) are modeled as required hook accessors
/// ([`factory`](Self::factory), [`lang`](Self::lang), [`at`](Self::at), [`tree`](Self::tree),
/// [`grammar`](Self::grammar), [`context`](Self::context), [`ctx_graph`](Self::ctx_graph)), since
/// a trait has no fields of its own -- mirroring the same pattern used throughout this crate's
/// other abstract-class ports (e.g.
/// [`AbstractAssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyGrammar)).
/// This is not just an implementation convenience: `factory`, `grammar`, and `vals` are `protected`
/// (not `private`) specifically because same-package collaborators
/// (`AssemblyOperandState`, `AssemblyConstructState`, `AssemblyConstructStateGenerator`,
/// `AssemblyHiddenConstructStateGenerator`, `AbstractAssemblyState`) read them directly
/// (`resolver.vals`, `resolver.factory`, `resolver.grammar`) -- exactly the field-shaped API these
/// hooks expose. The mutable `vals` map (built from `at` at construction time, and further
/// populated by [`resolve_pending_backfills`](Self::resolve_pending_backfills)) is exposed as a
/// pair, [`vals`](Self::vals)/[`vals_mut`](Self::vals_mut), rather than get/put-by-key methods, to
/// match that direct field-reference usage.
///
/// [`get_factory`](Self::get_factory), [`get_grammar`](Self::get_grammar),
/// [`get_root_recursion`](Self::get_root_recursion), and the static
/// [`compute_offset`](Self::compute_offset) are ported as default methods, since each is a pure
/// function of the hooks above plus types this crate has already ported (or ports here as minimal
/// placeholders -- [`Constructor::operand`](crate::app::seam_stubs::Constructor::operand) and
/// [`OperandSymbol`](crate::app::seam_stubs::OperandSymbol)). Every other method --
/// [`resolve`](Self::resolve), [`resolve_root_recursion`](Self::resolve_root_recursion),
/// [`resolve_pending_backfills`](Self::resolve_pending_backfills),
/// [`select_context`](Self::select_context), [`filter_forbidden`](Self::filter_forbidden),
/// [`filter_by_disassembly`](Self::filter_by_disassembly),
/// [`get_state_generator`](Self::get_state_generator),
/// [`get_hidden_state_generator`](Self::get_hidden_state_generator),
/// [`resolve_patterns`](Self::resolve_patterns), [`apply_mutations`](Self::apply_mutations),
/// [`apply_patterns`](Self::apply_patterns), [`apply_recursion_path`](Self::apply_recursion_path),
/// and [`try_resolve_backfills`](Self::try_resolve_backfills) -- is left as a required (bodyless)
/// trait method instead. Their Java bodies drive the actual resolution algorithm: they construct
/// and stream `AssemblyConstructStateGenerator`/`GeneratorContext`/`AssemblyGeneratedPrototype`
/// values (the other, not-yet-ported half of the cycle this type was cut to break), call a rich
/// `AbstractAssemblyResolutionFactory` builder API (`nop`, `contextOnly`, `newErrorBuilder`,
/// per-entry `Set<AssemblyResolution>` transforms via `AssemblyResolutionResults.apply`/`absorb`),
/// and reach into deeply recursive collaborator logic
/// (`AssemblyConstructorSemantic.solveContextChanges`, `AssemblyResolvedPatterns.combine`, SLEIGH
/// disassembly via `SleighLanguage.parse`). Porting those bodies faithfully would require porting
/// that entire collaborator graph first -- exactly what a cut-point trait exists to defer. Each
/// required method's doc comment below describes the Java body it stands in for, for whichever
/// future port implements it.
///
/// `parent`'s Java body (`temp.stream().map(r -> r.parent(description, opCount)).collect(...)`)
/// is the one exception: it only needs [`AssemblyResolutionResults::iter_all`]/[`::add`](
/// crate::app::seam_stubs::AssemblyResolutionResults::add) (added to that stub for this purpose)
/// plus the already-ported [`AssemblyResolution::parent`], so it's a real default method here too.
///
/// This class has exactly two concrete subclasses in Ghidra,
/// `AssemblyTreeResolver` (in this same package) and `WildAssemblyTreeResolver` (in the
/// `WildcardAssembler` feature) -- neither adds any members of its own beyond a constructor, so
/// there is no additional public surface from them to fold into this trait.
pub trait AbstractAssemblyTreeResolver {
    /// The factory used to build assembly results.
    ///
    /// Mirrors the constructor-assigned `factory` field, directly read by same-package
    /// collaborators (e.g. `AbstractAssemblyState`'s constructor: `this.factory =
    /// resolver.factory`).
    fn factory(&self) -> Arc<dyn AbstractAssemblyResolutionFactory>;

    /// The language for which patterns are being resolved.
    ///
    /// Mirrors the constructor-assigned `lang` field.
    fn lang(&self) -> &SleighLanguage;

    /// The address where the instruction will start.
    ///
    /// Mirrors the constructor-assigned `at` field.
    fn at(&self) -> Address;

    /// The parse tree being resolved.
    ///
    /// Mirrors the constructor-assigned `tree` field.
    fn tree(&self) -> Arc<dyn AssemblyParseBranch>;

    /// The grammar the parse tree was derived from.
    ///
    /// Mirrors the constructor-assigned `grammar` field (itself derived from `tree.getGrammar()`
    /// at construction time), directly read by same-package collaborators (e.g.
    /// `AssemblyConstructStateGenerator.getSemantics`: `resolver.grammar.getSemantics(...)`).
    fn grammar(&self) -> Arc<dyn AssemblyGrammar>;

    /// The context expected at `inst_start`, already mask-filled.
    ///
    /// Mirrors the constructor-assigned `context` field (assigned from `context.fillMask()` in
    /// the Java constructor -- implementers of this hook are responsible for storing the
    /// already-filled value, since this trait has no constructor of its own to perform that step).
    fn context(&self) -> Arc<dyn AssemblyPatternBlock>;

    /// The context transition graph used to resolve purely-recursive productions.
    ///
    /// Mirrors the constructor-assigned `ctxGraph` field.
    fn ctx_graph(&self) -> Arc<dyn AssemblyContextGraph>;

    /// The symbols defined so far during resolution (at least [`INST_START`], populated at
    /// construction time from [`at`](Self::at)).
    ///
    /// Mirrors read access to the constructor-populated `vals` field, directly read by
    /// same-package collaborators (e.g. `AssemblyConstructState.resolveMutations`:
    /// `sem.solveContextChanges(fromChildren, resolver.vals)`).
    fn vals(&self) -> &HashMap<String, i64>;

    /// Mutable access to [`vals`](Self::vals), for binding further symbols (e.g. [`INST_NEXT`])
    /// once they become known.
    ///
    /// Mirrors mutation of the `vals` field, as performed by
    /// [`resolve_pending_backfills`](Self::resolve_pending_backfills)'s Java body
    /// (`vals.put(INST_NEXT, ...)`).
    fn vals_mut(&mut self) -> &mut HashMap<String, i64>;

    /// Get the factory for assembly results.
    ///
    /// Mirrors `AbstractAssemblyTreeResolver.getFactory()`.
    fn get_factory(&self) -> Arc<dyn AbstractAssemblyResolutionFactory> {
        self.factory()
    }

    /// Get the grammar the parse tree was derived from.
    ///
    /// Mirrors `AbstractAssemblyTreeResolver.getGrammar()`.
    fn get_grammar(&self) -> Arc<dyn AssemblyGrammar> {
        self.grammar()
    }

    /// If applicable, get the `I => I` production of the grammar.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.getRootRecursion()`. The `assert
    /// tree.getParent() == null` is dropped (this trait has no `AssemblyParseTreeNode` parent-link
    /// to inspect; see [`AssemblyParseBranch`]'s own doc comment for why).
    fn get_root_recursion(&self) -> Option<Arc<dyn AssemblyProduction>> {
        let root_prod = self.tree().get_production();
        let start = root_prod.lhs();
        self.grammar().get_pure_recursion(start.as_ref())
    }

    /// Resolve the tree for the given parameters.
    ///
    /// Mirrors the public `AbstractAssemblyTreeResolver.resolve()`: builds a root
    /// `AssemblyConstructStateGenerator` over [`tree`](Self::tree), generates and streams
    /// `AssemblyGeneratedPrototype`s from it, resolves each distinct prototype's state into
    /// patterns (collecting errors along the way), then pipes the combined results through
    /// [`resolve_root_recursion`](Self::resolve_root_recursion),
    /// [`select_context`](Self::select_context),
    /// [`resolve_pending_backfills`](Self::resolve_pending_backfills),
    /// [`filter_forbidden`](Self::filter_forbidden), and
    /// [`filter_by_disassembly`](Self::filter_by_disassembly) in that order, before appending the
    /// collected errors. Left as a required method: reproducing it needs
    /// `AssemblyConstructStateGenerator`/`GeneratorContext`/`AssemblyGeneratedPrototype`, the
    /// other half of the dependency cycle this trait was cut to break.
    fn resolve(&mut self) -> Box<dyn AssemblyResolutionResults>;

    /// If necessary, resolve recursive constructors at the root, usually for prefixes.
    ///
    /// Mirrors the public `AbstractAssemblyTreeResolver.resolveRootRecursion(AssemblyResolutionResults)`:
    /// if [`get_root_recursion`](Self::get_root_recursion) finds no purely-recursive production,
    /// returns `temp` unmodified; otherwise, for each non-error entry, asks
    /// [`ctx_graph`](Self::ctx_graph) for the optimal constructor applications from
    /// [`context`](Self::context) to that entry's own context (both in the `"instruction"` table),
    /// and absorbs the result of applying each such path via
    /// [`apply_recursion_path`](Self::apply_recursion_path). Left as a required method: it needs
    /// `AssemblyContextGraph.computeOptimalApplications`, which this trait's minimal
    /// [`AssemblyContextGraph`](crate::app::seam_stubs::AssemblyContextGraph) placeholder doesn't
    /// model.
    fn resolve_root_recursion(
        &self,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Attempt a second time to solve operands and context changes.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.resolvePendingBackfills(AssemblyResolutionResults)`:
    /// binds [`INST_NEXT`] (and, per the Java comment, `INST_NEXT2` -- not really supported) in
    /// [`vals_mut`](Self::vals_mut) from each entry's instruction length, retries
    /// `AssemblyResolvedPatterns.backfill` on every entry that still has pending backfills, then
    /// replaces any entry that *still* has pending backfills with an "incomplete solution" error.
    /// Left as a required method: it needs `AssemblyResolvedPatterns.hasBackfills`/`.backfill`,
    /// not yet modeled on this trait's minimal
    /// [`AssemblyResolvedPatterns`](crate::app::seam_stubs::AssemblyResolvedPatterns) placeholder.
    fn resolve_pending_backfills(
        &mut self,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Filter out results whose context does not match that requested.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.selectContext(AssemblyResolutionResults)`:
    /// combines each entry with a context-only resolution built from [`context`](Self::context),
    /// replacing entries that fail to combine with an "incompatible context" error. Left as a
    /// required method: it needs `AbstractAssemblyResolutionFactory.contextOnly` and
    /// `AssemblyResolvedPatterns.combine`, neither modeled on this trait's minimal placeholders.
    fn select_context(
        &self,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Filter out results that would certainly be disassembled differently than assembled.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.filterForbidden(AssemblyResolutionResults)`:
    /// replaces each entry with the result of `AssemblyResolvedPatterns.checkNotForbidden()`. Left
    /// as a required method: that check isn't modeled on this trait's minimal
    /// `AssemblyResolvedPatterns` placeholder.
    fn filter_forbidden(
        &self,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Filter out results that get disassembled differently than assembled.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.filterByDisassembly(AssemblyResolutionResults)`:
    /// as a final fail-safe (the "forbids" mechanism isn't perfect), disassembles each entry's
    /// instruction bytes via [`lang`](Self::lang) under an `AssemblyDefaultContext` seeded from
    /// [`context`](Self::context), and replaces the entry with an error if the resulting
    /// prototype's root state isn't equivalent to the entry's own, or if disassembly fails
    /// outright. Left as a required method: it needs `SleighLanguage.parse` (a full
    /// disassembly pass) plus `AssemblyDefaultContext`/`ByteMemBufferImpl`/
    /// `SleighInstructionPrototype`/`AssemblyResolvedPatterns.equivalentConstructState`, none
    /// ported yet.
    fn filter_by_disassembly(
        &self,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Get the state generator for a given operand and parse tree node.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.getStateGenerator(OperandSymbol,
    /// AssemblyParseTreeNode, AssemblyResolvedPatterns)`: dispatches on `node`'s concrete type
    /// (hidden node, numeric token, branch, or plain token taking an operand index) to construct
    /// the matching `Abstract­AssemblyStateGenerator` subclass. `node` mirrors Java's nullable
    /// parameter as `None`, meaning a hidden operand. Left as a required method: the four
    /// generator subclasses it dispatches to are exactly the other half of the dependency cycle
    /// this trait was cut to break, and aren't ported yet (see this trait's own doc comment).
    fn get_state_generator(
        &self,
        op_sym: &dyn OperandSymbol,
        node: Option<&dyn AssemblyParseTreeNode>,
        from_left: &dyn AssemblyResolvedPatterns,
    ) -> Box<dyn AbstractAssemblyStateGenerator>;

    /// Get the state generator for a hidden operand.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.getHiddenStateGenerator(OperandSymbol,
    /// AssemblyResolvedPatterns)`: if the operand's defining symbol is a subtable, constructs an
    /// `AssemblyHiddenConstructStateGenerator`; otherwise, an `AssemblyNopStateGenerator`. Left as
    /// a required method for the same reason as [`get_state_generator`](Self::get_state_generator).
    fn get_hidden_state_generator(
        &self,
        op_sym: &dyn OperandSymbol,
        from_left: &dyn AssemblyResolvedPatterns,
    ) -> Box<dyn AbstractAssemblyStateGenerator>;

    /// Apply a constructor pattern.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.resolvePatterns(AssemblyConstructorSemantic,
    /// int, AssemblyResolutionResults)`: pipes `fromChildren` through
    /// [`apply_mutations`](Self::apply_mutations), [`apply_patterns`](Self::apply_patterns), then
    /// [`try_resolve_backfills`](Self::try_resolve_backfills). Per the Java class's own `TODO`,
    /// this is currently used only for resolving recursion (`AssemblyConstructState.resolve` has
    /// its own, newer equivalent). Left as a required method since each of the three steps it
    /// composes is itself required.
    fn resolve_patterns(
        &self,
        sem: &dyn AssemblyConstructorSemantic,
        shift: i32,
        from_children: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Apply a constructor's context-changing operations to a set of results.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.applyMutations(AssemblyConstructorSemantic,
    /// AssemblyResolutionResults)`: replaces each entry first with
    /// `sem.solveContextChanges(rp, vals)`, then with `rp.solveContextChangesForForbids(sem,
    /// vals)`. Left as a required method: `AssemblyConstructorSemantic.solveContextChanges` is a
    /// deeply recursive algorithm over `ContextChange`/`ContextOp`/`MaskedLong` and the resolution
    /// factory's own `solveOrBackfill`, none of which are ported yet.
    fn apply_mutations(
        &self,
        sem: &dyn AssemblyConstructorSemantic,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Apply a constructor's fixed patterns to a set of results.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.applyPatterns(AssemblyConstructorSemantic,
    /// int, AssemblyResolutionResults)`: shifts each of `sem`'s patterns by `shift`, then applies
    /// them to every entry via an `AssemblyResolutionResults.Applicator` that combines-in the
    /// shifted patterns (without inserting a sibling, since this is typically applied by a parent)
    /// and finishes each result with `checkNotForbidden()`. Left as a required method: the
    /// `Applicator` callback interface isn't modeled on this trait's minimal
    /// `AssemblyResolutionResults` placeholder.
    fn apply_patterns(
        &self,
        sem: &dyn AssemblyConstructorSemantic,
        shift: i32,
        temp: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Apply constructors as indicated by a path returned by the context resolution graph.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.applyRecursionPath(Deque<AssemblyConstructorSemantic>,
    /// AssemblyParseBranch, AssemblyProduction, AssemblyResolution)`: starting from `child`,
    /// repeatedly pops the last constructor semantic off `path`, shifts the accumulated results by
    /// its operand's relative offset (computed via [`compute_offset`](Self::compute_offset) in
    /// spirit, though Java inlines just the single-operand, non-offset-based case here and asserts
    /// on the offset-based one), wraps them as a child (via [`parent`](Self::parent)) describing
    /// the constructor's source location, and feeds them through
    /// [`resolve_patterns`](Self::resolve_patterns). `path` mirrors Java's `Deque`, emptied by the
    /// same `pollLast`-driven traversal. Left as a required method since it composes
    /// [`resolve_patterns`](Self::resolve_patterns), itself required.
    fn apply_recursion_path(
        &self,
        path: &mut VecDeque<Arc<dyn AssemblyConstructorSemantic>>,
        branch: &dyn AssemblyParseBranch,
        rec: &dyn AssemblyProduction,
        child: Box<dyn AssemblyResolution>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Wrap this resolution as a child, pushing right-siblings down, for every entry in `temp`.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.parent(String, AssemblyResolutionResults, int)`:
    /// `temp.stream().map(r -> r.parent(description, opCount)).collect(...)`. Unlike its sibling
    /// helper methods, this one needs nothing beyond [`factory`](Self::factory) (to build the
    /// result set) and the already-ported [`AssemblyResolution::parent`], so it's a real default
    /// method here.
    fn parent(
        &self,
        description: &str,
        temp: Box<dyn AssemblyResolutionResults>,
        op_count: i32,
    ) -> Box<dyn AssemblyResolutionResults> {
        let mut result = self.factory().new_assembly_resolution_results();
        for r in temp.iter_all() {
            result.add(r.parent(description, op_count));
        }
        result
    }

    /// Attempt to resolve any pending backfills in `results`, retrying until no more progress is
    /// made.
    ///
    /// Mirrors the protected `AbstractAssemblyTreeResolver.tryResolveBackfills(AssemblyResolutionResults)`:
    /// for each non-error entry, repeatedly calls `AssemblyResolvedPatterns.backfill` until either
    /// no backfills remain (success), the attempt errors or is still a backfill (failure), or no
    /// progress is made (also failure, to avoid looping forever). Per the Java class's own `TODO`,
    /// this seems to be missing from a refactor that introduced `AssemblyConstructState`'s
    /// equivalent. Left as a required method for the same reason as
    /// [`resolve_pending_backfills`](Self::resolve_pending_backfills): it needs
    /// `AssemblyResolvedPatterns.hasBackfills`/`.backfill`.
    fn try_resolve_backfills(
        &self,
        results: Box<dyn AssemblyResolutionResults>,
    ) -> Box<dyn AssemblyResolutionResults>;

    /// Compute the offset of an operand encoded in the instruction block.
    ///
    /// Mirrors the public static `AbstractAssemblyTreeResolver.computeOffset(OperandSymbol,
    /// Constructor)`: the operand's own relative offset, plus (if it's defined relative to a base
    /// operand within the same constructor, i.e. `getOffsetBase() != -1`) that base operand's
    /// minimum length and its own recursively-computed offset. A default method rather than a
    /// required one: unlike this trait's other helpers, it needs nothing beyond
    /// [`OperandSymbol`](crate::app::seam_stubs::OperandSymbol) and
    /// [`Constructor::operand`](crate::app::seam_stubs::Constructor::operand), both minimal
    /// placeholders defined for exactly this purpose. `where Self: Sized` keeps this
    /// non-`&self` method from breaking this trait's object safety (it's simply excluded from the
    /// vtable, as it takes no receiver of any kind).
    fn compute_offset(opsym: &dyn OperandSymbol, cons: &dyn Constructor) -> i32
    where
        Self: Sized,
    {
        let mut offset = opsym.relative_offset();
        let base_idx = opsym.offset_base();
        if base_idx != -1 {
            let base_op = cons.operand(base_idx);
            offset += base_op.minimum_length();
            offset += Self::compute_offset(base_op.as_ref(), cons);
        }
        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::seam_stubs::{AssemblyNonTerminal, AssemblyResolutionEntry};
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::pcode::PackedDecode;
    use std::cmp::Ordering;

    /// Builds a minimal but real `SleighLanguage`, by feeding a hand-assembled packed-binary
    /// `<sleigh>` document (identical to the one `program::model::lang::sleigh::mod`'s own
    /// `test_sleigh_decode_basic` decodes) through the crate's real `PackedDecode`, rather than
    /// hand-rolling a mock -- `SleighLanguage`'s fields are private outside its module, so a
    /// literal construction isn't available here.
    fn test_language() -> SleighLanguage {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh ...>
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version="4"
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian="false"
        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>
        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]); // </space>
        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>
        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(0x1000)
    }

    // --- AssemblyResolution mock, real enough to exercise `parent`'s default body ---

    #[derive(Clone, Debug)]
    struct MockRes {
        desc: String,
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
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockRes { desc: format!("{description}[{op_count}]<-{}", self.desc) })
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    // --- AssemblyResolutionResults / AbstractAssemblyResolutionFactory mocks ---

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

    struct MockFactory;

    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn AssemblyResolutionResults> {
            Box::new(MockResults::default())
        }
    }

    // --- Grammar/production/branch mocks, real enough to exercise `get_root_recursion` ---

    struct MockNonTerminal(&'static str);

    impl std::fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockProduction {
        lhs: Arc<dyn AssemblyNonTerminal>,
    }

    impl AbstractAssemblyProduction for MockProduction {
        fn index(&self) -> i32 {
            0
        }
        fn set_index(&mut self, _idx: i32) {}
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl AssemblyProduction for MockProduction {}

    struct MockBranch {
        production: Arc<dyn AssemblyProduction>,
    }

    impl AssemblyParseBranch for MockBranch {
        fn get_production(&self) -> Arc<dyn AssemblyProduction> {
            self.production.clone()
        }
        fn get_substitutions(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>> {
            Vec::new()
        }
        fn prepend_child(&mut self, _child: Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>) {}
    }

    /// A grammar whose `get_pure_recursion` only matches a single, fixed non-terminal name --
    /// enough to exercise `get_root_recursion`'s real "found"/"not found" behavior without needing
    /// the rest of `AssemblyGrammar`'s surface (never called by these tests).
    struct MockGrammar {
        recursive_lhs_name: &'static str,
        recursive: Arc<dyn AssemblyProduction>,
    }

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn AssemblyProduction>) {
            unimplemented!("not exercised by these tests")
        }
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn Constructor>,
            _indices: Vec<usize>,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn get_semantics(
            &self,
            _prod: &dyn AssemblyProduction,
        ) -> Vec<Arc<dyn AssemblyConstructorSemantic>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_semantic(
            &self,
            _cons: &dyn Constructor,
        ) -> Option<Arc<dyn AssemblyConstructorSemantic>> {
            unimplemented!("not exercised by these tests")
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {
            unimplemented!("not exercised by these tests")
        }
        fn get_pure_recursive(&self) -> Vec<Arc<dyn AssemblyProduction>> {
            vec![self.recursive.clone()]
        }
        fn get_pure_recursion(
            &self,
            lhs: &dyn AssemblyNonTerminal,
        ) -> Option<Arc<dyn AssemblyProduction>> {
            if lhs.get_name() == self.recursive_lhs_name {
                Some(self.recursive.clone())
            } else {
                None
            }
        }
    }

    // --- OperandSymbol / Constructor mocks, exercising `compute_offset` ---

    struct MockOperand {
        offset_base: i32,
        relative_offset: i32,
        minimum_length: i32,
    }

    impl OperandSymbol for MockOperand {
        fn offset_base(&self) -> i32 {
            self.offset_base
        }
        fn relative_offset(&self) -> i32 {
            self.relative_offset
        }
        fn minimum_length(&self) -> i32 {
            self.minimum_length
        }
    }

    struct MockConstructor {
        operands: Vec<Arc<dyn OperandSymbol>>,
    }

    impl Constructor for MockConstructor {
        fn operand(&self, index: i32) -> Arc<dyn OperandSymbol> {
            self.operands[index as usize].clone()
        }
    }

    // --- AbstractAssemblyStateGenerator mock ---

    struct MockStateGenerator;
    impl AbstractAssemblyStateGenerator for MockStateGenerator {}

    // --- The resolver mock itself, implementing every hook plus the required (bodyless) methods
    // with trivial pass-through bodies, proving object-safety and letting the default methods
    // under test run against real, non-trivial collaborator behavior. ---

    struct MockResolver {
        factory: Arc<dyn AbstractAssemblyResolutionFactory>,
        lang: SleighLanguage,
        at: Address,
        tree: Arc<dyn AssemblyParseBranch>,
        grammar: Arc<dyn AssemblyGrammar>,
        context: Arc<dyn AssemblyPatternBlock>,
        ctx_graph: Arc<dyn AssemblyContextGraph>,
        vals: HashMap<String, i64>,
    }

    struct MockContextGraph;
    impl AssemblyContextGraph for MockContextGraph {}

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

    impl MockResolver {
        fn new(recursive_lhs_name: &'static str, tree_lhs_name: &'static str) -> Self {
            let recursive = Arc::new(MockProduction { lhs: Arc::new(MockNonTerminal(recursive_lhs_name)) });
            let tree_prod: Arc<dyn AssemblyProduction> =
                Arc::new(MockProduction { lhs: Arc::new(MockNonTerminal(tree_lhs_name)) });
            let mut vals = HashMap::new();
            let at = test_address();
            vals.insert(INST_START.to_string(), at.addressable_word_offset());
            MockResolver {
                factory: Arc::new(MockFactory),
                lang: test_language(),
                at,
                tree: Arc::new(MockBranch { production: tree_prod }),
                grammar: Arc::new(MockGrammar { recursive_lhs_name, recursive }),
                context: Arc::new(MockPatternBlock),
                ctx_graph: Arc::new(MockContextGraph),
                vals,
            }
        }
    }

    impl AbstractAssemblyTreeResolver for MockResolver {
        fn factory(&self) -> Arc<dyn AbstractAssemblyResolutionFactory> {
            self.factory.clone()
        }
        fn lang(&self) -> &SleighLanguage {
            &self.lang
        }
        fn at(&self) -> Address {
            self.at.clone()
        }
        fn tree(&self) -> Arc<dyn AssemblyParseBranch> {
            self.tree.clone()
        }
        fn grammar(&self) -> Arc<dyn AssemblyGrammar> {
            self.grammar.clone()
        }
        fn context(&self) -> Arc<dyn AssemblyPatternBlock> {
            self.context.clone()
        }
        fn ctx_graph(&self) -> Arc<dyn AssemblyContextGraph> {
            self.ctx_graph.clone()
        }
        fn vals(&self) -> &HashMap<String, i64> {
            &self.vals
        }
        fn vals_mut(&mut self) -> &mut HashMap<String, i64> {
            &mut self.vals
        }

        fn resolve(&mut self) -> Box<dyn AssemblyResolutionResults> {
            self.factory().new_assembly_resolution_results()
        }
        fn resolve_root_recursion(
            &self,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn resolve_pending_backfills(
            &mut self,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn select_context(
            &self,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn filter_forbidden(
            &self,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn filter_by_disassembly(
            &self,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn get_state_generator(
            &self,
            _op_sym: &dyn OperandSymbol,
            _node: Option<&dyn AssemblyParseTreeNode>,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AbstractAssemblyStateGenerator> {
            Box::new(MockStateGenerator)
        }
        fn get_hidden_state_generator(
            &self,
            _op_sym: &dyn OperandSymbol,
            _from_left: &dyn AssemblyResolvedPatterns,
        ) -> Box<dyn AbstractAssemblyStateGenerator> {
            Box::new(MockStateGenerator)
        }
        fn resolve_patterns(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _shift: i32,
            from_children: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            from_children
        }
        fn apply_mutations(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn apply_patterns(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _shift: i32,
            temp: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            temp
        }
        fn apply_recursion_path(
            &self,
            _path: &mut VecDeque<Arc<dyn AssemblyConstructorSemantic>>,
            _branch: &dyn AssemblyParseBranch,
            _rec: &dyn AssemblyProduction,
            child: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolutionResults> {
            let mut results = self.factory().new_assembly_resolution_results();
            results.add(child);
            results
        }
        fn try_resolve_backfills(
            &self,
            results: Box<dyn AssemblyResolutionResults>,
        ) -> Box<dyn AssemblyResolutionResults> {
            results
        }
    }

    #[test]
    fn get_factory_and_get_grammar_delegate_to_hooks() {
        let resolver = MockResolver::new("insn", "insn");
        assert!(Arc::ptr_eq(&resolver.get_factory(), &resolver.factory()));
        assert!(Arc::ptr_eq(&resolver.get_grammar(), &resolver.grammar()));
    }

    #[test]
    fn get_root_recursion_finds_matching_pure_recursive_production() {
        let resolver = MockResolver::new("insn", "insn");
        let rec = resolver.get_root_recursion();
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().lhs().get_name(), "insn");
    }

    #[test]
    fn get_root_recursion_none_when_lhs_does_not_match() {
        let resolver = MockResolver::new("other_table", "insn");
        assert!(resolver.get_root_recursion().is_none());
    }

    #[test]
    fn compute_offset_is_relative_offset_when_absolute() {
        let base = MockOperand { offset_base: -1, relative_offset: 5, minimum_length: 2 };
        let cons = MockConstructor { operands: vec![] };
        assert_eq!(MockResolver::compute_offset(&base, &cons), 5);
    }

    #[test]
    fn compute_offset_chains_through_base_operand() {
        let base: Arc<dyn OperandSymbol> =
            Arc::new(MockOperand { offset_base: -1, relative_offset: 4, minimum_length: 2 });
        let dependent = MockOperand { offset_base: 0, relative_offset: 1, minimum_length: 0 };
        let cons = MockConstructor { operands: vec![base] };

        // dependent.relative_offset (1) + base.minimum_length (2) + compute_offset(base) (4) == 7
        assert_eq!(MockResolver::compute_offset(&dependent, &cons), 7);
    }

    #[test]
    fn parent_wraps_every_entry_with_description_and_op_count() {
        let resolver = MockResolver::new("insn", "insn");
        let mut temp = MockResults::default();
        temp.add(Box::new(MockRes { desc: "child0".to_string() }));
        temp.add(Box::new(MockRes { desc: "child1".to_string() }));

        let wrapped = resolver.parent("Resolving recursive constructor", Box::new(temp), 1);
        let mut descs: Vec<String> =
            wrapped.iter_all().iter().map(|r| r.get_description()).collect();
        descs.sort();

        assert_eq!(
            descs,
            vec![
                "Resolving recursive constructor[1]<-child0".to_string(),
                "Resolving recursive constructor[1]<-child1".to_string(),
            ]
        );
    }

    #[test]
    fn parent_on_empty_results_yields_empty_results() {
        let resolver = MockResolver::new("insn", "insn");
        let wrapped = resolver.parent("x", Box::new(MockResults::default()), 0);
        assert!(wrapped.iter_all().is_empty());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut resolver = MockResolver::new("insn", "insn");
        let as_dyn: &mut dyn AbstractAssemblyTreeResolver = &mut resolver;
        assert!(as_dyn.get_root_recursion().is_some());
        let results = as_dyn.resolve();
        assert!(results.iter_all().is_empty());
    }
}
