//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults`.

use std::cmp::Ordering;
use std::rc::Rc;

use super::{AbstractAssemblyResolutionFactory, AssemblyResolution, AssemblyResolvedBackfill, AssemblyResolvedPatterns};

/// Mirrors the nested `AssemblyResolutionResults.Applicator` interface.
///
/// Used by [`AssemblyResolutionResults::apply`] to combine each already-resolved pattern in a
/// results set with a further candidate resolution (e.g. the next operand's encoding), producing
/// a new results set.
///
/// Every `Box<dyn AssemblyResolution>`-typed `cur` parameter below mirrors Java's `cur` local,
/// which is really always an `AssemblyResolvedPatterns` in disguise (checked by the caller before
/// dispatch) -- narrowed via [`AssemblyResolution::as_resolved_patterns`], which panics if that
/// invariant is ever violated, mirroring Java's `ClassCastException` on a bad unchecked cast.
pub trait Applicator {
    /// Get the candidate resolutions (of the next operand, say) to combine with `cur`.
    ///
    /// Mirrors `Applicator.getPatterns(AssemblyResolvedPatterns)`. Java's `Iterable<? extends
    /// AssemblyResolution>` becomes an owned `Vec`, matching this crate's usual collection
    /// convention for this trait family (e.g. [`AssemblyResolutionResults::get_resolutions`]).
    fn get_patterns(&self, cur: &dyn AssemblyResolvedPatterns) -> Vec<Box<dyn AssemblyResolution>>;

    /// Attach `from`'s description to `res`.
    ///
    /// Mirrors the default `Applicator.setDescription(AssemblyResolvedPatterns,
    /// AssemblyResolution)`.
    fn set_description(
        &self,
        res: Box<dyn AssemblyResolvedPatterns>,
        from: &dyn AssemblyResolution,
    ) -> Box<dyn AssemblyResolvedPatterns> {
        res.with_description(&from.get_description())
    }

    /// Attach `cur` as `res`'s right sibling.
    ///
    /// Mirrors the default `Applicator.setRight(AssemblyResolvedPatterns,
    /// AssemblyResolvedPatterns)`; Java's second parameter type is narrowed to
    /// `AssemblyResolvedPatterns` there only because its one caller always has one in hand, so
    /// this keeps the wider `Box<dyn AssemblyResolution>` that
    /// [`AssemblyResolvedPatterns::with_right_patterns`] itself already accepts.
    fn set_right(
        &self,
        res: Box<dyn AssemblyResolvedPatterns>,
        cur: Box<dyn AssemblyResolution>,
    ) -> Box<dyn AssemblyResolvedPatterns> {
        res.with_right_patterns(cur)
    }

    /// Combine `cur` with another, already-resolved pattern `pat`.
    ///
    /// Returns `None` on failure, mirroring Java's nullable return.
    ///
    /// Mirrors the default `Applicator.combineConstructor(AssemblyResolvedPatterns,
    /// AssemblyResolvedPatterns)`.
    fn combine_constructor(
        &self,
        cur: Box<dyn AssemblyResolution>,
        pat: &dyn AssemblyResolvedPatterns,
    ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
        let combined = {
            let cur_rp = cur.as_resolved_patterns().expect(
                "Applicator::combine_constructor's `cur` must be AssemblyResolvedPatterns \
                 (mirrors Java's unchecked cast)",
            );
            cur_rp.combine(pat)?
        };
        Some(self.set_right(self.set_description(combined, pat), cur))
    }

    /// Combine `cur` with a pending backfill record `bf`.
    ///
    /// Mirrors the default `Applicator.combineBackfill(AssemblyResolvedPatterns,
    /// AssemblyResolvedBackfill)`.
    fn combine_backfill(
        &self,
        cur: Box<dyn AssemblyResolution>,
        bf: &dyn AssemblyResolvedBackfill,
    ) -> Box<dyn AssemblyResolvedPatterns> {
        let combined = {
            let cur_rp = cur.as_resolved_patterns().expect(
                "Applicator::combine_backfill's `cur` must be AssemblyResolvedPatterns (mirrors \
                 Java's unchecked cast)",
            );
            cur_rp.combine_backfill(bf)
        };
        self.set_right(self.set_description(combined, bf), cur)
    }

    /// Combine `cur` with an arbitrary further resolution `pat`, dispatching to
    /// [`combine_backfill`](Self::combine_backfill) or [`combine_constructor`](Self::combine_constructor)
    /// depending on `pat`'s concrete kind.
    ///
    /// Mirrors the default `Applicator.combine(AssemblyResolvedPatterns, AssemblyResolution)`,
    /// including its `pat.isError()` guard, which Java enforces by throwing `AssertionError` --
    /// reproduced here as a panic, since `pat` being an error at this call site is never expected
    /// to happen in practice (callers are expected to have already filtered errors out).
    fn combine(
        &self,
        cur: Box<dyn AssemblyResolution>,
        pat: &dyn AssemblyResolution,
    ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
        assert!(!pat.is_error(), "Applicator::combine called with an error resolution");
        if pat.is_backfill() {
            let bf = pat
                .as_backfill()
                .expect("is_backfill() true but as_backfill() returned None");
            return Some(self.combine_backfill(cur, bf));
        }
        let rp = pat.as_resolved_patterns().expect(
            "a resolution that is neither an error nor a backfill must be AssemblyResolvedPatterns",
        );
        self.combine_constructor(cur, rp)
    }

    /// Describe why combining `rc` with `pat` failed, for use in an error record.
    ///
    /// Mirrors the abstract `Applicator.describeError(AssemblyResolvedPatterns,
    /// AssemblyResolution)`.
    fn describe_error(&self, rc: &dyn AssemblyResolvedPatterns, pat: &dyn AssemblyResolution) -> String;

    /// Post-process a successfully combined result before it's added to the output set.
    ///
    /// Mirrors the default `Applicator.finish(AssemblyResolvedPatterns)`, which is simply the
    /// identity function.
    fn finish(&self, resolved: Box<dyn AssemblyResolvedPatterns>) -> Box<dyn AssemblyResolution> {
        resolved
    }
}

/// A set of possible assembly resolutions for a single SLEIGH constructor.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults`. Since the assembler
/// works from the leaves up, it's unclear in what context a given token appears. Thus, every
/// possible encoding is collected and passed upward. As resolution continues, many of the
/// possible encodings are pruned out. When the resolver reaches the root, we end up with every
/// possible encoding (less some prefixes) of an instruction. This object stores the possible
/// encodings, including error records describing the pruned intermediate results.
///
/// Java extends `AbstractSetDecorator<AssemblyResolution>` (a `java.util.Set`, backed by a
/// `LinkedHashSet` for insertion-ordered de-duplication via `equals()`/`hashCode()`). Composition
/// over inheritance: this struct wraps a plain `Vec<Box<dyn AssemblyResolution>>` instead, since
/// there's no Rust `Set` trait to extend and `AssemblyResolution` doesn't require `Eq`/`Hash` (no
/// concrete implementor needs it elsewhere). [`add`](Self::add) still gives real, insertion-order
/// set semantics -- just using [`AssemblyResolution::compare_to`] (`Ordering::Equal`) as the
/// equality test in place of `equals()`, since `compare_to` is the one already-required,
/// already-universal notion of "sameness" available on every implementor. This is a documented
/// approximation, not a bug: Java's own `AbstractAssemblyResolution.compareTo` is `// LAZY`
/// toString-comparison (see [`DefaultAssemblyResolvedError`](super::DefaultAssemblyResolvedError)'s
/// tests), so it can already disagree with a type's own `equals()` in the original too -- this
/// port just leans on that same lazily-consistent ordering directly, everywhere, rather than
/// introducing a second, `Eq`/`Hash`-based notion of equality this crate's `AssemblyResolution`
/// trait doesn't support.
///
/// The public no-arg constructor becomes [`AssemblyResolutionResults::new`]; the `protected`
/// `Set`-taking one (used internally by `AbstractAssemblyResolutionFactory.results`/`singleton`)
/// isn't ported, since those factory methods already have real default bodies here built directly
/// on [`add`](Self::add) (see [`AbstractAssemblyResolutionFactory::results`](
/// super::AbstractAssemblyResolutionFactory::results)).
///
/// [`absorb`](Self::absorb) takes `that` by value (rather than by reference, as Java's
/// `absorb(AssemblyResolutionResults)` does): every real call site
/// (`AbstractAssemblyTreeResolver.applyRecursionPath`/`AbstractSleighAssembler.resolveTree`, per
/// the Java source) passes a fresh, immediately-discarded result, so consuming it loses no real
/// behavior while sidestepping the need to duplicate un-`Clone`-able `AssemblyResolution` trait
/// objects to keep `that` usable afterward.
///
/// [`apply`](Self::apply) similarly takes `self` by value for the same reason (every real call
/// site reassigns or chains off its own return value rather than reusing the receiver), which
/// lets its inner loop move each stored resolution forward instead of needing to duplicate it --
/// except where one resolution needs to be handed to *more than one* downstream call (mirroring
/// Java's free reference sharing), where it's temporarily lifted into an
/// `Rc<dyn AssemblyResolution>` and re-boxed per use via [`AssemblyResolution`]'s blanket
/// `impl for Rc<dyn AssemblyResolution>` (see that trait's own doc comment).
#[derive(Debug, Default)]
pub struct AssemblyResolutionResults {
    resolutions: Vec<Box<dyn AssemblyResolution>>,
}

impl AssemblyResolutionResults {
    /// Construct a new (mutable) empty set of resolutions.
    ///
    /// Mirrors `AssemblyResolutionResults()`.
    pub fn new() -> Self {
        Self { resolutions: Vec::new() }
    }

    /// Add a resolution to this set, if an equal one (per [`AssemblyResolution::compare_to`]) is
    /// not already present.
    ///
    /// Returns `true` if the set changed, mirroring `Set.add`'s (and hence
    /// `AssemblyResolutionResults.add(AssemblyResolution)`'s) return value.
    pub fn add(&mut self, ar: Box<dyn AssemblyResolution>) -> bool {
        let already_present = self
            .resolutions
            .iter()
            .any(|existing| existing.compare_to(ar.as_ref()) == Ordering::Equal);
        if already_present {
            return false;
        }
        self.resolutions.push(ar);
        true
    }

    /// Absorb every resolution from `that` into this set.
    ///
    /// A synonym for [`add_all`](Self::add_all) that accepts only another resolution set, mirroring
    /// `absorb(AssemblyResolutionResults)`. See this struct's own doc comment for why `that` is
    /// taken by value here rather than by reference as in Java.
    pub fn absorb(&mut self, that: AssemblyResolutionResults) {
        for ar in that.resolutions {
            self.add(ar);
        }
    }

    /// Add every resolution in `c` to this set.
    ///
    /// Mirrors `AssemblyResolutionResults.addAll(Collection<? extends AssemblyResolution>)`,
    /// returning `true` if any were actually added.
    pub fn add_all(&mut self, c: Vec<Box<dyn AssemblyResolution>>) -> bool {
        let mut changed = false;
        for ar in c {
            if self.add(ar) {
                changed = true;
            }
        }
        changed
    }

    /// Get a read-only view of this set's contents, in insertion order.
    ///
    /// Mirrors `AssemblyResolutionResults.getResolutions()`'s `Collections.unmodifiableSet` view
    /// (a `Vec`/slice here, in place of a `Set`, per this struct's own doc comment).
    pub fn get_resolutions(&self) -> &[Box<dyn AssemblyResolution>] {
        &self.resolutions
    }

    /// Remove the first resolution equal (per [`AssemblyResolution::compare_to`]) to `ar`, if any.
    ///
    /// Returns `true` if a matching resolution was found and removed, mirroring
    /// `AssemblyResolutionResults.remove(AssemblyResolution)`'s `Set.remove` return value.
    pub fn remove(&mut self, ar: &dyn AssemblyResolution) -> bool {
        if let Some(index) =
            self.resolutions.iter().position(|existing| existing.compare_to(ar) == Ordering::Equal)
        {
            self.resolutions.remove(index);
            true
        } else {
            false
        }
    }

    /// The number of resolutions currently in this set.
    pub fn len(&self) -> usize {
        self.resolutions.len()
    }

    /// Returns `true` if this set has no resolutions.
    pub fn is_empty(&self) -> bool {
        self.resolutions.is_empty()
    }

    /// Iterate over this set's resolutions, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Box<dyn AssemblyResolution>> {
        self.resolutions.iter()
    }

    /// Combine every non-error resolution in this set with each of `applicator`'s candidate
    /// patterns, folding failures into error records via `factory`.
    ///
    /// Mirrors the protected `AssemblyResolutionResults.apply(AbstractAssemblyResolutionFactory<?,
    /// ?>, Applicator)`. See this struct's own doc comment for why `self` is consumed and why
    /// results are collected into a locally-constructed [`AssemblyResolutionResults`] rather than
    /// through `factory.newAssemblyResolutionResults()` as in Java (which, for this concrete
    /// type, could only ever build another instance of this very struct anyway).
    pub fn apply(
        self,
        factory: &dyn AbstractAssemblyResolutionFactory,
        applicator: &dyn Applicator,
    ) -> AssemblyResolutionResults {
        let mut results = AssemblyResolutionResults::new();
        for res in self.resolutions {
            if res.is_error() {
                results.add(res);
                continue;
            }
            let cur_rc: Rc<dyn AssemblyResolution> = Rc::from(res);
            let candidates = {
                let rp = cur_rc.as_resolved_patterns().expect(
                    "a non-error resolution in an AssemblyResolutionResults being `apply`-ed must \
                     be AssemblyResolvedPatterns (mirrors Java's unchecked cast in apply())",
                );
                applicator.get_patterns(rp)
            };
            for ar in candidates {
                let cur_handle: Box<dyn AssemblyResolution> = Box::new(cur_rc.clone());
                match applicator.combine(cur_handle, ar.as_ref()) {
                    None => {
                        let rp = cur_rc.as_resolved_patterns().expect("checked above");
                        let message = applicator.describe_error(rp, ar.as_ref());
                        results.add(factory.error(&message, ar.as_ref()));
                    }
                    Some(combined) => {
                        results.add(applicator.finish(combined));
                    }
                }
            }
        }
        results
    }

    /// Map every resolved-pattern entry in this set through `function`, passing errors through
    /// unchanged.
    ///
    /// Mirrors the protected `AssemblyResolutionResults.apply(AbstractAssemblyResolutionFactory<?,
    /// ?>, Function<AssemblyResolvedPatterns, AssemblyResolution>)`. Named distinctly from
    /// [`apply`](Self::apply), since Rust has no method overloading and Java overloads `apply` on
    /// its second parameter's type. `factory` is accepted (matching the Java signature) but
    /// unused, for the same reason described on [`apply`](Self::apply)'s own doc comment.
    pub fn apply_fn<F>(self, factory: &dyn AbstractAssemblyResolutionFactory, function: F) -> AssemblyResolutionResults
    where
        F: Fn(&dyn AssemblyResolvedPatterns) -> Box<dyn AssemblyResolution>,
    {
        let _ = factory;
        let mut results = AssemblyResolutionResults::new();
        for res in self.resolutions {
            let mapped: Box<dyn AssemblyResolution> = if res.is_backfill() {
                panic!(
                    "AssemblyResolutionResults::apply_fn encountered a still-pending backfill \
                     (mirrors Java's AssertionError)"
                );
            } else if res.is_error() {
                res
            } else if let Some(rp) = res.as_resolved_patterns() {
                function(rp)
            } else {
                panic!(
                    "AssemblyResolutionResults::apply_fn encountered a resolution that is \
                     neither an error, a backfill, nor AssemblyResolvedPatterns (mirrors Java's \
                     AssertionError)"
                );
            };
            results.add(mapped);
        }
        results
    }
}

impl<'a> IntoIterator for &'a AssemblyResolutionResults {
    type Item = &'a Box<dyn AssemblyResolution>;
    type IntoIter = std::slice::Iter<'a, Box<dyn AssemblyResolution>>;

    fn into_iter(self) -> Self::IntoIter {
        self.resolutions.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::sem::DefaultAssemblyResolvedError;

    fn err(desc: &str, error: &str) -> Box<dyn AssemblyResolution> {
        Box::new(DefaultAssemblyResolvedError::leaf(desc, error))
    }

    // --- Set-container behavior ---

    #[test]
    fn new_set_is_empty() {
        let results = AssemblyResolutionResults::new();
        assert!(results.is_empty());
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn add_returns_true_for_new_entry_and_grows_the_set() {
        let mut results = AssemblyResolutionResults::new();
        assert!(results.add(err("d1", "e1")));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn add_returns_false_and_does_not_duplicate_an_equal_entry() {
        let mut results = AssemblyResolutionResults::new();
        assert!(results.add(err("same", "same")));
        assert!(!results.add(err("same", "same")));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn add_treats_differently_described_entries_as_distinct() {
        let mut results = AssemblyResolutionResults::new();
        assert!(results.add(err("d1", "e")));
        assert!(results.add(err("d2", "e")));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn get_resolutions_preserves_insertion_order() {
        let mut results = AssemblyResolutionResults::new();
        results.add(err("first", "e"));
        results.add(err("second", "e"));
        let descs: Vec<String> =
            results.get_resolutions().iter().map(|r| r.get_description()).collect();
        assert_eq!(descs, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn remove_deletes_a_matching_entry_and_reports_success() {
        let mut results = AssemblyResolutionResults::new();
        results.add(err("d", "e"));
        let needle = DefaultAssemblyResolvedError::leaf("d", "e");
        assert!(results.remove(&needle));
        assert!(results.is_empty());
    }

    #[test]
    fn remove_reports_failure_when_nothing_matches() {
        let mut results = AssemblyResolutionResults::new();
        results.add(err("d", "e"));
        let needle = DefaultAssemblyResolvedError::leaf("other", "other");
        assert!(!results.remove(&needle));
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn absorb_moves_every_entry_from_the_other_set() {
        let mut a = AssemblyResolutionResults::new();
        a.add(err("a1", "e"));
        let mut b = AssemblyResolutionResults::new();
        b.add(err("b1", "e"));
        b.add(err("b2", "e"));

        a.absorb(b);

        assert_eq!(a.len(), 3);
    }

    #[test]
    fn absorb_deduplicates_against_the_receiver() {
        let mut a = AssemblyResolutionResults::new();
        a.add(err("shared", "shared"));
        let mut b = AssemblyResolutionResults::new();
        b.add(err("shared", "shared"));
        b.add(err("unique", "unique"));

        a.absorb(b);

        assert_eq!(a.len(), 2);
    }

    #[test]
    fn add_all_reports_whether_anything_changed() {
        let mut results = AssemblyResolutionResults::new();
        assert!(results.add_all(vec![err("d1", "e"), err("d1", "e"), err("d2", "e")]));
        assert_eq!(results.len(), 2);
        assert!(!results.add_all(vec![err("d1", "e")]));
    }

    #[test]
    fn iter_and_into_iter_visit_every_entry() {
        let mut results = AssemblyResolutionResults::new();
        results.add(err("a", "e"));
        results.add(err("b", "e"));

        let via_iter: Vec<String> = results.iter().map(|r| r.get_description()).collect();
        let via_into_iter: Vec<String> = (&results).into_iter().map(|r| r.get_description()).collect();
        assert_eq!(via_iter, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(via_into_iter, via_iter);
    }

    // --- `Applicator`/`apply` behavior ---

    use crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver;
    use crate::app::seam_stubs::{AssemblyPatternBlock, Constructor, MaskedLong};
    use std::collections::HashMap;
    use std::sync::Arc;

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

    /// A minimal, real `AssemblyResolvedPatterns` implementor: just enough of `combine`/
    /// `with_description`/`with_right_patterns` to exercise `Applicator`'s default combine
    /// machinery end-to-end, following the "combine two descriptions with `+`" convention used by
    /// `abstract_assembly_resolution_factory.rs`'s own `MockPatterns`.
    #[derive(Clone, Debug)]
    struct MockPatterns {
        desc: String,
        right: Option<String>,
        fails_to_combine: bool,
    }

    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl MockPatterns {
        fn new(desc: &str) -> Self {
            Self { desc: desc.to_string(), right: None, fails_to_combine: false }
        }
        fn failing(desc: &str) -> Self {
            Self { desc: desc.to_string(), right: None, fails_to_combine: true }
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
            self.right.clone().map(|d| Box::new(MockPatterns::new(&d)) as Box<dyn AssemblyResolution>)
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
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockPatterns::new(description))
        }
        fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
        fn as_resolved_patterns(&self) -> Option<&dyn AssemblyResolvedPatterns> {
            Some(self)
        }
    }

    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockPatternBlock)
        }
        fn with_context(&self, _ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn get_instruction_length(&self) -> i32 {
            0
        }
        fn get_defined_instruction_length(&self) -> i32 {
            0
        }
        fn get_backfills(&self) -> Vec<Box<dyn AssemblyResolvedBackfill>> {
            unimplemented!("not exercised by these tests")
        }
        fn has_backfills(&self) -> bool {
            false
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
        fn with_description(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string(), ..self.clone() })
        }
        fn with_right_patterns(
            &self,
            right: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { right: Some(right.get_description()), ..self.clone() })
        }
        fn with_constructor(&self, _cons: Arc<dyn Constructor>) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn combine(
            &self,
            pat: &dyn AssemblyResolvedPatterns,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            if self.fails_to_combine {
                return None;
            }
            Some(Box::new(MockPatterns::new(&format!("{}+{}", self.desc, pat.get_description()))))
        }
        fn combine_backfill(&self, bf: &dyn AssemblyResolvedBackfill) -> Box<dyn AssemblyResolvedPatterns> {
            let _ = bf;
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

    /// A minimal, real `AbstractAssemblyResolutionFactory` implementor -- only `error()` is ever
    /// reached by these tests (via `apply`'s failure path), so every other method panics if
    /// reached, following the convention already established by
    /// `abstract_assembly_resolution_factory.rs`'s own `MockFactory`.
    struct MockFactory;
    impl AbstractAssemblyResolutionFactory for MockFactory {
        fn new_assembly_resolution_results(&self) -> Box<dyn crate::app::seam_stubs::AssemblyResolutionResults> {
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
        fn error(&self, error: &str, _res: &dyn AssemblyResolution) -> Box<dyn AssemblyResolution> {
            Box::new(DefaultAssemblyResolvedError::leaf("apply-error", error))
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
        fn instr_only(&self, _ins: Box<dyn AssemblyPatternBlock>, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            unimplemented!("not exercised by these tests")
        }
        fn context_only(&self, _ctx: Box<dyn AssemblyPatternBlock>, _description: &str) -> Box<dyn AssemblyResolvedPatterns> {
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

    /// An `Applicator` that offers one or more fixed candidate patterns per `cur`, tracking how
    /// many times `describe_error` was reached.
    struct FixedApplicator {
        candidates: Vec<String>,
        error_calls: std::cell::RefCell<u32>,
    }

    impl Applicator for FixedApplicator {
        fn get_patterns(&self, _cur: &dyn AssemblyResolvedPatterns) -> Vec<Box<dyn AssemblyResolution>> {
            self.candidates.iter().map(|d| Box::new(MockPatterns::new(d)) as Box<dyn AssemblyResolution>).collect()
        }
        fn describe_error(&self, _rc: &dyn AssemblyResolvedPatterns, pat: &dyn AssemblyResolution) -> String {
            *self.error_calls.borrow_mut() += 1;
            format!("failed to combine with {}", pat.get_description())
        }
    }

    fn applicator(candidates: &[&str]) -> FixedApplicator {
        FixedApplicator {
            candidates: candidates.iter().map(|s| s.to_string()).collect(),
            error_calls: std::cell::RefCell::new(0),
        }
    }

    #[test]
    fn apply_combines_a_single_candidate_and_attaches_it_as_right_sibling() {
        let mut results = AssemblyResolutionResults::new();
        results.add(Box::new(MockPatterns::new("base")));

        let factory = MockFactory;
        let app = applicator(&["op1"]);
        let out = results.apply(&factory, &app);

        assert_eq!(out.len(), 1);
        let combined = &out.get_resolutions()[0];
        // `Applicator::combine`'s default `setDescription` step (matching Java) overwrites the
        // combined description with the *candidate*'s, not the merged encoding's -- "op1" here,
        // not "base+op1". `cur` ("base") survives instead as the combined result's right sibling
        // via `setRight`, verified below via `get_right`.
        assert_eq!(combined.get_description(), "op1");
        let right = combined.get_right().expect("combine should attach `cur` as the right sibling");
        assert_eq!(right.get_description(), "base");
    }

    #[test]
    fn apply_combines_the_same_cur_with_multiple_candidates() {
        // Exercises the `Rc`-sharing path: `get_patterns` yields more than one candidate for the
        // same `cur`, mirroring Java's free reuse of the same `AssemblyResolvedPatterns`
        // reference across every iteration of the inner loop.
        let mut results = AssemblyResolutionResults::new();
        results.add(Box::new(MockPatterns::new("base")));

        let factory = MockFactory;
        let app = applicator(&["op1", "op2", "op3"]);
        let out = results.apply(&factory, &app);

        let mut descs: Vec<String> =
            out.get_resolutions().iter().map(|r| r.get_description()).collect();
        descs.sort();
        assert_eq!(descs, vec!["op1".to_string(), "op2".to_string(), "op3".to_string()]);
        // Every combined result shares the very same `cur` ("base") as its right sibling.
        for r in out.get_resolutions() {
            let right = r.get_right().expect("combine should attach `cur` as the right sibling");
            assert_eq!(right.get_description(), "base");
        }
    }

    #[test]
    fn apply_passes_error_entries_through_unchanged() {
        let mut results = AssemblyResolutionResults::new();
        results.add(err("bad", "already broken"));

        let factory = MockFactory;
        let app = applicator(&["op1"]);
        let out = results.apply(&factory, &app);

        assert_eq!(out.len(), 1);
        assert!(out.get_resolutions()[0].is_error());
        assert_eq!(out.get_resolutions()[0].get_description(), "bad");
    }

    #[test]
    fn apply_turns_a_combine_failure_into_a_factory_built_error_via_describe_error() {
        let mut results = AssemblyResolutionResults::new();
        results.add(Box::new(MockPatterns::failing("base")));

        let factory = MockFactory;
        let app = applicator(&["op1"]);
        let out = results.apply(&factory, &app);

        assert_eq!(out.len(), 1);
        let entry = &out.get_resolutions()[0];
        assert!(entry.is_error());
        assert_eq!(*app.error_calls.borrow(), 1);
    }

    #[test]
    fn apply_fn_maps_patterns_and_passes_errors_through() {
        let mut results = AssemblyResolutionResults::new();
        results.add(Box::new(MockPatterns::new("p1")));
        results.add(err("bad", "broken"));

        let factory = MockFactory;
        let out = results.apply_fn(&factory, |rp| Box::new(MockPatterns::new(&format!("mapped:{}", rp.get_description()))));

        let mut descs: Vec<String> = out.get_resolutions().iter().map(|r| r.get_description()).collect();
        descs.sort();
        assert_eq!(descs, vec!["bad".to_string(), "mapped:p1".to_string()]);
    }

    #[test]
    fn apply_fn_panics_on_a_still_pending_backfill_reproducing_java_assertion_error() {
        struct StubBackfill;
        impl std::fmt::Display for StubBackfill {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "backfill")
            }
        }
        impl std::fmt::Debug for StubBackfill {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "StubBackfill")
            }
        }
        impl AssemblyResolution for StubBackfill {
            fn get_description(&self) -> String {
                "backfill".to_string()
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
                "backfill".to_string()
            }
            fn is_backfill(&self) -> bool {
                true
            }
            fn is_error(&self) -> bool {
                false
            }
            fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
                Box::new(StubBackfill)
            }
            fn parent(&self, _description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
                unimplemented!("not exercised by this test")
            }
            fn collect_all_right(&self, _into: &mut Vec<Box<dyn AssemblyResolution>>) {}
            fn to_string_indented(&self, indent: &str) -> String {
                format!("{indent}backfill")
            }
            fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
                "backfill".cmp(&other.get_description())
            }
        }

        let mut results = AssemblyResolutionResults::new();
        results.add(Box::new(StubBackfill));
        let factory = MockFactory;

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            results.apply_fn(&factory, |rp| Box::new(MockPatterns::new(rp.get_description().as_str())))
        }));
        assert!(outcome.is_err(), "apply_fn must panic on a pending backfill, mirroring Java's AssertionError");
    }

    #[test]
    fn combine_panics_when_given_an_error_resolution_reproducing_java_assertion_error() {
        struct NoopApplicator;
        impl Applicator for NoopApplicator {
            fn get_patterns(&self, _cur: &dyn AssemblyResolvedPatterns) -> Vec<Box<dyn AssemblyResolution>> {
                vec![]
            }
            fn describe_error(&self, _rc: &dyn AssemblyResolvedPatterns, _pat: &dyn AssemblyResolution) -> String {
                String::new()
            }
        }
        let app = NoopApplicator;
        let cur: Box<dyn AssemblyResolution> = Box::new(MockPatterns::new("cur"));
        let pat = err("bad", "e");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            app.combine(cur, pat.as_ref())
        }));
        assert!(outcome.is_err(), "combine must panic when `pat` is an error, mirroring Java's AssertionError");
    }
}
