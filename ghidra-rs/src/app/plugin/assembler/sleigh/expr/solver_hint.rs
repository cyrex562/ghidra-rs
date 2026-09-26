use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A type for solver hints.
///
/// Hints inform sub-solvers of the techniques already being applied by the calling solvers. This
/// helps prevent situations where, e.g., two multiplication solvers (applied to repeated or
/// nested multiplication) both attempt to synthesize new goals for repetition. This sort of
/// expression is common when decoding immediates in the AArch64 specification.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.SolverHint`, cut to a trait to break a
/// dependency cycle at this node in the port graph. The Java interface is a marker with no
/// members, implemented by an enumeration
/// (`ghidra.app.plugin.assembler.sleigh.expr.DefaultSolverHint`) whose constants get Java's
/// default identity-based `equals`/`hashCode` -- each enum constant is its own singleton, so
/// putting one in a `Set<SolverHint>` twice is a no-op. Rust trait objects have no equivalent
/// built-in identity, so implementers instead report a stable [`SolverHint::tag`] that plays the
/// same role: two hints with the same tag are treated as the same hint for set membership.
pub trait SolverHint: fmt::Debug {
    /// A stable identity for this hint, used for equality and hashing within a hint set.
    ///
    /// Implementers backed by an enum-like set of variants (as `DefaultSolverHint` is) should
    /// return a distinct tag per variant, e.g. the variant's name.
    fn tag(&self) -> &'static str;
}

impl PartialEq for dyn SolverHint {
    /// Port of the identity-based `Object#equals(Object)` `DefaultSolverHint` inherits: true iff
    /// the hints report the same [`SolverHint::tag`].
    fn eq(&self, other: &Self) -> bool {
        self.tag() == other.tag()
    }
}

impl Eq for dyn SolverHint {}

impl Hash for dyn SolverHint {
    /// Port of the identity-based `Object#hashCode()` `DefaultSolverHint` inherits.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tag().hash(state);
    }
}

/// Port of `SolverHint.with(Set<SolverHint>, SolverHint...)`: returns a new set containing every
/// hint in `set` plus every hint in `plus`.
pub fn with(set: &HashSet<Arc<dyn SolverHint>>, plus: &[Arc<dyn SolverHint>]) -> HashSet<Arc<dyn SolverHint>> {
    let mut hints = set.clone();
    hints.extend(plus.iter().cloned());
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockHint(&'static str);

    impl SolverHint for MockHint {
        fn tag(&self) -> &'static str {
            self.0
        }
    }

    #[test]
    fn same_tag_is_equal() {
        let a: &dyn SolverHint = &MockHint("GUESSING_REPETITION");
        let b: &dyn SolverHint = &MockHint("GUESSING_REPETITION");
        assert!(a == b);
    }

    #[test]
    fn different_tag_is_not_equal() {
        let a: &dyn SolverHint = &MockHint("GUESSING_REPETITION");
        let b: &dyn SolverHint = &MockHint("GUESSING_LEFT_SHIFT_AMOUNT");
        assert!(a != b);
    }

    #[test]
    fn with_unions_and_dedupes_by_tag() {
        let mut set: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        set.insert(Arc::new(MockHint("GUESSING_REPETITION")));

        let plus: Vec<Arc<dyn SolverHint>> = vec![
            Arc::new(MockHint("GUESSING_REPETITION")),
            Arc::new(MockHint("GUESSING_CIRCULAR_SHIFT_AMOUNT")),
        ];
        let combined = with(&set, &plus);

        assert_eq!(combined.len(), 2);
        assert!(combined.contains(&(Arc::new(MockHint("GUESSING_REPETITION")) as Arc<dyn SolverHint>)));
        assert!(combined
            .contains(&(Arc::new(MockHint("GUESSING_CIRCULAR_SHIFT_AMOUNT")) as Arc<dyn SolverHint>)));
    }

    #[test]
    fn with_does_not_mutate_original_set() {
        let mut set: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        set.insert(Arc::new(MockHint("GUESSING_REPETITION")));

        let plus: Vec<Arc<dyn SolverHint>> = vec![Arc::new(MockHint("GUESSING_RIGHT_SHIFT_AMOUNT"))];
        let _combined = with(&set, &plus);

        assert_eq!(set.len(), 1);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let h: Box<dyn SolverHint> = Box::new(MockHint("GUESSING_REPETITION"));
        assert_eq!(h.tag(), "GUESSING_REPETITION");
    }
}
