//! Port of `ghidra.app.plugin.assembler.sleigh.expr.DefaultSolverHint`.

use crate::app::plugin::assembler::sleigh::expr::solver_hint::SolverHint;

/// A set of built-in [`SolverHint`]s.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.DefaultSolverHint`, an enum implementing the
/// `SolverHint` marker interface. [`SolverHint`] was ported as a trait using a stable
/// [`SolverHint::tag`] to stand in for Java's identity-based `equals`/`hashCode` (each enum
/// constant its own singleton); here each variant reports its own Java constant name as its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultSolverHint {
    /// A multiplication solver is synthesizing goals with repetition.
    GuessingRepetition,
    /// A boolean `or` solver which matches a circular shift is solving the value having guessed a
    /// shift.
    GuessingCircularShiftAmount,
    /// A left-shift solver is solving the value having guessed a shift.
    GuessingLeftShiftAmount,
    /// A right-shift solver is solving the value having guessed a shift.
    GuessingRightShiftAmount,
}

impl SolverHint for DefaultSolverHint {
    fn tag(&self) -> &'static str {
        match self {
            DefaultSolverHint::GuessingRepetition => "GUESSING_REPETITION",
            DefaultSolverHint::GuessingCircularShiftAmount => "GUESSING_CIRCULAR_SHIFT_AMOUNT",
            DefaultSolverHint::GuessingLeftShiftAmount => "GUESSING_LEFT_SHIFT_AMOUNT",
            DefaultSolverHint::GuessingRightShiftAmount => "GUESSING_RIGHT_SHIFT_AMOUNT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_matches_java_constant_name() {
        assert_eq!(DefaultSolverHint::GuessingRepetition.tag(), "GUESSING_REPETITION");
        assert_eq!(
            DefaultSolverHint::GuessingCircularShiftAmount.tag(),
            "GUESSING_CIRCULAR_SHIFT_AMOUNT"
        );
        assert_eq!(DefaultSolverHint::GuessingLeftShiftAmount.tag(), "GUESSING_LEFT_SHIFT_AMOUNT");
        assert_eq!(
            DefaultSolverHint::GuessingRightShiftAmount.tag(),
            "GUESSING_RIGHT_SHIFT_AMOUNT"
        );
    }

    #[test]
    fn same_variant_is_equal_as_trait_object() {
        let a: &dyn SolverHint = &DefaultSolverHint::GuessingRepetition;
        let b: &dyn SolverHint = &DefaultSolverHint::GuessingRepetition;
        assert!(a == b);
    }

    #[test]
    fn different_variant_is_not_equal_as_trait_object() {
        let a: &dyn SolverHint = &DefaultSolverHint::GuessingRepetition;
        let b: &dyn SolverHint = &DefaultSolverHint::GuessingLeftShiftAmount;
        assert!(a != b);
    }

    #[test]
    fn enum_equality_is_structural() {
        assert_eq!(DefaultSolverHint::GuessingRepetition, DefaultSolverHint::GuessingRepetition);
        assert_ne!(DefaultSolverHint::GuessingRepetition, DefaultSolverHint::GuessingLeftShiftAmount);
    }

    #[test]
    fn usable_as_boxed_trait_object_in_a_hint_set() {
        use std::collections::HashSet;
        use std::sync::Arc;

        let mut set: HashSet<Arc<dyn SolverHint>> = HashSet::new();
        set.insert(Arc::new(DefaultSolverHint::GuessingRepetition));
        set.insert(Arc::new(DefaultSolverHint::GuessingRepetition));
        set.insert(Arc::new(DefaultSolverHint::GuessingLeftShiftAmount));
        assert_eq!(set.len(), 2);
    }
}
