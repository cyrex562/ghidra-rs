/// Behavioral contract for a panel that lets the user select resolutions for
/// merge conflicts.
///
/// The Java source is an abstract `JPanel` subclass
/// (`ghidra.app.merge.listing.ChoiceComponent`). In Rust the behavioral
/// contract is expressed as a trait; egui rendering is left to implementors.
pub trait ChoiceComponent {
    /// Returns `true` when every conflict presented by this component has been
    /// resolved by the user.
    fn all_choices_are_resolved(&self) -> bool;

    /// Returns the number of conflicts that have currently been resolved in
    /// this component.
    fn get_num_conflicts_resolved(&self) -> usize;

    /// Returns `true` when every conflict is resolved *and* the user chose the
    /// same resolution for all of them.
    fn all_choices_are_same(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoneResolved;

    impl ChoiceComponent for NoneResolved {
        fn all_choices_are_resolved(&self) -> bool {
            false
        }
        fn get_num_conflicts_resolved(&self) -> usize {
            0
        }
        fn all_choices_are_same(&self) -> bool {
            false
        }
    }

    struct AllSame {
        total: usize,
    }

    impl ChoiceComponent for AllSame {
        fn all_choices_are_resolved(&self) -> bool {
            true
        }
        fn get_num_conflicts_resolved(&self) -> usize {
            self.total
        }
        fn all_choices_are_same(&self) -> bool {
            true
        }
    }

    struct AllResolvedMixed {
        total: usize,
    }

    impl ChoiceComponent for AllResolvedMixed {
        fn all_choices_are_resolved(&self) -> bool {
            true
        }
        fn get_num_conflicts_resolved(&self) -> usize {
            self.total
        }
        fn all_choices_are_same(&self) -> bool {
            false
        }
    }

    #[test]
    fn none_resolved_reports_zero_and_unresolved() {
        let c = NoneResolved;
        assert!(!c.all_choices_are_resolved());
        assert_eq!(c.get_num_conflicts_resolved(), 0);
        assert!(!c.all_choices_are_same());
    }

    #[test]
    fn all_resolved_same_returns_true_for_both_checks() {
        let c = AllSame { total: 3 };
        assert!(c.all_choices_are_resolved());
        assert_eq!(c.get_num_conflicts_resolved(), 3);
        assert!(c.all_choices_are_same());
    }

    #[test]
    fn all_resolved_mixed_choices_not_same() {
        let c = AllResolvedMixed { total: 4 };
        assert!(c.all_choices_are_resolved());
        assert_eq!(c.get_num_conflicts_resolved(), 4);
        assert!(!c.all_choices_are_same());
    }

    #[test]
    fn all_same_implies_all_resolved() {
        let c = AllSame { total: 2 };
        // all_choices_are_same can only be true when all_choices_are_resolved is also true
        if c.all_choices_are_same() {
            assert!(c.all_choices_are_resolved());
        }
    }
}
