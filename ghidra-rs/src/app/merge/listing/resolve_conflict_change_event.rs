/// Event passed to a listener to indicate that a user changed one of the
/// choices in a row of a table that is part of a `VerticalChoicesPanel` or
/// `VariousChoicesPanel`.
///
/// Corresponds to `ghidra.app.merge.listing.ResolveConflictChangeEvent`.
/// The Java source extends `javax.swing.event.ChangeEvent`; in Rust there is
/// no Swing event hierarchy, so the struct carries only the domain-relevant
/// fields (`row` and `choice`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveConflictChangeEvent {
    row: i32,
    choice: i32,
}

impl ResolveConflictChangeEvent {
    /// Creates a new event indicating that the user changed a choice.
    ///
    /// * `row` – the table row where the change occurred.
    /// * `choice` – the new choice value for that row.
    pub fn new(row: i32, choice: i32) -> Self {
        Self { row, choice }
    }

    /// Returns the row where the change occurred.
    pub fn get_row(&self) -> i32 {
        self.row
    }

    /// Returns the new choice value for the row.
    pub fn get_choice(&self) -> i32 {
        self.choice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_row_and_choice() {
        let e = ResolveConflictChangeEvent::new(3, 2);
        assert_eq!(e.get_row(), 3);
        assert_eq!(e.get_choice(), 2);
    }

    #[test]
    fn zero_values_are_valid() {
        let e = ResolveConflictChangeEvent::new(0, 0);
        assert_eq!(e.get_row(), 0);
        assert_eq!(e.get_choice(), 0);
    }

    #[test]
    fn negative_values_are_preserved() {
        let e = ResolveConflictChangeEvent::new(-1, -5);
        assert_eq!(e.get_row(), -1);
        assert_eq!(e.get_choice(), -5);
    }

    #[test]
    fn large_values_are_preserved() {
        let e = ResolveConflictChangeEvent::new(i32::MAX, i32::MAX);
        assert_eq!(e.get_row(), i32::MAX);
        assert_eq!(e.get_choice(), i32::MAX);
    }

    #[test]
    fn equality_holds_for_same_fields() {
        let a = ResolveConflictChangeEvent::new(1, 2);
        let b = ResolveConflictChangeEvent::new(1, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_different_row() {
        let a = ResolveConflictChangeEvent::new(1, 2);
        let b = ResolveConflictChangeEvent::new(2, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_on_different_choice() {
        let a = ResolveConflictChangeEvent::new(1, 2);
        let b = ResolveConflictChangeEvent::new(1, 3);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_value() {
        let original = ResolveConflictChangeEvent::new(7, 42);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
