/// Tracks a component's position in the filter dialog for focus restoration when the dialog
/// is rebuilt.
///
/// Models the filter dialog as a grid: a set of compound rows, each of which can have sub-rows.
/// Column indices are the same for the dialog and its sub-components.
///
/// Corresponds to `docking.widgets.table.constraint.dialog.ColumnFilterGridLocation` in the
/// Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ColumnFilterGridLocation {
    /// Row number in the dialog's set of compound rows.
    pub dialog_row: i32,
    /// Row number within a given dialog row.
    pub sub_row: i32,
    /// Column index.
    pub col: i32,
}

impl ColumnFilterGridLocation {
    pub fn new(dialog_row: i32, sub_row: i32, col: i32) -> Self {
        Self { dialog_row, sub_row, col }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_stored_correctly() {
        let loc = ColumnFilterGridLocation::new(1, 2, 3);
        assert_eq!(loc.dialog_row, 1);
        assert_eq!(loc.sub_row, 2);
        assert_eq!(loc.col, 3);
    }

    #[test]
    fn equality_holds_for_identical_values() {
        let a = ColumnFilterGridLocation::new(0, 0, 0);
        let b = ColumnFilterGridLocation::new(0, 0, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_differing_fields() {
        let base = ColumnFilterGridLocation::new(1, 1, 1);
        assert_ne!(base, ColumnFilterGridLocation::new(2, 1, 1));
        assert_ne!(base, ColumnFilterGridLocation::new(1, 2, 1));
        assert_ne!(base, ColumnFilterGridLocation::new(1, 1, 2));
    }

    #[test]
    fn copy_is_independent() {
        let a = ColumnFilterGridLocation::new(3, 4, 5);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn hash_equal_for_equal_values() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ColumnFilterGridLocation::new(1, 2, 3));
        assert!(set.contains(&ColumnFilterGridLocation::new(1, 2, 3)));
        assert!(!set.contains(&ColumnFilterGridLocation::new(1, 2, 4)));
    }
}
