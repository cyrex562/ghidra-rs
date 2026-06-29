/// A row and column location within a field panel.
///
/// Corresponds to `docking.widgets.fieldpanel.support.RowColLocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RowColLocation {
    pub row: i32,
    pub col: i32,
}

impl RowColLocation {
    /// Creates a new `RowColLocation` with the given row and column.
    pub fn new(row: i32, col: i32) -> Self {
        Self { row, col }
    }

    pub fn row(&self) -> i32 {
        self.row
    }

    pub fn col(&self) -> i32 {
        self.col
    }

    /// Returns a new `RowColLocation` with the same row but a different column.
    pub fn with_col(&self, new_col: i32) -> Self {
        Self { row: self.row, col: new_col }
    }

    /// Returns a new `RowColLocation` with the same column but a different row.
    pub fn with_row(&self, new_row: i32) -> Self {
        Self { row: new_row, col: self.col }
    }
}

impl std::fmt::Display for RowColLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.row, self.col)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_row_and_col() {
        let loc = RowColLocation::new(3, 7);
        assert_eq!(loc.row(), 3);
        assert_eq!(loc.col(), 7);
    }

    #[test]
    fn with_col_changes_only_col() {
        let loc = RowColLocation::new(2, 5);
        let updated = loc.with_col(10);
        assert_eq!(updated.row(), 2);
        assert_eq!(updated.col(), 10);
    }

    #[test]
    fn with_row_changes_only_row() {
        let loc = RowColLocation::new(2, 5);
        let updated = loc.with_row(9);
        assert_eq!(updated.row(), 9);
        assert_eq!(updated.col(), 5);
    }

    #[test]
    fn display_format() {
        let loc = RowColLocation::new(4, 12);
        assert_eq!(loc.to_string(), "4,12");
    }

    #[test]
    fn equality_same_values() {
        let a = RowColLocation::new(1, 2);
        let b = RowColLocation::new(1, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_row() {
        let a = RowColLocation::new(1, 2);
        let b = RowColLocation::new(3, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn equality_different_col() {
        let a = RowColLocation::new(1, 2);
        let b = RowColLocation::new(1, 5);
        assert_ne!(a, b);
    }

    #[test]
    fn zero_row_col() {
        let loc = RowColLocation::new(0, 0);
        assert_eq!(loc.to_string(), "0,0");
        assert_eq!(loc.row(), 0);
        assert_eq!(loc.col(), 0);
    }

    #[test]
    fn negative_values() {
        let loc = RowColLocation::new(-1, -5);
        assert_eq!(loc.row(), -1);
        assert_eq!(loc.col(), -5);
        assert_eq!(loc.to_string(), "-1,-5");
    }

    #[test]
    fn hash_equal_for_equal_locations() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RowColLocation::new(1, 2));
        set.insert(RowColLocation::new(1, 2));
        assert_eq!(set.len(), 1);
    }
}
