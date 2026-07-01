use super::RowColLocation;

/// A location used to represent an edge case where no suitable location can be found and the
/// client does not wish to return null.
///
/// Corresponds to `docking.widgets.fieldpanel.support.DefaultRowColLocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefaultRowColLocation {
    location: RowColLocation,
}

impl DefaultRowColLocation {
    /// Creates a new `DefaultRowColLocation` at the default position (0, 0).
    pub fn new() -> Self {
        Self {
            location: RowColLocation::new(0, 0),
        }
    }

    /// Creates a new `DefaultRowColLocation` at the given row and column.
    pub fn new_with_location(row: i32, col: i32) -> Self {
        Self {
            location: RowColLocation::new(row, col),
        }
    }

    /// Returns the row of this location.
    pub fn row(&self) -> i32 {
        self.location.row
    }

    /// Returns the column of this location.
    pub fn col(&self) -> i32 {
        self.location.col
    }

    /// Returns a new `DefaultRowColLocation` with the same row but a different column.
    pub fn with_col(&self, new_col: i32) -> Self {
        Self {
            location: RowColLocation::new(self.location.row, new_col),
        }
    }

    /// Returns a new `DefaultRowColLocation` with the same column but a different row.
    pub fn with_row(&self, new_row: i32) -> Self {
        Self {
            location: RowColLocation::new(new_row, self.location.col),
        }
    }

    /// Returns the underlying `RowColLocation`.
    pub fn as_row_col_location(&self) -> RowColLocation {
        self.location
    }
}

impl Default for DefaultRowColLocation {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DefaultRowColLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_creates_zero_zero_location() {
        let loc = DefaultRowColLocation::new();
        assert_eq!(loc.row(), 0);
        assert_eq!(loc.col(), 0);
    }

    #[test]
    fn default_trait_creates_zero_zero_location() {
        let loc = DefaultRowColLocation::default();
        assert_eq!(loc.row(), 0);
        assert_eq!(loc.col(), 0);
    }

    #[test]
    fn new_with_location_stores_row_and_col() {
        let loc = DefaultRowColLocation::new_with_location(5, 3);
        assert_eq!(loc.row(), 5);
        assert_eq!(loc.col(), 3);
    }

    #[test]
    fn with_col_changes_only_col() {
        let loc = DefaultRowColLocation::new_with_location(2, 5);
        let updated = loc.with_col(10);
        assert_eq!(updated.row(), 2);
        assert_eq!(updated.col(), 10);
    }

    #[test]
    fn with_row_changes_only_row() {
        let loc = DefaultRowColLocation::new_with_location(2, 5);
        let updated = loc.with_row(9);
        assert_eq!(updated.row(), 9);
        assert_eq!(updated.col(), 5);
    }

    #[test]
    fn with_col_returns_default_row_col_location() {
        let loc = DefaultRowColLocation::new_with_location(1, 1);
        let updated = loc.with_col(2);
        assert!(matches!(updated, DefaultRowColLocation { .. }));
    }

    #[test]
    fn with_row_returns_default_row_col_location() {
        let loc = DefaultRowColLocation::new_with_location(1, 1);
        let updated = loc.with_row(2);
        assert!(matches!(updated, DefaultRowColLocation { .. }));
    }

    #[test]
    fn display_format() {
        let loc = DefaultRowColLocation::new_with_location(4, 12);
        assert_eq!(loc.to_string(), "4,12");
    }

    #[test]
    fn as_row_col_location_preserves_values() {
        let loc = DefaultRowColLocation::new_with_location(7, 3);
        let row_col = loc.as_row_col_location();
        assert_eq!(row_col.row, 7);
        assert_eq!(row_col.col, 3);
    }

    #[test]
    fn equality() {
        let a = DefaultRowColLocation::new_with_location(1, 2);
        let b = DefaultRowColLocation::new_with_location(1, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_row() {
        let a = DefaultRowColLocation::new_with_location(1, 2);
        let b = DefaultRowColLocation::new_with_location(3, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_col() {
        let a = DefaultRowColLocation::new_with_location(1, 2);
        let b = DefaultRowColLocation::new_with_location(1, 5);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_equal_for_equal_locations() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DefaultRowColLocation::new_with_location(1, 2));
        set.insert(DefaultRowColLocation::new_with_location(1, 2));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn chained_modifications() {
        let loc = DefaultRowColLocation::new_with_location(1, 1);
        let updated = loc.with_row(5).with_col(10);
        assert_eq!(updated.row(), 5);
        assert_eq!(updated.col(), 10);
    }
}
