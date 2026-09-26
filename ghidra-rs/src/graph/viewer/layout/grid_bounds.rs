use super::grid_point::GridPoint;

/// Tracks the minimum and maximum indexes for both rows and columns.
///
/// Port of `ghidra.graph.viewer.layout.GridBounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridBounds {
    min_row: i32,
    max_row: i32,
    min_col: i32,
    max_col: i32,
}

impl GridBounds {
    /// Creates a new (empty-looking, but see the quirk below) set of bounds.
    ///
    /// Mirrors the implicit default constructor: all four Java fields are initialized to `0`
    /// (`private int minRow = 0;`, etc), *not* to `Integer.MAX_VALUE`/`MIN_VALUE`. This is
    /// important -- see [`GridBounds::fmt`](std::fmt::Display) below for a real consequence.
    pub fn new() -> Self {
        Self {
            min_row: 0,
            max_row: 0,
            min_col: 0,
            max_col: 0,
        }
    }

    /// Updates the bounds for the given [`GridPoint`].
    pub fn update(&mut self, p: &GridPoint) {
        self.min_row = self.min_row.min(p.row);
        self.max_row = self.max_row.max(p.row);
        self.min_col = self.min_col.min(p.col);
        self.max_col = self.max_col.max(p.col);
    }

    /// Shifts the row/column bounds by the given amounts.
    pub fn shift(&mut self, row_shift: i32, col_shift: i32) {
        self.min_col += col_shift;
        self.max_col += col_shift;
        self.min_row += row_shift;
        self.max_row += row_shift;
    }

    pub fn max_col(&self) -> i32 {
        self.max_col
    }

    /// Mirrors `minCol()`.
    ///
    /// Java's defensive "handle case when grid is empty" check (`minCol > maxCol`) is
    /// unreachable through the public API: [`GridBounds::new`] starts both fields at `0`
    /// (`min_col == max_col`), [`GridBounds::update`] only ever shrinks `min_col` or grows
    /// `max_col` relative to their current values (so `min_col <= max_col` is preserved), and
    /// [`GridBounds::shift`] adds the same delta to both, also preserving the ordering. This
    /// dead branch is kept anyway, faithfully mirroring the Java source; see
    /// `min_col_defensive_branch_is_unreachable_via_public_api` for the demonstration.
    pub fn min_col(&self) -> i32 {
        if self.min_col > self.max_col {
            return 0;
        }
        self.min_col
    }

    pub fn max_row(&self) -> i32 {
        self.max_row
    }

    /// Mirrors `minRow()`. See [`GridBounds::min_col`] for the equivalent (also unreachable via
    /// the public API) defensive-check quirk this preserves.
    pub fn min_row(&self) -> i32 {
        if self.min_row > self.max_row {
            return 0;
        }
        self.min_row
    }

    pub fn contains(&self, p: &GridPoint) -> bool {
        if p.row < self.min_row || p.row > self.max_row {
            return false;
        }
        if p.col < self.min_col || p.col > self.max_col {
            return false;
        }
        true
    }

    pub fn transpose(&mut self) {
        std::mem::swap(&mut self.min_row, &mut self.min_col);
        std::mem::swap(&mut self.max_row, &mut self.max_col);
    }

    /// Test-only constructor for exercising the defensive `min_row > max_row` / `min_col >
    /// max_col` branches in [`GridBounds::min_row`]/[`GridBounds::min_col`] and the
    /// `min_row == i32::MAX` branch in `Display`, none of which are reachable by any sequence of
    /// calls through the ordinary public API (see the doc comments on those methods).
    #[cfg(test)]
    fn with_fields(min_row: i32, max_row: i32, min_col: i32, max_col: i32) -> Self {
        Self {
            min_row,
            max_row,
            min_col,
            max_col,
        }
    }
}

impl Default for GridBounds {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for GridBounds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Faithful reproduction of a real Java dead-code quirk: `GridBounds`'s fields are
        // initialized to `0`, never to `Integer.MAX_VALUE`, so this "Empty" check can never
        // actually trigger through any sequence of `update`/`shift` calls starting from a fresh
        // `GridBounds` -- see `display_never_reports_empty_via_public_api`.
        if self.min_row == i32::MAX {
            return write!(f, "Empty");
        }
        write!(
            f,
            "Grid Bounds: rows: {} -> {},  cols: {} -> {}",
            self.min_row, self.max_row, self.min_col, self.max_col
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_zero_not_at_int_extremes() {
        let b = GridBounds::new();
        assert_eq!(b.min_row(), 0);
        assert_eq!(b.max_row(), 0);
        assert_eq!(b.min_col(), 0);
        assert_eq!(b.max_col(), 0);
    }

    #[test]
    fn update_expands_bounds_in_all_directions() {
        let mut b = GridBounds::new();
        b.update(&GridPoint::new(-3, 5));
        b.update(&GridPoint::new(7, -2));
        assert_eq!(b.min_row(), -3);
        assert_eq!(b.max_row(), 7);
        assert_eq!(b.min_col(), -2);
        assert_eq!(b.max_col(), 5);
    }

    #[test]
    fn shift_moves_all_bounds_by_the_given_deltas() {
        let mut b = GridBounds::new();
        b.update(&GridPoint::new(1, 2));
        b.shift(10, -5);
        assert_eq!(b.min_row(), 0 + 10);
        assert_eq!(b.max_row(), 1 + 10);
        assert_eq!(b.min_col(), 0 - 5);
        assert_eq!(b.max_col(), 2 - 5);
    }

    #[test]
    fn contains_respects_both_row_and_column_bounds() {
        let mut b = GridBounds::new();
        b.update(&GridPoint::new(2, 3));
        assert!(b.contains(&GridPoint::new(0, 0)));
        assert!(b.contains(&GridPoint::new(2, 3)));
        assert!(!b.contains(&GridPoint::new(3, 0)));
        assert!(!b.contains(&GridPoint::new(0, 4)));
    }

    #[test]
    fn transpose_swaps_row_and_column_bounds() {
        let mut b = GridBounds::new();
        b.update(&GridPoint::new(-1, 5));
        b.transpose();
        assert_eq!(b.min_row(), 0);
        assert_eq!(b.max_row(), 5);
        assert_eq!(b.min_col(), -1);
        assert_eq!(b.max_col(), 0);
    }

    #[test]
    fn display_format_matches_java_spacing() {
        let mut b = GridBounds::new();
        b.update(&GridPoint::new(-3, 5));
        b.update(&GridPoint::new(7, -2));
        assert_eq!(b.to_string(), "Grid Bounds: rows: -3 -> 7,  cols: -2 -> 5");
    }

    #[test]
    fn display_never_reports_empty_via_public_api() {
        // However many updates/shifts are applied starting from `new()`, `min_row` can never
        // reach `i32::MAX` through the public API, so the "Empty" branch is genuinely dead code
        // -- faithfully preserved from the Java source rather than "fixed."
        let mut b = GridBounds::new();
        for i in 0..50 {
            b.update(&GridPoint::new(i * 7 - 100, i * 3 - 40));
        }
        b.shift(1_000_000, -1_000_000);
        assert_ne!(b.to_string(), "Empty");
    }

    #[test]
    fn display_reports_empty_when_min_row_is_forced_to_int_max() {
        // Demonstrates the dead branch is still faithfully present in the ported code, even
        // though `with_fields` is the only way to reach it.
        let b = GridBounds::with_fields(i32::MAX, 0, 0, 0);
        assert_eq!(b.to_string(), "Empty");
    }

    #[test]
    fn min_row_defensive_branch_is_unreachable_via_public_api() {
        let mut b = GridBounds::new();
        for i in 0..50 {
            b.update(&GridPoint::new(i - 25, 0));
            assert!(b.min_row() <= b.max_row());
        }
    }

    #[test]
    fn min_col_defensive_branch_returns_zero_when_forced() {
        // `min_col > max_col` cannot arise via `update`/`shift`, but the guard is still ported
        // faithfully; exercise it directly via the test-only constructor.
        let b = GridBounds::with_fields(0, 0, 5, 2);
        assert_eq!(b.min_col(), 0);
        assert_eq!(b.max_col(), 2);
    }

    #[test]
    fn min_row_defensive_branch_returns_zero_when_forced() {
        let b = GridBounds::with_fields(5, 2, 0, 0);
        assert_eq!(b.min_row(), 0);
        assert_eq!(b.max_row(), 2);
    }
}
