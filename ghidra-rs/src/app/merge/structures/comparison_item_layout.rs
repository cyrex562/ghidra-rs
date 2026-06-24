use super::comparison_item::MAX_COLS;

/// Horizontal gap in pixels between columns.
pub const HGAP: i32 = 5;

/// Per-column minimum and maximum display widths.
///
/// Each column accumulates the widest text seen across all items of that type so the
/// three comparison panes can align like columns. `add_min_width`/`add_max_width` only
/// grow the stored value; they never shrink it.
///
/// Mirrors the package-private `ComparisonItemLayout.ColumnWidths` inner class from
/// `ghidra.app.merge.structures.ComparisonItemLayout`.
#[derive(Debug, Clone, Default)]
pub struct ColumnWidths {
    min_widths: [i32; MAX_COLS],
    max_widths: [i32; MAX_COLS],
}

impl ColumnWidths {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_min_width(&self, column: usize) -> i32 {
        self.min_widths[column]
    }

    pub fn get_max_width(&self, column: usize) -> i32 {
        self.max_widths[column]
    }

    /// Grow the stored minimum for `column` to at least `width`.
    pub fn add_min_width(&mut self, column: usize, width: i32) {
        self.min_widths[column] = self.min_widths[column].max(width);
    }

    /// Grow the stored maximum for `column` to at least `width`.
    pub fn add_max_width(&mut self, column: usize, width: i32) {
        self.max_widths[column] = self.max_widths[column].max(width);
    }
}

/// Column-width layout manager for comparison-item rows.
///
/// Computes per-column widths so that like item types align their fields across the
/// three comparison panes (left, right, merged). Columns start at their minimum widths;
/// any spare space up to `available_width` is distributed 10 pixels at a time until
/// each column reaches its maximum or the available space is exhausted.
///
/// Mirrors `ghidra.app.merge.structures.ComparisonItemLayout`. The Swing `LayoutManager`
/// interface methods are replaced by the pure [`layout`] helper; callers apply the
/// returned `(x_offset, width)` pairs using their own UI toolkit.
///
/// [`layout`]: ComparisonItemLayout::layout
pub struct ComparisonItemLayout {
    min_max_widths: ColumnWidths,
    adjusted_widths: [i32; MAX_COLS],
}

impl ComparisonItemLayout {
    pub fn new() -> Self {
        Self {
            min_max_widths: ColumnWidths::new(),
            adjusted_widths: [0; MAX_COLS],
        }
    }

    /// Replace the column min/max width constraints.
    pub fn set_column_widths(&mut self, widths: ColumnWidths) {
        self.min_max_widths = widths;
    }

    /// Minimum total width needed to fit `component_count` columns at their minimum sizes
    /// plus three [`HGAP`] gaps.
    ///
    /// Corresponds to the body of `minimumLayoutSize` (without Swing insets).
    pub fn minimum_width(&self, component_count: usize) -> i32 {
        let mut width = 0;
        for i in 0..component_count {
            width += self.min_max_widths.get_min_width(i);
        }
        width + 3 * HGAP
    }

    /// Compute per-column adjusted widths given `available_width` pixels and `component_count`
    /// active columns.
    ///
    /// After this call, [`adjusted_widths`] returns the result. Mirrors the private
    /// `computeWidths` method; made public so callers that pre-compute widths without laying
    /// out can call it directly.
    ///
    /// [`adjusted_widths`]: ComparisonItemLayout::adjusted_widths
    pub fn compute_widths(&mut self, width: i32, component_count: usize) {
        let mut total_width = 0;
        let mut total_max_width = 0;
        for i in 0..component_count {
            let min = self.min_max_widths.get_min_width(i);
            let max = self.min_max_widths.get_max_width(i);
            total_width += min;
            total_max_width += max;
            self.adjusted_widths[i] = min;
        }

        if width >= total_max_width {
            for i in 0..component_count {
                self.adjusted_widths[i] = self.min_max_widths.get_max_width(i);
            }
            return;
        }

        while total_width < width && total_width < total_max_width {
            total_width = self.add_to_column_widths(total_max_width - total_width);
        }
    }

    /// Distribute up to `extra_width` pixels across all `MAX_COLS` columns, at most 10
    /// pixels per column per call, without exceeding each column's maximum.
    ///
    /// Returns the new total adjusted width. Mirrors `addToColumnWidths`; iterates
    /// `MAX_COLS` (not component count) to match the original Java behaviour.
    fn add_to_column_widths(&mut self, mut extra_width: i32) -> i32 {
        let mut total_width = 0;
        for i in 0..MAX_COLS {
            let max_width = self.min_max_widths.get_max_width(i);
            let increment = (max_width - self.adjusted_widths[i]).min(10);
            self.adjusted_widths[i] += increment;
            extra_width -= increment;
            total_width += self.adjusted_widths[i];
            if extra_width <= 0 {
                break;
            }
        }
        total_width
    }

    /// Returns the computed column widths from the most recent [`compute_widths`] call.
    ///
    /// [`compute_widths`]: ComparisonItemLayout::compute_widths
    pub fn adjusted_widths(&self) -> &[i32; MAX_COLS] {
        &self.adjusted_widths
    }

    /// Compute `(x_offset, width)` pairs for each of `component_count` columns within
    /// `available_width` pixels.
    ///
    /// Pure-Rust equivalent of `layoutContainer`: instead of calling `setBounds` on Swing
    /// components, the caller receives the positions and applies them with their UI toolkit.
    pub fn layout(&mut self, available_width: i32, component_count: usize) -> Vec<(i32, i32)> {
        self.compute_widths(available_width, component_count);

        let mut result = Vec::with_capacity(component_count);
        let mut x = 0;
        let mut width_so_far = 0;
        for i in 0..component_count {
            let comp_width = self.adjusted_widths[i].min(available_width - width_so_far);
            result.push((x, comp_width));
            x += comp_width + HGAP;
            width_so_far += comp_width;
        }
        result
    }
}

impl Default for ComparisonItemLayout {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layout_with_two_cols(min0: i32, max0: i32, min1: i32, max1: i32) -> ComparisonItemLayout {
        let mut widths = ColumnWidths::new();
        widths.add_min_width(0, min0);
        widths.add_max_width(0, max0);
        widths.add_min_width(1, min1);
        widths.add_max_width(1, max1);
        let mut layout = ComparisonItemLayout::new();
        layout.set_column_widths(widths);
        layout
    }

    // ColumnWidths tests

    #[test]
    fn column_widths_default_is_zero() {
        let cw = ColumnWidths::new();
        for i in 0..MAX_COLS {
            assert_eq!(cw.get_min_width(i), 0);
            assert_eq!(cw.get_max_width(i), 0);
        }
    }

    #[test]
    fn add_min_width_takes_max() {
        let mut cw = ColumnWidths::new();
        cw.add_min_width(0, 30);
        cw.add_min_width(0, 20); // smaller — should not shrink
        assert_eq!(cw.get_min_width(0), 30);
        cw.add_min_width(0, 50); // larger — should grow
        assert_eq!(cw.get_min_width(0), 50);
    }

    #[test]
    fn add_max_width_takes_max() {
        let mut cw = ColumnWidths::new();
        cw.add_max_width(2, 100);
        cw.add_max_width(2, 80);
        assert_eq!(cw.get_max_width(2), 100);
        cw.add_max_width(2, 150);
        assert_eq!(cw.get_max_width(2), 150);
    }

    #[test]
    fn add_widths_are_independent_per_column() {
        let mut cw = ColumnWidths::new();
        cw.add_min_width(0, 10);
        cw.add_min_width(1, 20);
        assert_eq!(cw.get_min_width(0), 10);
        assert_eq!(cw.get_min_width(1), 20);
    }

    // ComparisonItemLayout tests

    #[test]
    fn hgap_is_five() {
        assert_eq!(HGAP, 5);
    }

    #[test]
    fn minimum_width_sums_mins_plus_three_hgap() {
        let layout = make_layout_with_two_cols(10, 50, 20, 60);
        // 10 + 20 + 3*5 = 45
        assert_eq!(layout.minimum_width(2), 45);
    }

    #[test]
    fn minimum_width_respects_component_count() {
        let layout = make_layout_with_two_cols(10, 50, 20, 60);
        // only 1 column: 10 + 15 = 25
        assert_eq!(layout.minimum_width(1), 25);
    }

    #[test]
    fn compute_widths_sets_max_when_space_exceeds_total_max() {
        let mut layout = make_layout_with_two_cols(10, 30, 20, 50);
        // available 200 > totalMax 80
        layout.compute_widths(200, 2);
        let w = layout.adjusted_widths();
        assert_eq!(w[0], 30);
        assert_eq!(w[1], 50);
    }

    #[test]
    fn compute_widths_sets_min_when_space_is_tight() {
        let mut layout = make_layout_with_two_cols(10, 30, 20, 50);
        // available 15 < totalMin 30 — columns stay at min, loop condition fails immediately
        layout.compute_widths(15, 2);
        let w = layout.adjusted_widths();
        assert_eq!(w[0], 10);
        assert_eq!(w[1], 20);
    }

    #[test]
    fn compute_widths_distributes_extra_space_ten_at_a_time() {
        // col0: min=10 max=30, col1: min=20 max=50 → totalMin=30, totalMax=80
        let mut layout = make_layout_with_two_cols(10, 30, 20, 50);
        // available=45: extra=15 — one iteration adds 10 to col0 (→20) and 5 to col1 (→25)
        // After that totalWidth=45 == width, loop exits.
        layout.compute_widths(45, 2);
        let w = layout.adjusted_widths();
        assert_eq!(w[0], 20); // min 10 + 10 increment
        assert_eq!(w[1], 25); // min 20 + 5 from remaining extra
    }

    #[test]
    fn layout_returns_correct_x_offsets() {
        let mut layout = make_layout_with_two_cols(10, 30, 20, 50);
        // available=200 → both get max widths (30, 50)
        let positions = layout.layout(200, 2);
        assert_eq!(positions.len(), 2);
        // col0: x=0, width=30
        assert_eq!(positions[0], (0, 30));
        // col1: x=30+5=35, width=50
        assert_eq!(positions[1], (35, 50));
    }

    #[test]
    fn layout_clips_last_column_when_space_exhausted() {
        let mut layout = make_layout_with_two_cols(10, 100, 20, 100);
        // available=12: totalMin=30>12, loop doesn't run; widths=[10,20]
        // clip: col0 width=min(10,12)=10, widthSoFar=10; col1 width=min(20,12-10)=2
        let positions = layout.layout(12, 2);
        assert_eq!(positions[0].1, 10);
        assert_eq!(positions[1].1, 2);
    }

    #[test]
    fn layout_single_column_uses_full_width_up_to_max() {
        let mut layout = make_layout_with_two_cols(5, 40, 0, 0);
        let positions = layout.layout(100, 1);
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0], (0, 40));
    }

    #[test]
    fn set_column_widths_replaces_constraints() {
        let mut layout = make_layout_with_two_cols(10, 30, 20, 50);
        let mut new_widths = ColumnWidths::new();
        new_widths.add_min_width(0, 50);
        new_widths.add_max_width(0, 100);
        layout.set_column_widths(new_widths);
        // minimum_width with 1 col: 50 + 15 = 65
        assert_eq!(layout.minimum_width(1), 65);
    }

    #[test]
    fn default_and_new_produce_same_state() {
        let a = ComparisonItemLayout::new();
        let b = ComparisonItemLayout::default();
        assert_eq!(a.adjusted_widths(), b.adjusted_widths());
    }
}
