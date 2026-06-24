/// Maximum number of display columns any [`ComparisonItem`] can have.
pub const MAX_COLS: usize = 5;

/// Apply state for a comparison item.
///
/// Mirrors the `ItemApplyState` inner enum from `ghidra.app.merge.structures.ComparisonItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemApplyState {
    NonApplicable,
    Applied,
    NotApplied,
}

/// Contract for items that can be displayed in a coordinated structure comparison view.
///
/// Each coordinated line has three comparison items: one for the left-side structure,
/// one for the right-side structure, and one for the merged structure. Every method
/// has a sensible default matching the Java base-class defaults so implementors only
/// override what they need.
///
/// Mirrors `ghidra.app.merge.structures.ComparisonItem`.
pub trait ComparisonItem {
    /// Line number for this item in the coordinated display.
    ///
    /// May differ from the item's index in a list model because the merged view removes
    /// blank lines while keeping line numbers synchronized with the left/right views.
    fn line(&self) -> i32;

    /// Type category for this item (e.g. "name", "comment", "component").
    ///
    /// Used to align columns of like items across the three comparison panes.
    fn item_type(&self) -> &str;

    /// Text to display for the given column index.
    fn get_column_text(&self, _column: usize) -> &str {
        ""
    }

    /// Returns `true` if this item represents something that can be applied or not applied.
    ///
    /// Used to decide whether a button should be created for the item. For example, a
    /// structure name can be applied from either side, but the syntax line `{` is the
    /// same everywhere and is never appliable.
    fn is_appliable(&self) -> bool {
        false
    }

    /// Returns `true` if any information in this item is not currently applied to the merged item.
    ///
    /// When `true` the corresponding button should be shown as unselected, indicating that
    /// information is available but not yet applied.
    fn can_apply_any(&self) -> bool {
        false
    }

    /// Returns `true` if the information from this item can be cleared.
    ///
    /// Currently only component-line items can be cleared. Items such as the structure name
    /// can never be cleared—they can only change by selecting the other side's value.
    fn can_clear(&self) -> bool {
        false
    }

    /// Returns `true` if the information for the given column is currently applied.
    ///
    /// Used by the renderer to bold applied information and fade unapplied information.
    fn is_applied(&self, _column: usize) -> bool {
        false
    }

    /// Returns `true` if the information for the given column can be applied (whether or not
    /// it is currently applied).
    ///
    /// Used by the renderer to display the column text at normal weight (not faded or bold).
    fn is_column_appliable(&self, _column: usize) -> bool {
        false
    }

    /// Minimum width of the given column.
    ///
    /// Used to reserve space for a column even when there is no text to display. The column
    /// may be wider if its text exceeds this minimum. Helps the renderer distribute extra
    /// space when the view is resized.
    fn get_min_width(&self, _column: usize) -> u32 {
        0
    }

    /// Returns `true` if the column text should be left-justified within the column.
    fn is_left_justified(&self, _column: usize) -> bool {
        true
    }

    /// Applies all information in this item to the merged structure.
    ///
    /// # Panics
    ///
    /// The default implementation panics. Override to provide concrete behaviour.
    fn apply_all(&mut self) {
        panic!("apply_all is not supported for this ComparisonItem");
    }

    /// Clears this item from the merged structure.
    ///
    /// Normally called when the corresponding item from the other side is applied, allowing
    /// a state where neither side is applied.
    ///
    /// # Panics
    ///
    /// The default implementation panics. Override to provide concrete behaviour.
    fn clear(&mut self) {
        panic!("clear is not supported for this ComparisonItem");
    }

    /// Returns `true` if this item represents a blank line.
    ///
    /// Useful for removing blank lines from the merge structure view.
    fn is_blank(&self) -> bool {
        false
    }

    /// Compares this item to `other` by line number, matching `Comparable<ComparisonItem>`.
    fn compare_to(&self, other: &dyn ComparisonItem) -> std::cmp::Ordering {
        self.line().cmp(&other.line())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    struct SimpleItem {
        line: i32,
        kind: &'static str,
    }

    impl ComparisonItem for SimpleItem {
        fn line(&self) -> i32 {
            self.line
        }
        fn item_type(&self) -> &str {
            self.kind
        }
    }

    struct AppliableItem {
        line: i32,
        applied: bool,
    }

    impl ComparisonItem for AppliableItem {
        fn line(&self) -> i32 {
            self.line
        }
        fn item_type(&self) -> &str {
            "component"
        }
        fn is_appliable(&self) -> bool {
            true
        }
        fn can_apply_any(&self) -> bool {
            !self.applied
        }
        fn can_clear(&self) -> bool {
            true
        }
        fn is_applied(&self, _col: usize) -> bool {
            self.applied
        }
        fn is_column_appliable(&self, _col: usize) -> bool {
            true
        }
        fn get_min_width(&self, _col: usize) -> u32 {
            40
        }
        fn is_left_justified(&self, _col: usize) -> bool {
            true
        }
        fn get_column_text(&self, _col: usize) -> &str {
            "field"
        }
    }

    #[test]
    fn max_cols_is_five() {
        assert_eq!(MAX_COLS, 5);
    }

    #[test]
    fn item_apply_state_variants() {
        assert_ne!(ItemApplyState::Applied, ItemApplyState::NotApplied);
        assert_ne!(ItemApplyState::Applied, ItemApplyState::NonApplicable);
        assert_ne!(ItemApplyState::NotApplied, ItemApplyState::NonApplicable);
    }

    #[test]
    fn defaults_are_false_and_empty() {
        let item = SimpleItem { line: 3, kind: "name" };
        assert_eq!(item.get_column_text(0), "");
        assert!(!item.is_appliable());
        assert!(!item.can_apply_any());
        assert!(!item.can_clear());
        assert!(!item.is_applied(0));
        assert!(!item.is_column_appliable(0));
        assert_eq!(item.get_min_width(0), 0);
        assert!(item.is_left_justified(0));
        assert!(!item.is_blank());
    }

    #[test]
    fn get_line_returns_stored_line() {
        let item = SimpleItem { line: 7, kind: "comment" };
        assert_eq!(item.line(), 7);
    }

    #[test]
    fn get_type_returns_stored_type() {
        let item = SimpleItem { line: 0, kind: "component" };
        assert_eq!(item.item_type(), "component");
    }

    #[test]
    fn compare_to_orders_by_line() {
        let a = SimpleItem { line: 1, kind: "name" };
        let b = SimpleItem { line: 5, kind: "name" };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        let c = SimpleItem { line: 1, kind: "comment" };
        assert_eq!(a.compare_to(&c), Ordering::Equal);
    }

    #[test]
    fn appliable_item_overrides_defaults() {
        let item = AppliableItem { line: 2, applied: false };
        assert!(item.is_appliable());
        assert!(item.can_apply_any());
        assert!(item.can_clear());
        assert!(!item.is_applied(0));
        assert!(item.is_column_appliable(0));
        assert_eq!(item.get_min_width(0), 40);
        assert_eq!(item.get_column_text(0), "field");
    }

    #[test]
    fn applied_item_can_apply_any_is_false() {
        let item = AppliableItem { line: 2, applied: true };
        assert!(!item.can_apply_any());
        assert!(item.is_applied(0));
    }

    #[test]
    fn apply_all_panics_by_default() {
        let mut item = SimpleItem { line: 0, kind: "name" };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| item.apply_all()));
        assert!(result.is_err());
    }

    #[test]
    fn clear_panics_by_default() {
        let mut item = SimpleItem { line: 0, kind: "name" };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| item.clear()));
        assert!(result.is_err());
    }
}
