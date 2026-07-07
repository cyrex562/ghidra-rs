use std::fmt;
use std::hash::{Hash, Hasher};

use super::comparison_item::ComparisonItem;
use super::coordinated_structure_line::{CoordinatedStructureLine, CoordinatedStructureModel};

/// A single coordinated display line for invariant structure information.
///
/// Covers syntax lines (`{` and `}`) and structure-detail lines (size, alignment,
/// packing) that are the same conceptually across all three panes but whose text
/// may differ between the left, right, and merged views.
///
/// Mirrors `ghidra.app.merge.structures.StructureInfoLine`.
pub struct StructureInfoLine<M> {
    left: InfoItem,
    right: InfoItem,
    merged: InfoItem,
    model: M,
}

impl<M: CoordinatedStructureModel> StructureInfoLine<M> {
    /// Creates a new line with independent text for each pane.
    ///
    /// * `model`     — the coordinated-structure model that owns this line.
    /// * `left`      — text shown in the left pane.
    /// * `right`     — text shown in the right pane.
    /// * `merged`    — text shown in the merged pane.
    /// * `line`      — display-row number (shared by all three pane items).
    /// * `item_type` — type category (e.g. `"Syntax"` or `"Structure details"`).
    pub fn new(
        model: M,
        left: impl Into<String>,
        right: impl Into<String>,
        merged: impl Into<String>,
        line: i32,
        item_type: impl Into<String>,
    ) -> Self {
        let item_type = item_type.into();
        Self {
            left: InfoItem::new(left.into(), item_type.clone(), line),
            right: InfoItem::new(right.into(), item_type.clone(), line),
            merged: InfoItem::new(merged.into(), item_type, line),
            model,
        }
    }

    /// Creates a new line where all three panes share the same text.
    ///
    /// Mirrors the two-argument convenience constructor in the Java source.
    pub fn new_uniform(
        model: M,
        all: impl Into<String>,
        line: i32,
        item_type: impl Into<String>,
    ) -> Self {
        let all = all.into();
        let item_type = item_type.into();
        Self::new(model, all.clone(), all.clone(), all, line, item_type)
    }
}

impl<M: CoordinatedStructureModel> CoordinatedStructureLine for StructureInfoLine<M> {
    fn left(&self) -> Option<&dyn ComparisonItem> {
        Some(&self.left)
    }

    fn right(&self) -> Option<&dyn ComparisonItem> {
        Some(&self.right)
    }

    fn merged(&self) -> Option<&dyn ComparisonItem> {
        Some(&self.merged)
    }

    fn model_mut(&mut self) -> &mut dyn CoordinatedStructureModel {
        &mut self.model
    }
}

impl<M: CoordinatedStructureModel> fmt::Display for StructureInfoLine<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "left: {}, right: {}, merged: {}",
            self.left.info, self.right.info, self.merged.info
        )
    }
}

// ── InfoItem ─────────────────────────────────────────────────────────────────

/// A single pane's item inside a [`StructureInfoLine`].
///
/// Implements [`ComparisonItem`] so that column 0 shows the stored text and
/// column 0 carries a minimum width of 350, matching the Java inner class
/// `StructureInfoLine.InfoItem`.
#[derive(Debug)]
struct InfoItem {
    info: String,
    item_type: String,
    line: i32,
}

impl InfoItem {
    fn new(info: String, item_type: String, line: i32) -> Self {
        Self { info, item_type, line }
    }
}

impl ComparisonItem for InfoItem {
    fn line(&self) -> i32 {
        self.line
    }

    fn item_type(&self) -> &str {
        &self.item_type
    }

    fn get_column_text(&self, column: usize) -> &str {
        if column == 0 { &self.info } else { "" }
    }

    fn get_min_width(&self, column: usize) -> u32 {
        if column == 0 { 350 } else { 0 }
    }
}

impl PartialEq for InfoItem {
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}

impl Eq for InfoItem {}

impl Hash for InfoItem {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.info.hash(state);
    }
}

impl fmt::Display for InfoItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.info)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::merge::structures::coordinated_structure_line::{
        CompareId, CoordinatedStructureLine,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // ── test double ──────────────────────────────────────────────────────────

    #[derive(Default)]
    struct FakeModel {
        rebuild_count: usize,
    }

    impl CoordinatedStructureModel for FakeModel {
        fn rebuild(&mut self) {
            self.rebuild_count += 1;
        }
        fn error(&mut self, _message: &str) {}
    }

    fn make_line(
        left: &str,
        right: &str,
        merged: &str,
    ) -> StructureInfoLine<FakeModel> {
        StructureInfoLine::new(FakeModel::default(), left, right, merged, 0, "Syntax")
    }

    fn make_uniform(all: &str) -> StructureInfoLine<FakeModel> {
        StructureInfoLine::new_uniform(FakeModel::default(), all, 1, "Structure details")
    }

    // ── constructor: separate strings ────────────────────────────────────────

    #[test]
    fn new_stores_left_right_merged_independently() {
        let line = make_line("L", "R", "M");
        assert_eq!(line.left().unwrap().get_column_text(0), "L");
        assert_eq!(line.right().unwrap().get_column_text(0), "R");
        assert_eq!(line.merged().unwrap().get_column_text(0), "M");
    }

    #[test]
    fn new_propagates_line_number_and_type() {
        let line = StructureInfoLine::new(
            FakeModel::default(),
            "a",
            "b",
            "c",
            42,
            "Syntax",
        );
        assert_eq!(line.left().unwrap().line(), 42);
        assert_eq!(line.right().unwrap().line(), 42);
        assert_eq!(line.merged().unwrap().line(), 42);
        assert_eq!(line.left().unwrap().item_type(), "Syntax");
    }

    // ── constructor: uniform ─────────────────────────────────────────────────

    #[test]
    fn new_uniform_sets_all_panes_to_same_text() {
        let line = make_uniform("{");
        assert_eq!(line.left().unwrap().get_column_text(0), "{");
        assert_eq!(line.right().unwrap().get_column_text(0), "{");
        assert_eq!(line.merged().unwrap().get_column_text(0), "{");
    }

    #[test]
    fn new_uniform_propagates_line_and_type() {
        let line = make_uniform("}");
        assert_eq!(line.left().unwrap().line(), 1);
        assert_eq!(line.left().unwrap().item_type(), "Structure details");
    }

    // ── CoordinatedStructureLine: pane routing ───────────────────────────────

    #[test]
    fn get_comparison_item_left() {
        let line = make_line("X", "Y", "Z");
        assert_eq!(
            line.get_comparison_item(CompareId::Left)
                .unwrap()
                .get_column_text(0),
            "X"
        );
    }

    #[test]
    fn get_comparison_item_right() {
        let line = make_line("X", "Y", "Z");
        assert_eq!(
            line.get_comparison_item(CompareId::Right)
                .unwrap()
                .get_column_text(0),
            "Y"
        );
    }

    #[test]
    fn get_comparison_item_merged() {
        let line = make_line("X", "Y", "Z");
        assert_eq!(
            line.get_comparison_item(CompareId::Merged)
                .unwrap()
                .get_column_text(0),
            "Z"
        );
    }

    // ── model_changed delegation ─────────────────────────────────────────────

    #[test]
    fn model_changed_increments_rebuild_count() {
        let mut line = make_line("a", "b", "c");
        assert_eq!(line.model.rebuild_count, 0);
        line.model_changed();
        assert_eq!(line.model.rebuild_count, 1);
    }

    // ── Display / toString ───────────────────────────────────────────────────

    #[test]
    fn display_matches_java_tostring_format() {
        let line = make_line("hello", "world", "merged");
        assert_eq!(
            line.to_string(),
            "left: hello, right: world, merged: merged"
        );
    }

    #[test]
    fn display_uniform_shows_same_text_three_times() {
        let line = make_uniform("{");
        assert_eq!(line.to_string(), "left: {, right: {, merged: {");
    }

    // ── InfoItem: column 0 vs other columns ──────────────────────────────────

    #[test]
    fn column_0_returns_info_text() {
        let line = make_line("data", "x", "y");
        assert_eq!(line.left().unwrap().get_column_text(0), "data");
    }

    #[test]
    fn column_nonzero_returns_empty() {
        let line = make_line("data", "x", "y");
        assert_eq!(line.left().unwrap().get_column_text(1), "");
        assert_eq!(line.left().unwrap().get_column_text(99), "");
    }

    // ── InfoItem: min width ──────────────────────────────────────────────────

    #[test]
    fn min_width_column_0_is_350() {
        let line = make_line("a", "b", "c");
        assert_eq!(line.left().unwrap().get_min_width(0), 350);
    }

    #[test]
    fn min_width_other_columns_is_0() {
        let line = make_line("a", "b", "c");
        assert_eq!(line.left().unwrap().get_min_width(1), 0);
        assert_eq!(line.left().unwrap().get_min_width(4), 0);
    }

    // ── InfoItem: equality and hash based on info field ──────────────────────

    #[test]
    fn info_items_with_same_text_are_equal() {
        let a = InfoItem::new("foo".into(), "Syntax".into(), 0);
        let b = InfoItem::new("foo".into(), "Other".into(), 99);
        assert_eq!(a, b);
    }

    #[test]
    fn info_items_with_different_text_are_not_equal() {
        let a = InfoItem::new("foo".into(), "Syntax".into(), 0);
        let b = InfoItem::new("bar".into(), "Syntax".into(), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn info_items_with_same_text_have_same_hash() {
        let a = InfoItem::new("hello".into(), "Syntax".into(), 0);
        let b = InfoItem::new("hello".into(), "Details".into(), 5);
        let hash_of = |item: &InfoItem| {
            let mut h = DefaultHasher::new();
            item.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn info_item_display_returns_info_text() {
        let item = InfoItem::new("size: 8".into(), "Syntax".into(), 3);
        assert_eq!(item.to_string(), "size: 8");
    }

    // ── is_appliable / is_blank defaults (inherited from ComparisonItem) ─────

    #[test]
    fn info_item_is_not_appliable() {
        let line = make_line("x", "y", "z");
        assert!(!line.left().unwrap().is_appliable());
    }

    #[test]
    fn info_item_is_not_blank() {
        let line = make_line("x", "y", "z");
        assert!(!line.left().unwrap().is_blank());
    }
}
