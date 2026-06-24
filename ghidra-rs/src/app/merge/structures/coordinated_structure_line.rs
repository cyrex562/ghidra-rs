use super::comparison_item::ComparisonItem;

/// Identifies which comparison pane (left, right, or merged) to target.
///
/// Mirrors the `CompareId` inner enum from
/// `ghidra.app.merge.structures.CoordinatedStructureLine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareId {
    Left,
    Right,
    Merged,
}

/// The subset of `CoordinatedStructureModel` required by [`CoordinatedStructureLine`].
///
/// The full `CoordinatedStructureModel` type will implement this trait when it is ported.
/// Defined here to avoid adding an unported dependency to `CoordinatedStructureLine`.
pub trait CoordinatedStructureModel {
    /// Rebuild the model's display after a state change.
    fn rebuild(&mut self);
    /// Report an error message to the model's error handler.
    fn error(&mut self, message: &str);
}

/// Base behaviour for a single display line that coordinates the left, right, and merged
/// views of a structure-merge operation.
///
/// Each line holds up to three [`ComparisonItem`] references — one per comparison pane.
/// Implementors supply read access to those items and mutable access to the backing model;
/// this trait provides the remaining behaviour (item dispatch, model notification, error
/// reporting) as default-method implementations.
///
/// This is the Rust equivalent of the abstract class
/// `ghidra.app.merge.structures.CoordinatedStructureLine`. Because Java abstract-class
/// equality relies on run-time dispatch that Rust trait objects do not support cleanly,
/// equality is left to each concrete implementor (`PartialEq` is not provided here).
pub trait CoordinatedStructureLine {
    /// Returns the left-pane comparison item, if one has been set.
    fn left(&self) -> Option<&dyn ComparisonItem>;
    /// Returns the right-pane comparison item, if one has been set.
    fn right(&self) -> Option<&dyn ComparisonItem>;
    /// Returns the merged-pane comparison item, if one has been set.
    fn merged(&self) -> Option<&dyn ComparisonItem>;
    /// Returns a mutable reference to the backing model.
    fn model_mut(&mut self) -> &mut dyn CoordinatedStructureModel;

    /// Returns the comparison item for the given pane.
    ///
    /// Both `CompareId::Merged` and any future variants default to the merged item,
    /// matching the `default:` arm of the Java `switch`.
    fn get_comparison_item(&self, id: CompareId) -> Option<&dyn ComparisonItem> {
        match id {
            CompareId::Left => self.left(),
            CompareId::Right => self.right(),
            CompareId::Merged => self.merged(),
        }
    }

    /// Notifies the backing model that this line's state has changed, triggering a rebuild.
    ///
    /// Mirrors `modelChanged`.
    fn model_changed(&mut self) {
        self.model_mut().rebuild();
    }

    /// Reports an error message to the backing model.
    ///
    /// Mirrors `error`.
    fn error(&mut self, message: &str) {
        self.model_mut().error(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── minimal test doubles ─────────────────────────────────────────────────────

    struct MockItem(i32);

    impl ComparisonItem for MockItem {
        fn line(&self) -> i32 {
            self.0
        }
        fn item_type(&self) -> &str {
            "mock"
        }
    }

    #[derive(Default)]
    struct MockModel {
        rebuild_count: usize,
        last_error: Option<String>,
    }

    impl CoordinatedStructureModel for MockModel {
        fn rebuild(&mut self) {
            self.rebuild_count += 1;
        }
        fn error(&mut self, message: &str) {
            self.last_error = Some(message.to_string());
        }
    }

    struct TestLine {
        left: Option<MockItem>,
        right: Option<MockItem>,
        merged: Option<MockItem>,
        model: MockModel,
    }

    impl TestLine {
        fn new(left: Option<i32>, right: Option<i32>, merged: Option<i32>) -> Self {
            Self {
                left: left.map(MockItem),
                right: right.map(MockItem),
                merged: merged.map(MockItem),
                model: MockModel::default(),
            }
        }
    }

    impl CoordinatedStructureLine for TestLine {
        fn left(&self) -> Option<&dyn ComparisonItem> {
            self.left.as_ref().map(|x| x as &dyn ComparisonItem)
        }
        fn right(&self) -> Option<&dyn ComparisonItem> {
            self.right.as_ref().map(|x| x as &dyn ComparisonItem)
        }
        fn merged(&self) -> Option<&dyn ComparisonItem> {
            self.merged.as_ref().map(|x| x as &dyn ComparisonItem)
        }
        fn model_mut(&mut self) -> &mut dyn CoordinatedStructureModel {
            &mut self.model
        }
    }

    // ── CompareId tests ──────────────────────────────────────────────────────────

    #[test]
    fn compare_id_variants_are_distinct() {
        assert_ne!(CompareId::Left, CompareId::Right);
        assert_ne!(CompareId::Left, CompareId::Merged);
        assert_ne!(CompareId::Right, CompareId::Merged);
    }

    #[test]
    fn compare_id_copy() {
        let id = CompareId::Left;
        let id2 = id;
        assert_eq!(id, id2);
    }

    // ── get_comparison_item routing ──────────────────────────────────────────────

    #[test]
    fn get_left_returns_left_item() {
        let line = TestLine::new(Some(1), Some(2), Some(3));
        assert_eq!(line.get_comparison_item(CompareId::Left).map(|i| i.line()), Some(1));
    }

    #[test]
    fn get_right_returns_right_item() {
        let line = TestLine::new(Some(1), Some(2), Some(3));
        assert_eq!(line.get_comparison_item(CompareId::Right).map(|i| i.line()), Some(2));
    }

    #[test]
    fn get_merged_returns_merged_item() {
        let line = TestLine::new(Some(1), Some(2), Some(3));
        assert_eq!(line.get_comparison_item(CompareId::Merged).map(|i| i.line()), Some(3));
    }

    #[test]
    fn get_left_returns_none_when_unset() {
        let line = TestLine::new(None, Some(2), Some(3));
        assert!(line.get_comparison_item(CompareId::Left).is_none());
    }

    #[test]
    fn get_right_returns_none_when_unset() {
        let line = TestLine::new(Some(1), None, Some(3));
        assert!(line.get_comparison_item(CompareId::Right).is_none());
    }

    #[test]
    fn get_merged_returns_none_when_unset() {
        let line = TestLine::new(Some(1), Some(2), None);
        assert!(line.get_comparison_item(CompareId::Merged).is_none());
    }

    // ── model_changed ────────────────────────────────────────────────────────────

    #[test]
    fn model_changed_calls_rebuild() {
        let mut line = TestLine::new(None, None, None);
        assert_eq!(line.model.rebuild_count, 0);
        line.model_changed();
        assert_eq!(line.model.rebuild_count, 1);
        line.model_changed();
        assert_eq!(line.model.rebuild_count, 2);
    }

    // ── error ────────────────────────────────────────────────────────────────────

    #[test]
    fn error_forwards_message_to_model() {
        let mut line = TestLine::new(None, None, None);
        assert!(line.model.last_error.is_none());
        line.error("something went wrong");
        assert_eq!(line.model.last_error.as_deref(), Some("something went wrong"));
    }

    #[test]
    fn error_overwrites_previous_error() {
        let mut line = TestLine::new(None, None, None);
        line.error("first");
        line.error("second");
        assert_eq!(line.model.last_error.as_deref(), Some("second"));
    }
}
