use super::comparison_item::ComparisonItem;
use super::coordinated_structure_line::CompareId;

/// Data provider interface that [`StructDisplayModel`] uses to fetch comparison items.
///
/// This is the subset of `ghidra.app.merge.structures.CoordinatedStructureModel`
/// required by `StructDisplayModel`.  Items returned by [`get_data`] must be in
/// ascending line-number order so that [`StructDisplayModel::get_index`] can use
/// binary search.
///
/// [`get_data`]: StructDisplayDataProvider::get_data
pub trait StructDisplayDataProvider {
    /// Returns the ordered list of comparison items for the specified pane.
    fn get_data(&self, compare_id: CompareId) -> Vec<Box<dyn ComparisonItem>>;
}

/// Data model for one pane (left, right, or merged) in a coordinated structure
/// comparison display.
///
/// Caches the items from an upstream [`StructDisplayDataProvider`] for the given
/// [`CompareId`] pane and exposes indexed access plus a line-number binary search.
///
/// This is the Rust equivalent of `ghidra.app.merge.structures.StructDisplayModel`,
/// minus the Swing `AbstractListModel` machinery.  The Java change-listener callback
/// is replaced by an explicit [`refresh`] call that the owner invokes when upstream
/// data changes.
///
/// [`refresh`]: StructDisplayModel::refresh
pub struct StructDisplayModel {
    compare_id: CompareId,
    data: Vec<Box<dyn ComparisonItem>>,
}

impl StructDisplayModel {
    /// Creates a new model for the given `compare_id` pane, pre-populated from `provider`.
    pub fn new(provider: &dyn StructDisplayDataProvider, compare_id: CompareId) -> Self {
        let data = provider.get_data(compare_id);
        Self { compare_id, data }
    }

    /// Refreshes the cached item list from `provider`.
    ///
    /// Call this whenever the upstream model changes.  Replaces the Swing
    /// change-listener subscription (`model.addChangeListener(…)`) from the Java source.
    pub fn refresh(&mut self, provider: &dyn StructDisplayDataProvider) {
        self.data = provider.get_data(self.compare_id);
    }

    /// Returns the number of items in this pane's list.
    ///
    /// Mirrors `AbstractListModel.getSize()`.
    pub fn get_size(&self) -> usize {
        self.data.len()
    }

    /// Returns the comparison item at `index`, or `None` if `index` is out of range.
    ///
    /// Mirrors `AbstractListModel.getElementAt(int)`.
    pub fn get_element_at(&self, index: usize) -> Option<&dyn ComparisonItem> {
        self.data.get(index).map(|b| b.as_ref())
    }

    /// Returns the list index of the item whose line number matches `item.line()`.
    ///
    /// Uses binary search on the cached data (which is sorted by line number).
    /// Returns `-1` when `item` is `None` or when no item with that line number
    /// exists.  A non-negative result is the zero-based index of the matching item.
    ///
    /// Mirrors `StructDisplayModel.getIndex(ComparisonItem)`.
    pub fn get_index(&self, item: Option<&dyn ComparisonItem>) -> i32 {
        let Some(item) = item else { return -1; };
        let target = item.line();
        match self.data.binary_search_by_key(&target, |i| i.line()) {
            Ok(idx) => idx as i32,
            Err(_) => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── test doubles ─────────────────────────────────────────────────────────────

    struct TestItem {
        line: i32,
    }

    impl ComparisonItem for TestItem {
        fn line(&self) -> i32 {
            self.line
        }
        fn item_type(&self) -> &str {
            "test"
        }
    }

    fn item(line: i32) -> Box<dyn ComparisonItem> {
        Box::new(TestItem { line })
    }

    struct TestProvider {
        left: Vec<i32>,
        right: Vec<i32>,
        merged: Vec<i32>,
    }

    impl TestProvider {
        fn new(left: Vec<i32>, right: Vec<i32>, merged: Vec<i32>) -> Self {
            Self { left, right, merged }
        }
    }

    impl StructDisplayDataProvider for TestProvider {
        fn get_data(&self, compare_id: CompareId) -> Vec<Box<dyn ComparisonItem>> {
            let lines = match compare_id {
                CompareId::Left => &self.left,
                CompareId::Right => &self.right,
                CompareId::Merged => &self.merged,
            };
            lines.iter().map(|&l| item(l)).collect()
        }
    }

    // ── new / constructor ─────────────────────────────────────────────────────────

    #[test]
    fn new_populates_data_for_correct_pane() {
        let provider = TestProvider::new(vec![1, 2, 3], vec![10, 20], vec![100]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert_eq!(model.get_size(), 3);
    }

    #[test]
    fn new_selects_right_pane() {
        let provider = TestProvider::new(vec![1], vec![10, 20, 30], vec![100]);
        let model = StructDisplayModel::new(&provider, CompareId::Right);
        assert_eq!(model.get_size(), 3);
        assert_eq!(model.get_element_at(0).map(|i| i.line()), Some(10));
    }

    #[test]
    fn new_selects_merged_pane() {
        let provider = TestProvider::new(vec![1], vec![10], vec![100, 200]);
        let model = StructDisplayModel::new(&provider, CompareId::Merged);
        assert_eq!(model.get_size(), 2);
        assert_eq!(model.get_element_at(1).map(|i| i.line()), Some(200));
    }

    #[test]
    fn new_with_empty_pane() {
        let provider = TestProvider::new(vec![], vec![1], vec![2]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert_eq!(model.get_size(), 0);
    }

    // ── refresh ───────────────────────────────────────────────────────────────────

    #[test]
    fn refresh_updates_data() {
        let provider1 = TestProvider::new(vec![1, 2], vec![], vec![]);
        let mut model = StructDisplayModel::new(&provider1, CompareId::Left);
        assert_eq!(model.get_size(), 2);

        let provider2 = TestProvider::new(vec![1, 2, 3, 4], vec![], vec![]);
        model.refresh(&provider2);
        assert_eq!(model.get_size(), 4);
    }

    #[test]
    fn refresh_uses_original_compare_id() {
        let provider = TestProvider::new(vec![1, 2], vec![10, 20, 30], vec![]);
        let mut model = StructDisplayModel::new(&provider, CompareId::Right);
        assert_eq!(model.get_size(), 3);

        let provider2 = TestProvider::new(vec![1], vec![10], vec![100]);
        model.refresh(&provider2);
        // compare_id is still Right
        assert_eq!(model.get_size(), 1);
        assert_eq!(model.get_element_at(0).map(|i| i.line()), Some(10));
    }

    // ── get_size ──────────────────────────────────────────────────────────────────

    #[test]
    fn get_size_returns_item_count() {
        let provider = TestProvider::new(vec![1, 2, 3, 4, 5], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert_eq!(model.get_size(), 5);
    }

    #[test]
    fn get_size_zero_for_empty() {
        let provider = TestProvider::new(vec![], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Merged);
        assert_eq!(model.get_size(), 0);
    }

    // ── get_element_at ────────────────────────────────────────────────────────────

    #[test]
    fn get_element_at_returns_items_in_order() {
        let provider = TestProvider::new(vec![5, 10, 15], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert_eq!(model.get_element_at(0).map(|i| i.line()), Some(5));
        assert_eq!(model.get_element_at(1).map(|i| i.line()), Some(10));
        assert_eq!(model.get_element_at(2).map(|i| i.line()), Some(15));
    }

    #[test]
    fn get_element_at_out_of_range_returns_none() {
        let provider = TestProvider::new(vec![1, 2], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert!(model.get_element_at(2).is_none());
        assert!(model.get_element_at(100).is_none());
    }

    #[test]
    fn get_element_at_empty_model_returns_none() {
        let provider = TestProvider::new(vec![], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert!(model.get_element_at(0).is_none());
    }

    // ── get_index ─────────────────────────────────────────────────────────────────

    #[test]
    fn get_index_returns_negative_one_for_none() {
        let provider = TestProvider::new(vec![1, 2, 3], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        assert_eq!(model.get_index(None), -1);
    }

    #[test]
    fn get_index_finds_first_item() {
        let provider = TestProvider::new(vec![5, 10, 15], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        let needle = TestItem { line: 5 };
        assert_eq!(model.get_index(Some(&needle)), 0);
    }

    #[test]
    fn get_index_finds_middle_item() {
        let provider = TestProvider::new(vec![5, 10, 15], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        let needle = TestItem { line: 10 };
        assert_eq!(model.get_index(Some(&needle)), 1);
    }

    #[test]
    fn get_index_finds_last_item() {
        let provider = TestProvider::new(vec![5, 10, 15], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        let needle = TestItem { line: 15 };
        assert_eq!(model.get_index(Some(&needle)), 2);
    }

    #[test]
    fn get_index_returns_negative_one_when_not_found() {
        let provider = TestProvider::new(vec![5, 10, 15], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        let needle = TestItem { line: 7 };
        assert_eq!(model.get_index(Some(&needle)), -1);
    }

    #[test]
    fn get_index_on_empty_model_returns_negative_one() {
        let provider = TestProvider::new(vec![], vec![], vec![]);
        let model = StructDisplayModel::new(&provider, CompareId::Left);
        let needle = TestItem { line: 1 };
        assert_eq!(model.get_index(Some(&needle)), -1);
    }
}
