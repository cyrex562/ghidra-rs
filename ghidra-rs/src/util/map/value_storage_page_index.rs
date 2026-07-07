use crate::util::datastruct::RedBlackLongKeySet;

/// Used to find the property pages before and after a given property page.
///
/// Port of `ghidra.util.map.ValueStoragePageIndex`.
pub struct ValueStoragePageIndex {
    rbtree: RedBlackLongKeySet,
}

impl ValueStoragePageIndex {
    /// Creates a new empty ValueStoragePageIndex.
    pub fn new() -> Self {
        Self {
            rbtree: RedBlackLongKeySet::new(),
        }
    }

    /// Get the ID of the page after pageID.
    /// Returns -1 if there is no page after pageID.
    pub fn get_next(&self, page_id: i64) -> i64 {
        self.rbtree.get_next(page_id).unwrap_or(-1)
    }

    /// Get the number of pages in the table.
    pub fn get_num_pages(&self) -> usize {
        self.rbtree.size()
    }

    /// Get the ID of the page before pageID.
    /// Returns -1 if there is no page before pageID.
    pub fn get_previous(&self, page_id: i64) -> i64 {
        self.rbtree.get_previous(page_id).unwrap_or(-1)
    }

    /// Return whether the pageID exists in the table.
    pub fn has_page(&self, page_id: i64) -> bool {
        self.rbtree.contains_key(page_id)
    }

    /// Add the given pageID to the table.
    pub fn add(&mut self, page_id: i64) {
        self.rbtree.put(page_id);
    }

    /// Remove pageID from the table.
    /// Returns true if the pageID was removed.
    pub fn remove(&mut self, page_id: i64) -> bool {
        self.rbtree.remove(page_id)
    }
}

impl Default for ValueStoragePageIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let index = ValueStoragePageIndex::new();
        assert_eq!(index.get_num_pages(), 0);
    }

    #[test]
    fn default_is_empty() {
        let index = ValueStoragePageIndex::default();
        assert_eq!(index.get_num_pages(), 0);
    }

    #[test]
    fn add_single_page() {
        let mut index = ValueStoragePageIndex::new();
        index.add(42);
        assert_eq!(index.get_num_pages(), 1);
        assert!(index.has_page(42));
    }

    #[test]
    fn add_multiple_pages() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(20);
        index.add(30);
        assert_eq!(index.get_num_pages(), 3);
        assert!(index.has_page(10));
        assert!(index.has_page(20));
        assert!(index.has_page(30));
    }

    #[test]
    fn add_duplicate() {
        let mut index = ValueStoragePageIndex::new();
        index.add(42);
        index.add(42);
        assert_eq!(index.get_num_pages(), 1);
    }

    #[test]
    fn has_page_not_present() {
        let index = ValueStoragePageIndex::new();
        assert!(!index.has_page(42));
    }

    #[test]
    fn remove_existing_page() {
        let mut index = ValueStoragePageIndex::new();
        index.add(42);
        assert!(index.has_page(42));
        assert!(index.remove(42));
        assert!(!index.has_page(42));
        assert_eq!(index.get_num_pages(), 0);
    }

    #[test]
    fn remove_non_existing_page() {
        let mut index = ValueStoragePageIndex::new();
        assert!(!index.remove(42));
    }

    #[test]
    fn get_next_from_empty() {
        let index = ValueStoragePageIndex::new();
        assert_eq!(index.get_next(42), -1);
    }

    #[test]
    fn get_next_existing() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(20);
        index.add(30);
        assert_eq!(index.get_next(10), 20);
        assert_eq!(index.get_next(20), 30);
    }

    #[test]
    fn get_next_last() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(20);
        assert_eq!(index.get_next(20), -1);
    }

    #[test]
    fn get_next_between_values() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(30);
        assert_eq!(index.get_next(10), 30);
    }

    #[test]
    fn get_next_no_successor() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        assert_eq!(index.get_next(15), -1);
    }

    #[test]
    fn get_previous_from_empty() {
        let index = ValueStoragePageIndex::new();
        assert_eq!(index.get_previous(42), -1);
    }

    #[test]
    fn get_previous_existing() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(20);
        index.add(30);
        assert_eq!(index.get_previous(30), 20);
        assert_eq!(index.get_previous(20), 10);
    }

    #[test]
    fn get_previous_first() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(20);
        assert_eq!(index.get_previous(10), -1);
    }

    #[test]
    fn get_previous_between_values() {
        let mut index = ValueStoragePageIndex::new();
        index.add(10);
        index.add(30);
        assert_eq!(index.get_previous(30), 10);
    }

    #[test]
    fn get_previous_no_predecessor() {
        let mut index = ValueStoragePageIndex::new();
        index.add(30);
        assert_eq!(index.get_previous(20), -1);
    }

    #[test]
    fn alternating_operations() {
        let mut index = ValueStoragePageIndex::new();
        index.add(5);
        index.add(10);
        index.add(15);
        assert_eq!(index.get_num_pages(), 3);
        assert_eq!(index.get_next(5), 10);

        index.remove(10);
        assert_eq!(index.get_num_pages(), 2);
        assert_eq!(index.get_next(5), 15);
        assert_eq!(index.get_previous(15), 5);

        index.add(10);
        assert_eq!(index.get_num_pages(), 3);
        assert_eq!(index.get_next(5), 10);
    }
}
