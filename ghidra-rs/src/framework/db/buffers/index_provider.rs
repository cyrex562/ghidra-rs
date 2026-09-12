//! Port of `db.buffers.IndexProvider`.
//!
//! Maintains the free index list associated with a `BufferFile`. This provider exhausts the
//! free index list before allocating new indexes. It relies on the associated `BufferFile`
//! growing automatically when buffers with indexes beyond the end-of-file are written.
//!
//! The Java class is package-private, concrete, and has no `extends` clause -- it is a plain
//! leaf data holder wrapping a counter and a `Stack<Integer>`. This is ported directly as a
//! struct; there is no inheritance to decouple via composition here.
//!
//! Java's `Stack<Integer>` (a `Vector` subclass used stack-style via `push`/`pop`) is modeled as
//! a plain `Vec<i32>`: `push` appends, `pop` removes from the end, and `get(i)`/iteration order
//! matches `Vec` indexing (index 0 is the bottom of the stack, pushed first).

/// Allocates and recycles buffer indexes for a `BufferFile`. Mirrors `db.buffers.IndexProvider`.
#[derive(Debug, Clone, Default)]
pub struct IndexProvider {
    next_index: i32,
    free_index_stack: Vec<i32>,
}

impl IndexProvider {
    /// Constructor for an empty `BufferFile`. Mirrors `IndexProvider()`.
    pub fn new() -> Self {
        Self { next_index: 0, free_index_stack: Vec::new() }
    }

    /// Constructor with initial state. Mirrors `IndexProvider(int, int[])`.
    ///
    /// # Parameters
    /// - `index_count`: previously allocated buffer count.
    /// - `free_indexes`: list of free buffer indexes.
    pub fn with_initial_state(index_count: i32, free_indexes: &[i32]) -> Self {
        let mut free_index_stack = Vec::with_capacity(free_indexes.len());
        for &index in free_indexes {
            free_index_stack.push(index);
        }
        Self { next_index: index_count, free_index_stack }
    }

    /// Returns the total number of buffer indexes which have been allocated. Mirrors
    /// `getIndexCount()`.
    pub fn get_index_count(&self) -> i32 {
        self.next_index
    }

    /// Returns the number of free indexes within the allocated index space. Mirrors
    /// `getFreeIndexCount()`.
    pub fn get_free_index_count(&self) -> usize {
        self.free_index_stack.len()
    }

    /// Allocates a new buffer index. Exhausts the free list before increasing the total index
    /// count. Mirrors `allocateIndex()`.
    pub fn allocate_index(&mut self) -> i32 {
        match self.free_index_stack.pop() {
            Some(index) => index,
            None => {
                let index = self.next_index;
                self.next_index += 1;
                index
            }
        }
    }

    /// Allocates a specific index. The current index count is adjusted if the specified index
    /// exceeds the current index count. Mirrors `allocateIndex(int)`.
    ///
    /// Returns true if the index was successfully allocated.
    pub fn allocate_index_at(&mut self, index: i32) -> bool {
        // Increase index count
        if index >= self.next_index {
            for i in self.next_index..index {
                self.free_index_stack.push(i);
            }
            self.next_index = index + 1;
            return true;
        }

        // Mirrors Vector.remove(Object): removes the first occurrence found while scanning from
        // the bottom of the stack (index 0) upward.
        if let Some(pos) = self.free_index_stack.iter().position(|&v| v == index) {
            self.free_index_stack.remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns true if the specified index is present in the free list. Mirrors `isFree(int)`.
    pub fn is_free(&self, index: i32) -> bool {
        self.free_index_stack.contains(&index)
    }

    /// Frees the specified buffer index. Mirrors `freeIndex(int)`.
    pub fn free_index(&mut self, index: i32) {
        self.free_index_stack.push(index);
    }

    /// Truncates this buffer file's index space. Has no effect if the specified `new_index_cnt`
    /// is greater than or equal to the current buffer count. Mirrors `truncate(int)`.
    ///
    /// Returns true if successful, false if `new_index_cnt` is larger than (or equal to) the
    /// current index count.
    pub fn truncate(&mut self, new_index_cnt: i32) -> bool {
        if new_index_cnt >= self.next_index {
            return false;
        }
        self.next_index = new_index_cnt;

        // Java removes lost free indexes by scanning from the top of the stack down to the
        // bottom, removing matching entries by position as it goes; because it always removes
        // at-or-below the current scan position while walking downward, no not-yet-visited
        // entry is ever shifted, so the relative order of survivors is unchanged. Filtering here
        // with `retain` produces the identical resulting order.
        self.free_index_stack.retain(|&free_index| free_index < new_index_cnt);
        true
    }

    /// Returns the current list of free indexes for this index provider, in the same order as
    /// the underlying stack (bottom to top). Mirrors `getFreeIndexes()`.
    pub fn get_free_indexes(&self) -> Vec<i32> {
        self.free_index_stack.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_provider_starts_empty() {
        let provider = IndexProvider::new();
        assert_eq!(provider.get_index_count(), 0);
        assert_eq!(provider.get_free_index_count(), 0);
        assert_eq!(provider.get_free_indexes(), Vec::<i32>::new());
    }

    #[test]
    fn with_initial_state_seeds_count_and_free_list_in_order() {
        let provider = IndexProvider::with_initial_state(10, &[3, 1, 7]);
        assert_eq!(provider.get_index_count(), 10);
        assert_eq!(provider.get_free_index_count(), 3);
        // Order mirrors the array order pushed onto the stack (bottom to top).
        assert_eq!(provider.get_free_indexes(), vec![3, 1, 7]);
    }

    #[test]
    fn allocate_index_exhausts_free_list_before_growing() {
        let mut provider = IndexProvider::with_initial_state(5, &[1, 2]);
        // LIFO: most recently pushed (2) comes back first.
        assert_eq!(provider.allocate_index(), 2);
        assert_eq!(provider.allocate_index(), 1);
        // Free list now exhausted; grows from next_index.
        assert_eq!(provider.allocate_index(), 5);
        assert_eq!(provider.allocate_index(), 6);
        assert_eq!(provider.get_index_count(), 7);
    }

    #[test]
    fn allocate_index_at_beyond_current_count_backfills_free_list() {
        let mut provider = IndexProvider::new();
        assert!(provider.allocate_index_at(3));
        // Indexes 0,1,2 should now be free; next_index becomes 4.
        assert_eq!(provider.get_index_count(), 4);
        assert_eq!(provider.get_free_indexes(), vec![0, 1, 2]);
    }

    #[test]
    fn allocate_index_at_within_free_list_removes_it() {
        let mut provider = IndexProvider::with_initial_state(5, &[0, 1, 2]);
        assert!(provider.allocate_index_at(1));
        assert_eq!(provider.get_free_indexes(), vec![0, 2]);
    }

    #[test]
    fn allocate_index_at_within_count_but_not_free_fails() {
        let mut provider = IndexProvider::with_initial_state(5, &[0, 2]);
        // Index 3 is within [0, next_index) but not present in the free list.
        assert!(!provider.allocate_index_at(3));
        assert_eq!(provider.get_free_indexes(), vec![0, 2]);
    }

    #[test]
    fn is_free_reflects_free_list_membership() {
        let provider = IndexProvider::with_initial_state(5, &[2, 4]);
        assert!(provider.is_free(2));
        assert!(provider.is_free(4));
        assert!(!provider.is_free(0));
    }

    #[test]
    fn free_index_pushes_onto_stack() {
        let mut provider = IndexProvider::new();
        provider.free_index(9);
        assert!(provider.is_free(9));
        assert_eq!(provider.get_free_indexes(), vec![9]);
    }

    #[test]
    fn truncate_rejects_new_count_at_or_above_current() {
        let mut provider = IndexProvider::with_initial_state(5, &[]);
        assert!(!provider.truncate(5));
        assert!(!provider.truncate(6));
        assert_eq!(provider.get_index_count(), 5);
    }

    #[test]
    fn truncate_shrinks_count_and_drops_out_of_range_free_indexes() {
        let mut provider = IndexProvider::with_initial_state(10, &[1, 8, 3, 9, 2]);
        assert!(provider.truncate(5));
        assert_eq!(provider.get_index_count(), 5);
        // Entries >= 5 (8, 9) are dropped; remaining survivors keep their relative order.
        assert_eq!(provider.get_free_indexes(), vec![1, 3, 2]);
    }

    #[test]
    fn allocate_index_then_free_index_round_trips() {
        let mut provider = IndexProvider::new();
        let index = provider.allocate_index();
        assert_eq!(index, 0);
        provider.free_index(index);
        assert_eq!(provider.allocate_index(), 0);
    }
}
