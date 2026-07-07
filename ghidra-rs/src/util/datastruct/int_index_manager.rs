/// Manages allocation and reuse of `i32` index values for arrays or tables.
///
/// Tracks a high-water mark and a free list of returned indices. Freed indices
/// are reused (LIFO) before the high-water mark is advanced.
#[derive(Debug, Clone, Default)]
pub struct IntIndexManager {
    next_index: i32,
    free_list: Vec<i32>,
}

impl IntIndexManager {
    /// Creates a new `IntIndexManager` with all indices available.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the smallest unused index value.
    ///
    /// Reuses freed indices before advancing the high-water mark.
    ///
    /// # Panics
    ///
    /// Panics when the index space is exhausted (i.e. `i32::MAX` indices have
    /// been allocated and none are free, causing the internal counter to wrap
    /// negative).
    pub fn allocate(&mut self) -> i32 {
        if let Some(index) = self.free_list.pop() {
            return index;
        }
        if self.next_index < 0 {
            panic!("IntIndexManager: index space exhausted");
        }
        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);
        index
    }

    /// Returns `index` to the pool so it can be reused.
    ///
    /// If `index` is the current high-water mark minus one, the mark is
    /// decremented rather than adding to the free list. When all allocated
    /// indices have been freed the manager resets to its initial state.
    ///
    /// # Panics
    ///
    /// Panics if `index` is negative or was never allocated (`index >= next_index`).
    pub fn deallocate(&mut self, index: i32) {
        if index < 0 || index >= self.next_index {
            panic!("IntIndexManager: index out of bounds: {index}");
        }
        if index == self.next_index - 1 {
            self.next_index -= 1;
        } else {
            self.free_list.push(index);
        }
        if self.next_index == self.free_list.len() as i32 {
            self.clear();
        }
    }

    /// Frees all index values and resets the manager to its initial state.
    pub fn clear(&mut self) {
        self.next_index = 0;
        self.free_list.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_sequential_indices() {
        let mut m = IntIndexManager::new();
        for i in 0..10 {
            assert_eq!(m.allocate(), i);
        }
    }

    #[test]
    fn deallocate_non_last_reuses_lifo() {
        let mut m = IntIndexManager::new();
        for _ in 0..10 {
            m.allocate();
        }
        // deallocate 5, 6, 7 – none are the current last (9)
        m.deallocate(5);
        m.deallocate(6);
        m.deallocate(7);
        // reallocate: free list pops LIFO (7, 6, 5)
        assert_eq!(m.allocate(), 7);
        assert_eq!(m.allocate(), 6);
        assert_eq!(m.allocate(), 5);
        // free list empty; high-water mark (10) is next
        assert_eq!(m.allocate(), 10);
    }

    #[test]
    fn deallocate_last_decrements_high_water() {
        let mut m = IntIndexManager::new();
        let i = m.allocate(); // 0
        m.deallocate(i);
        assert_eq!(m.allocate(), 0);
    }

    #[test]
    fn all_freed_triggers_reset() {
        let mut m = IntIndexManager::new();
        let a = m.allocate(); // 0
        let b = m.allocate(); // 1
        m.deallocate(a); // 0 goes to free list; next_index=2, free_list.len()=1 — no reset
        m.deallocate(b); // b==next_index-1, so next_index=1; now 1==free_list.len()==1 -> reset
        assert_eq!(m.allocate(), 0);
        assert_eq!(m.allocate(), 1);
    }

    #[test]
    fn explicit_clear_resets_state() {
        let mut m = IntIndexManager::new();
        m.allocate();
        m.allocate();
        m.clear();
        assert_eq!(m.allocate(), 0);
    }

    #[test]
    #[should_panic]
    fn deallocate_negative_panics() {
        let mut m = IntIndexManager::new();
        m.deallocate(-1);
    }

    #[test]
    #[should_panic]
    fn deallocate_unallocated_panics() {
        let mut m = IntIndexManager::new();
        m.deallocate(0);
    }

    #[test]
    #[should_panic]
    fn deallocate_above_high_water_panics() {
        let mut m = IntIndexManager::new();
        m.allocate(); // next_index becomes 1
        m.deallocate(5);
    }

    #[test]
    fn default_produces_fresh_manager() {
        let mut m = IntIndexManager::default();
        assert_eq!(m.allocate(), 0);
    }

    #[test]
    fn multiple_clear_cycles() {
        let mut m = IntIndexManager::new();
        for _ in 0..3 {
            for i in 0..5_i32 {
                assert_eq!(m.allocate(), i);
            }
            m.clear();
        }
    }
}
