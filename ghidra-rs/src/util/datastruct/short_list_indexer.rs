const END_OF_LIST: i16 = -1;

/// Manages multiple linked lists of `i16` indexes backed by a shared pool.
///
/// Users can add indexes to a list, remove indexes from a list, remove all
/// indexes from a list, and retrieve all indexes within a given list.
#[derive(Debug, Clone)]
pub struct ShortListIndexer {
    heads: Vec<i16>,
    links: Vec<i16>,
    free_ptr: i16,
    size: i16,
    capacity: i16,
    num_lists: i16,
}

impl ShortListIndexer {
    /// Creates a new `ShortListIndexer` with `num_lists` lists and a pool of
    /// `capacity` index resources, all initially free.
    pub fn new(num_lists: i16, capacity: i16) -> Self {
        let mut indexer = Self {
            heads: vec![0; num_lists as usize],
            links: vec![0; capacity as usize],
            free_ptr: END_OF_LIST,
            size: 0,
            capacity,
            num_lists,
        };
        indexer.clear();
        indexer
    }

    /// Allocates a new index and prepends it to the list at `list_id`.
    ///
    /// Returns the new index, or `-1` if the pool is exhausted and cannot grow.
    ///
    /// # Panics
    ///
    /// Panics if `list_id` is not in `[0, num_lists)`.
    pub fn add(&mut self, list_id: i16) -> i16 {
        if list_id < 0 || list_id >= self.num_lists {
            panic!("list_id out of bounds: {list_id}");
        }
        let index = self.allocate();
        if index >= 0 {
            self.links[index as usize] = self.heads[list_id as usize];
            self.heads[list_id as usize] = index;
        }
        index
    }

    /// Allocates a new index and appends it to the end of the list at `list_id`.
    ///
    /// Returns the new index, or `-1` if the pool is exhausted and cannot grow.
    ///
    /// # Panics
    ///
    /// Panics if `list_id` is not in `[0, num_lists)`.
    pub fn append(&mut self, list_id: i16) -> i16 {
        if list_id < 0 || list_id >= self.num_lists {
            panic!("list_id out of bounds: {list_id}");
        }
        let index = self.allocate();
        if index >= 0 {
            if self.heads[list_id as usize] == END_OF_LIST {
                self.heads[list_id as usize] = index;
            } else {
                let mut p = self.heads[list_id as usize];
                while self.links[p as usize] != END_OF_LIST {
                    p = self.links[p as usize];
                }
                self.links[p as usize] = index;
            }
        }
        index
    }

    /// Removes the index resource at `index` from the linked list at `list_id`.
    ///
    /// If `index` is not in the list, this is a no-op.
    ///
    /// # Panics
    ///
    /// Panics if `list_id` is not in `[0, num_lists)`, or `index` is not in
    /// `[0, capacity)`.
    pub fn remove(&mut self, list_id: i16, index: i16) {
        if list_id < 0 || list_id >= self.num_lists {
            panic!("list_id out of bounds: {list_id}");
        }
        if index < 0 || index >= self.capacity {
            panic!("index out of bounds: {index}");
        }

        let head = self.heads[list_id as usize];
        if head == END_OF_LIST {
            return;
        }

        if head == index {
            let temp = self.links[head as usize];
            self.free_node(head);
            self.heads[list_id as usize] = temp;
            return;
        }

        let mut ptr = head;
        while self.links[ptr as usize] != END_OF_LIST {
            if self.links[ptr as usize] == index {
                self.links[ptr as usize] = self.links[index as usize];
                self.free_node(index);
                break;
            }
            ptr = self.links[ptr as usize];
        }
    }

    /// Removes all index resources from the linked list at `list_id`.
    pub fn remove_all(&mut self, list_id: i16) {
        let mut head = self.heads[list_id as usize];
        self.heads[list_id as usize] = END_OF_LIST;
        while head != END_OF_LIST {
            let temp = head;
            head = self.links[head as usize];
            self.free_node(temp);
        }
    }

    /// Returns the capacity that would result from the next automatic growth.
    ///
    /// Returns `-1` when the pool is already at `i16::MAX`.
    pub fn get_new_capacity(&self) -> i16 {
        if self.capacity == i16::MAX {
            return -1;
        }
        if self.capacity < i16::MAX / 2 {
            self.capacity * 2
        } else {
            i16::MAX
        }
    }

    /// Returns the number of index resources currently in use across all lists.
    pub fn get_size(&self) -> i16 {
        self.size
    }

    /// Returns the current size of the index resource pool.
    pub fn get_capacity(&self) -> i16 {
        self.capacity
    }

    /// Returns the number of linked lists being managed.
    pub fn get_num_lists(&self) -> i16 {
        self.num_lists
    }

    /// Returns the index that follows `index` in its linked list.
    ///
    /// Behavior is undefined if `index` is on the free list rather than in an
    /// active list (matches Java semantics).
    pub fn next(&self, index: i16) -> i16 {
        self.links[index as usize]
    }

    /// Returns the first index in the linked list at `list_id`, or `-1` if
    /// the list is empty.
    pub fn first(&self, list_id: i16) -> i16 {
        self.heads[list_id as usize]
    }

    /// Grows the index resource pool to `new_capacity`.
    ///
    /// New slots are linked onto the free list starting at the old capacity
    /// boundary. If `new_capacity` is not greater than the current capacity,
    /// this is a no-op.
    pub fn grow_capacity(&mut self, new_capacity: i16) {
        if new_capacity <= self.capacity {
            return;
        }
        let old_cap = self.capacity as usize;
        let new_cap = new_capacity as usize;
        self.links.resize(new_cap, 0);
        for i in old_cap..new_cap {
            self.links[i] = (i + 1) as i16;
        }
        self.links[new_cap - 1] = END_OF_LIST;
        self.free_ptr = self.capacity;
        self.capacity = new_capacity;
    }

    /// Grows the number of managed lists to `new_list_size`.
    ///
    /// New lists start empty. If `new_list_size` is not greater than the
    /// current count, this is a no-op.
    pub fn grow_num_lists(&mut self, new_list_size: i16) {
        if new_list_size <= self.num_lists {
            return;
        }
        self.heads.resize(new_list_size as usize, END_OF_LIST);
        self.num_lists = new_list_size;
    }

    /// Removes all indexes from all lists and resets the free list.
    pub fn clear(&mut self) {
        let cap = self.capacity as usize;
        for i in 0..cap {
            self.links[i] = (i + 1) as i16;
        }
        if cap > 0 {
            self.links[cap - 1] = END_OF_LIST;
            self.free_ptr = 0;
        } else {
            self.free_ptr = END_OF_LIST;
        }
        for h in self.heads.iter_mut() {
            *h = END_OF_LIST;
        }
        self.size = 0;
    }

    /// Returns the number of index resources in the list at `list_id`.
    ///
    /// # Panics
    ///
    /// Panics if `list_id` is not in `[0, num_lists)`.
    pub fn get_list_size(&self, list_id: i16) -> i32 {
        if list_id < 0 || list_id >= self.num_lists {
            panic!("list_id out of bounds: {list_id}");
        }
        let mut count = 0i32;
        let mut p = self.heads[list_id as usize];
        while p != END_OF_LIST {
            count += 1;
            p = self.links[p as usize];
        }
        count
    }

    fn allocate(&mut self) -> i16 {
        if self.free_ptr == END_OF_LIST {
            let new_cap = self.get_new_capacity();
            self.grow_capacity(new_cap);
            if self.free_ptr == END_OF_LIST {
                return END_OF_LIST;
            }
        }
        let p = self.free_ptr;
        self.free_ptr = self.links[p as usize];
        self.links[p as usize] = END_OF_LIST;
        self.size += 1;
        p
    }

    fn free_node(&mut self, p: i16) {
        self.size -= 1;
        self.links[p as usize] = self.free_ptr;
        self.free_ptr = p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let idx = ShortListIndexer::new(3, 10);
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get_capacity(), 10);
        assert_eq!(idx.get_num_lists(), 3);
        assert_eq!(idx.first(0), END_OF_LIST);
        assert_eq!(idx.first(1), END_OF_LIST);
        assert_eq!(idx.first(2), END_OF_LIST);
    }

    #[test]
    fn add_prepends_to_list() {
        let mut idx = ShortListIndexer::new(1, 10);
        let a = idx.add(0);
        let b = idx.add(0);
        let c = idx.add(0);
        assert_eq!(idx.first(0), c);
        assert_eq!(idx.next(c), b);
        assert_eq!(idx.next(b), a);
        assert_eq!(idx.next(a), END_OF_LIST);
        assert_eq!(idx.get_size(), 3);
    }

    #[test]
    fn append_adds_to_tail() {
        let mut idx = ShortListIndexer::new(1, 10);
        let a = idx.append(0);
        let b = idx.append(0);
        let c = idx.append(0);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.next(a), b);
        assert_eq!(idx.next(b), c);
        assert_eq!(idx.next(c), END_OF_LIST);
        assert_eq!(idx.get_size(), 3);
    }

    #[test]
    fn add_and_append_use_independent_lists() {
        let mut idx = ShortListIndexer::new(2, 10);
        let a = idx.add(0);
        let b = idx.append(1);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.first(1), b);
        assert_eq!(idx.get_size(), 2);
    }

    #[test]
    fn remove_head() {
        let mut idx = ShortListIndexer::new(1, 10);
        let a = idx.add(0);
        let b = idx.add(0); // b is head
        idx.remove(0, b);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn remove_middle() {
        let mut idx = ShortListIndexer::new(1, 10);
        let a = idx.append(0);
        let b = idx.append(0);
        let c = idx.append(0);
        idx.remove(0, b);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.next(a), c);
        assert_eq!(idx.next(c), END_OF_LIST);
        assert_eq!(idx.get_size(), 2);
    }

    #[test]
    fn remove_tail() {
        let mut idx = ShortListIndexer::new(1, 10);
        let a = idx.append(0);
        let b = idx.append(0);
        idx.remove(0, b);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.next(a), END_OF_LIST);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn remove_index_not_in_list_is_noop() {
        let mut idx = ShortListIndexer::new(2, 10);
        let a = idx.add(0);
        let b = idx.add(1); // b is in list 1, not list 0
        idx.remove(0, b);
        assert_eq!(idx.first(0), a);
        assert_eq!(idx.first(1), b);
        assert_eq!(idx.get_size(), 2);
    }

    #[test]
    fn remove_from_empty_list_is_noop() {
        let mut idx = ShortListIndexer::new(2, 10);
        let a = idx.add(0);
        idx.remove(1, a); // list 1 is empty
        assert_eq!(idx.get_size(), 1);
        assert_eq!(idx.first(0), a);
    }

    #[test]
    fn remove_all_empties_list_and_frees_resources() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.add(0);
        idx.add(0);
        idx.add(0);
        let b = idx.add(1);
        idx.remove_all(0);
        assert_eq!(idx.first(0), END_OF_LIST);
        assert_eq!(idx.get_size(), 1);
        assert_eq!(idx.first(1), b);
    }

    #[test]
    fn get_list_size_counts_items() {
        let mut idx = ShortListIndexer::new(2, 10);
        assert_eq!(idx.get_list_size(0), 0);
        idx.add(0);
        idx.add(0);
        idx.append(0);
        assert_eq!(idx.get_list_size(0), 3);
        assert_eq!(idx.get_list_size(1), 0);
    }

    #[test]
    fn clear_resets_all_lists_and_pool() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.add(0);
        idx.add(1);
        idx.clear();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.first(0), END_OF_LIST);
        assert_eq!(idx.first(1), END_OF_LIST);
        let a = idx.add(0);
        assert!(a >= 0);
    }

    #[test]
    fn get_new_capacity_doubles() {
        let idx = ShortListIndexer::new(1, 10);
        assert_eq!(idx.get_new_capacity(), 20);
    }

    #[test]
    fn get_new_capacity_at_max_returns_minus_one() {
        let mut idx = ShortListIndexer::new(1, 4);
        idx.capacity = i16::MAX;
        assert_eq!(idx.get_new_capacity(), -1);
    }

    #[test]
    fn get_new_capacity_near_max_returns_max() {
        let mut idx = ShortListIndexer::new(1, 4);
        idx.capacity = i16::MAX / 2; // 16383
        assert_eq!(idx.get_new_capacity(), i16::MAX);
    }

    #[test]
    fn grow_capacity_extends_pool() {
        let mut idx = ShortListIndexer::new(1, 2);
        let a = idx.add(0);
        let b = idx.add(0);
        assert_ne!(a, END_OF_LIST);
        assert_ne!(b, END_OF_LIST);
        idx.grow_capacity(10);
        assert_eq!(idx.get_capacity(), 10);
        let c = idx.add(0);
        assert_ne!(c, END_OF_LIST);
    }

    #[test]
    fn grow_capacity_noop_when_not_larger() {
        let mut idx = ShortListIndexer::new(1, 10);
        idx.grow_capacity(5);
        assert_eq!(idx.get_capacity(), 10);
    }

    #[test]
    fn grow_num_lists_extends_list_count() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.grow_num_lists(5);
        assert_eq!(idx.get_num_lists(), 5);
        assert_eq!(idx.first(2), END_OF_LIST);
        assert_eq!(idx.first(4), END_OF_LIST);
        let a = idx.add(4);
        assert_ne!(a, END_OF_LIST);
    }

    #[test]
    fn grow_num_lists_noop_when_not_larger() {
        let mut idx = ShortListIndexer::new(5, 10);
        idx.grow_num_lists(3);
        assert_eq!(idx.get_num_lists(), 5);
    }

    #[test]
    fn pool_auto_grows_when_exhausted() {
        let mut idx = ShortListIndexer::new(1, 2);
        let a = idx.add(0);
        let b = idx.add(0);
        assert_ne!(a, END_OF_LIST);
        assert_ne!(b, END_OF_LIST);
        let c = idx.add(0); // triggers auto-grow
        assert_ne!(c, END_OF_LIST);
        assert_eq!(idx.get_capacity(), 4);
    }

    #[test]
    fn freed_indexes_are_reused() {
        let mut idx = ShortListIndexer::new(1, 4);
        let a = idx.add(0);
        let _b = idx.add(0);
        idx.remove_all(0);
        let c = idx.add(0);
        assert!(c >= 0 && c < 4);
        assert!(c == a || c == _b);
    }

    #[test]
    fn multiple_clear_cycles() {
        let mut idx = ShortListIndexer::new(2, 4);
        for _ in 0..3 {
            idx.add(0);
            idx.add(0);
            idx.add(1);
            idx.clear();
            assert_eq!(idx.get_size(), 0);
            assert_eq!(idx.first(0), END_OF_LIST);
            assert_eq!(idx.first(1), END_OF_LIST);
        }
    }

    #[test]
    #[should_panic]
    fn add_invalid_list_id_panics() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.add(5);
    }

    #[test]
    #[should_panic]
    fn add_negative_list_id_panics() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.add(-1);
    }

    #[test]
    #[should_panic]
    fn append_invalid_list_id_panics() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.append(2);
    }

    #[test]
    #[should_panic]
    fn remove_invalid_list_id_panics() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.remove(5, 0);
    }

    #[test]
    #[should_panic]
    fn remove_negative_index_panics() {
        let mut idx = ShortListIndexer::new(2, 10);
        idx.remove(0, -1);
    }

    #[test]
    #[should_panic]
    fn get_list_size_invalid_list_id_panics() {
        let idx = ShortListIndexer::new(2, 10);
        idx.get_list_size(10);
    }
}
