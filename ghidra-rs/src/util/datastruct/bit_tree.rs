use super::short_key_set::ShortKeySet;

/// An ordered set of `i16` keys in `[0, maxKey]`, backed by a binary tree
/// packed into bits of `i32` words.
///
/// Supports `O(log n)` add/remove/successor/predecessor queries and `O(1)`
/// membership tests. A bit at tree position `n` has children at `2*n` and
/// `2*n+1` and is "on" if any bit in its subtree is "on"; leaf bits (at
/// positions `power2..power2+size`) correspond directly to keys.
///
/// Port of `ghidra.util.datastruct.BitTree`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitTree {
    /// The maximum number of keys in the set; keys range from `0` to `size-1`.
    size: i32,
    /// The next power of 2 greater than or equal to `size`.
    power2: i32,
    /// Packed tree bits: a bit at position `n` has a left child at `2*n` and
    /// a right child at `2*n+1`, and its parent at `n/2`.
    bits: Vec<i32>,
    /// The current number of keys in the set.
    num_keys: i32,
}

impl BitTree {
    /// Creates a new, empty `BitTree` whose legal keys range from `0` to
    /// `max_key`.
    pub fn new(max_key: i16) -> Self {
        Self::with_full(max_key, false)
    }

    /// Creates a new `BitTree` whose legal keys range from `0` to `max_key`.
    /// If `is_full` is `true`, the set starts containing all legal keys.
    pub fn with_full(max_key: i16, is_full: bool) -> Self {
        let size = max_key as i32 + 1;

        // Find the next power of 2 greater than or equal to `size`.
        let mut power2 = 2i32;
        let mut sz = size;
        while sz > 1 {
            sz /= 2;
            power2 *= 2;
        }

        // 2x the number of keys worth of bits, packed into 32-bit words; at least 1 word.
        let n_ints = std::cmp::max(power2 / 16, 1) as usize;

        let mut bits = vec![0i32; n_ints];
        let mut num_keys = 0;
        if is_full {
            bits.iter_mut().for_each(|b| *b = -1); // 0xFFFFFFFF as i32
            num_keys = size;
        }

        Self { size, power2, bits, num_keys }
    }

    fn set_bit(&mut self, n: i32) -> bool {
        let int_index = (n >> 5) as usize;
        let mask_index = n & 0x1f;
        let old = self.bits[int_index];
        self.bits[int_index] |= 1i32 << mask_index;
        self.bits[int_index] != old
    }

    fn clear_bit(&mut self, n: i32) -> bool {
        let int_index = (n >> 5) as usize;
        let mask_index = n & 0x1f;
        let old = self.bits[int_index];
        self.bits[int_index] &= !(1i32 << mask_index);
        self.bits[int_index] != old
    }

    fn is_bit_set(&self, n: i32) -> bool {
        let int_index = (n >> 5) as usize;
        let mask_index = n & 0x1f;
        (self.bits[int_index] & (1i32 << mask_index)) != 0
    }

    fn check_key_range(&self, key: i16) {
        let key = key as i32;
        if key < 0 || key >= self.size {
            panic!("IndexOutOfBoundsException (Java parity): key {key} out of range [0, {})", self.size);
        }
    }
}

impl ShortKeySet for BitTree {
    fn size(&self) -> usize {
        self.num_keys as usize
    }

    fn is_empty(&self) -> bool {
        self.num_keys == 0
    }

    fn contains_key(&self, key: i16) -> bool {
        let key32 = key as i32;
        if key32 < 0 || key32 >= self.size {
            return false;
        }
        self.is_bit_set(self.power2 + key32)
    }

    fn get_first(&self) -> Option<i16> {
        if self.contains_key(0) {
            return Some(0);
        }
        self.get_next(0)
    }

    fn get_last(&self) -> Option<i16> {
        let last = (self.size - 1) as i16;
        if self.contains_key(last) {
            return Some(last);
        }
        self.get_previous(last)
    }

    fn put(&mut self, key: i16) {
        self.check_key_range(key);

        let mut node_index = self.power2 + key as i32;
        if !self.set_bit(node_index) {
            return;
        }
        self.num_keys += 1;

        while node_index != 1 {
            node_index /= 2;
            if !self.set_bit(node_index) {
                return;
            }
        }
    }

    fn remove(&mut self, key: i16) -> bool {
        self.check_key_range(key);

        let mut node_index = self.power2 + key as i32;
        if !self.clear_bit(node_index) {
            return false;
        }
        self.num_keys -= 1;

        while node_index != 1 {
            node_index /= 2;
            if !self.is_bit_set(node_index) {
                return true;
            }
            if self.is_bit_set(node_index * 2) || self.is_bit_set(node_index * 2 + 1) {
                return true;
            }
            self.clear_bit(node_index);
        }
        true
    }

    fn remove_all(&mut self) {
        self.bits.iter_mut().for_each(|b| *b = 0);
        self.num_keys = 0;
    }

    fn get_next(&self, key: i16) -> Option<i16> {
        self.check_key_range(key);

        let mut node_index = key as i32 + self.power2;
        while node_index != 1 {
            let odd = node_index % 2;
            if odd == 0 && self.is_bit_set(node_index + 1) {
                node_index += 1;
                break;
            }
            node_index /= 2;
        }

        if node_index == 1 {
            return None;
        }

        while node_index < self.power2 {
            node_index *= 2;
            if !self.is_bit_set(node_index) {
                node_index += 1;
            }
        }
        let next_key = node_index - self.power2;
        if next_key >= self.size {
            None
        } else {
            Some(next_key as i16)
        }
    }

    fn get_previous(&self, key: i16) -> Option<i16> {
        self.check_key_range(key);

        let mut node_index = key as i32 + self.power2;
        while node_index != 1 {
            let odd = node_index % 2;
            if odd == 1 && self.is_bit_set(node_index - 1) {
                node_index -= 1;
                break;
            }
            node_index /= 2;
        }

        if node_index == 1 {
            return None;
        }

        while node_index < self.power2 {
            node_index *= 2;
            if self.is_bit_set(node_index + 1) {
                node_index += 1;
            }
        }
        Some((node_index - self.power2) as i16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{self, AssertUnwindSafe};

    #[test]
    fn new_tree_is_empty() {
        let tree = BitTree::new(99);
        assert!(tree.is_empty());
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.get_first(), None);
        assert_eq!(tree.get_last(), None);
    }

    #[test]
    fn with_full_true_contains_every_key() {
        let tree = BitTree::with_full(9, true);
        assert_eq!(tree.size(), 10);
        for k in 0..10i16 {
            assert!(tree.contains_key(k), "expected key {k} to be present");
        }
        assert_eq!(tree.get_first(), Some(0));
        assert_eq!(tree.get_last(), Some(9));
    }

    #[test]
    fn put_and_contains_key() {
        let mut tree = BitTree::new(99);
        assert!(!tree.contains_key(5));
        tree.put(5);
        assert!(tree.contains_key(5));
        assert!(!tree.contains_key(4));
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn put_duplicate_does_not_increase_size() {
        let mut tree = BitTree::new(99);
        tree.put(10);
        tree.put(10);
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn remove_present_key_returns_true_and_removes() {
        let mut tree = BitTree::new(99);
        tree.put(7);
        assert!(tree.remove(7));
        assert!(!tree.contains_key(7));
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn remove_absent_key_returns_false() {
        let mut tree = BitTree::new(99);
        assert!(!tree.remove(42));
    }

    #[test]
    fn remove_all_clears_set() {
        let mut tree = BitTree::new(99);
        tree.put(1);
        tree.put(2);
        tree.put(3);
        tree.remove_all();
        assert!(tree.is_empty());
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn get_first_and_last() {
        let mut tree = BitTree::new(99);
        tree.put(10);
        tree.put(3);
        tree.put(7);
        assert_eq!(tree.get_first(), Some(3));
        assert_eq!(tree.get_last(), Some(10));
    }

    #[test]
    fn get_next_and_previous() {
        let mut tree = BitTree::new(99);
        tree.put(1);
        tree.put(3);
        tree.put(5);
        assert_eq!(tree.get_next(0), Some(1));
        assert_eq!(tree.get_next(1), Some(3));
        assert_eq!(tree.get_next(2), Some(3));
        assert_eq!(tree.get_next(5), None);

        assert_eq!(tree.get_previous(0), None);
        assert_eq!(tree.get_previous(1), None);
        assert_eq!(tree.get_previous(2), Some(1));
        assert_eq!(tree.get_previous(6), Some(5));
    }

    #[test]
    fn ascending_iteration_via_get_next() {
        let mut tree = BitTree::new(99);
        for k in [5i16, 1, 9, 3, 7] {
            tree.put(k);
        }
        let mut result = Vec::new();
        let mut cur = tree.get_first();
        while let Some(k) = cur {
            result.push(k);
            cur = tree.get_next(k);
        }
        assert_eq!(result, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn descending_iteration_via_get_previous() {
        let mut tree = BitTree::new(99);
        for k in [5i16, 1, 9, 3, 7] {
            tree.put(k);
        }
        let mut result = Vec::new();
        let mut cur = tree.get_last();
        while let Some(k) = cur {
            result.push(k);
            cur = tree.get_previous(k);
        }
        assert_eq!(result, vec![9, 7, 5, 3, 1]);
    }

    #[test]
    fn zero_key_is_valid() {
        let mut tree = BitTree::new(9);
        tree.put(0);
        assert!(tree.contains_key(0));
        assert_eq!(tree.get_first(), Some(0));
        assert_eq!(tree.get_previous(0), None);
    }

    #[test]
    fn max_key_boundary_is_valid() {
        let mut tree = BitTree::new(9);
        tree.put(9);
        assert!(tree.contains_key(9));
        assert_eq!(tree.get_last(), Some(9));
    }

    #[test]
    fn non_power_of_two_size_works() {
        // maxKey=9 -> size=10, which is not itself a power of 2 (forces power2=16 padding).
        let mut tree = BitTree::new(9);
        for k in 0..10i16 {
            tree.put(k);
        }
        assert_eq!(tree.size(), 10);
        assert_eq!(tree.get_last(), Some(9));
        assert_eq!(tree.get_next(9), None);
    }

    #[test]
    fn contains_key_out_of_range_returns_false_without_panicking() {
        let tree = BitTree::new(9);
        assert!(!tree.contains_key(-1));
        assert!(!tree.contains_key(100));
    }

    /// Java's `put`, `remove`, `getNext`, and `getPrevious` throw
    /// `IndexOutOfBoundsException` for a key outside `[0, size-1]`. Verify
    /// the panic happens specifically inside `put`, not merely somewhere in
    /// the test (per project convention for `should_panic` claims).
    #[test]
    fn put_out_of_range_key_panics() {
        let mut tree = BitTree::new(9);
        let result = panic::catch_unwind(AssertUnwindSafe(|| tree.put(100)));
        assert!(result.is_err());
    }

    #[test]
    fn get_next_out_of_range_key_panics() {
        let tree = BitTree::new(9);
        let result = panic::catch_unwind(AssertUnwindSafe(|| tree.get_next(-1)));
        assert!(result.is_err());
    }

    #[test]
    fn as_short_key_set_trait_object() {
        let mut tree: Box<dyn ShortKeySet> = Box::new(BitTree::new(9));
        tree.put(4);
        assert!(tree.contains_key(4));
        assert_eq!(tree.size(), 1);
    }
}
