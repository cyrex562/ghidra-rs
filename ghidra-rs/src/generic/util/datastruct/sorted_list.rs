use crate::generic::util::datastruct::value_sorted_map::LesserList;

/// An interface for sorted lists.
///
/// This might be better described as a NavigableMultiset; however, elements remain retrievable
/// by index, though insertion and mutation is not permitted by index. This implies that though
/// unordered, the underlying implementation has sorted the elements in some way and wishes to
/// expose that ordering to its clients.
///
/// Mirrors `ghidra.generic.util.datastruct.SortedList`.
pub trait SortedList<E>: LesserList<E> {
    /// Returns the greatest index in this list whose element is strictly less than `element`,
    /// or `-1`.
    fn lower_index(&self, element: &E) -> i64;

    /// Returns the greatest index in this list whose element is less than or equal to
    /// `element`, or `-1`.
    ///
    /// If multiples of the specified element exist, this returns the least index of that
    /// element.
    fn floor_index(&self, element: &E) -> i64;

    /// Returns the least index in this list whose element is greater than or equal to
    /// `element`, or `-1`.
    ///
    /// If multiples of the specified element exist, this returns the greatest index of that
    /// element.
    fn ceiling_index(&self, element: &E) -> i64;

    /// Returns the least index in this list whose element is strictly greater than `element`,
    /// or `-1`.
    fn higher_index(&self, element: &E) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ListIterator;

    /// A `SortedList<i32>` backed by an ascending, possibly-duplicate-laden `Vec`, just enough
    /// to prove `SortedList` is object-safe and that the "multiples" tie-breaking rules for
    /// `floor_index`/`ceiling_index` hold, not just trivial getters.
    struct VecSortedList {
        data: Vec<i32>,
    }

    impl LesserList<i32> for VecSortedList {
        fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        fn len(&self) -> usize {
            self.data.len()
        }

        fn get(&self, i: usize) -> &i32 {
            &self.data[i]
        }

        fn to_vec(&self) -> Vec<i32> {
            self.data.clone()
        }

        fn list_iterator(&self, _index: usize) -> Box<dyn ListIterator<i32> + '_> {
            unimplemented!("not exercised by the smoke test")
        }

        fn index_of(&self, o: &i32) -> i64 {
            self.data.iter().position(|x| x == o).map(|i| i as i64).unwrap_or(-1)
        }

        fn contains(&self, o: &i32) -> bool {
            self.data.contains(o)
        }

        fn poll(&mut self) -> Option<i32> {
            if self.data.is_empty() {
                None
            } else {
                Some(self.data.remove(0))
            }
        }

        fn remove(&mut self, o: &i32) -> bool {
            if let Some(pos) = self.data.iter().position(|x| x == o) {
                self.data.remove(pos);
                true
            } else {
                false
            }
        }
    }

    impl SortedList<i32> for VecSortedList {
        fn lower_index(&self, element: &i32) -> i64 {
            self.data.iter().rposition(|v| v < element).map(|i| i as i64).unwrap_or(-1)
        }

        fn floor_index(&self, element: &i32) -> i64 {
            match self.data.iter().rposition(|v| v <= element) {
                Some(pos) if self.data[pos] == *element => {
                    self.data.iter().position(|v| v == element).unwrap() as i64
                }
                Some(pos) => pos as i64,
                None => -1,
            }
        }

        fn ceiling_index(&self, element: &i32) -> i64 {
            match self.data.iter().position(|v| v >= element) {
                Some(pos) if self.data[pos] == *element => {
                    self.data.iter().rposition(|v| v == element).unwrap() as i64
                }
                Some(pos) => pos as i64,
                None => -1,
            }
        }

        fn higher_index(&self, element: &i32) -> i64 {
            self.data.iter().position(|v| v > element).map(|i| i as i64).unwrap_or(-1)
        }
    }

    fn build() -> VecSortedList {
        // Ascending, with a run of duplicate 20s at indices 2..=4.
        VecSortedList { data: vec![10, 15, 20, 20, 20, 25, 30] }
    }

    #[test]
    fn lower_index_finds_strictly_less() {
        let list = build();
        assert_eq!(list.lower_index(&20), 1);
        assert_eq!(list.lower_index(&10), -1);
        assert_eq!(list.lower_index(&100), 6);
    }

    #[test]
    fn floor_index_prefers_least_index_among_duplicates() {
        let list = build();
        // 20 has duplicates at 2,3,4 -- floor_index must return the least of those.
        assert_eq!(list.floor_index(&20), 2);
        // A value between duplicates and the next: no exact match, so the greatest <= wins.
        assert_eq!(list.floor_index(&22), 4);
        assert_eq!(list.floor_index(&5), -1);
    }

    #[test]
    fn ceiling_index_prefers_greatest_index_among_duplicates() {
        let list = build();
        // 20 has duplicates at 2,3,4 -- ceiling_index must return the greatest of those.
        assert_eq!(list.ceiling_index(&20), 4);
        // No exact match: the least index whose value is >= wins.
        assert_eq!(list.ceiling_index(&18), 2);
        assert_eq!(list.ceiling_index(&100), -1);
    }

    #[test]
    fn higher_index_finds_strictly_greater() {
        let list = build();
        assert_eq!(list.higher_index(&20), 5);
        assert_eq!(list.higher_index(&30), -1);
        assert_eq!(list.higher_index(&0), 0);
    }

    #[test]
    fn sorted_list_object_safety_and_lesser_list_supertrait() {
        let list: Box<dyn SortedList<i32>> = Box::new(build());
        assert_eq!(list.len(), 7);
        assert!(list.contains(&25));
        assert_eq!(list.floor_index(&20), 2);
    }
}
