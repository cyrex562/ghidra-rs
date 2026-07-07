use super::iterator_stl::IteratorStl;

/// Binary search for the first position where an element is >= key
///
/// Mirrors `generic.stl.Algorithms.lower_bound()` from Ghidra.
/// Iterates through elements starting from `start` until `end`, and returns
/// an iterator pointing to the first element where `element.cmp(&key) >= Ordering::Equal`,
/// or `end` if no such element is found.
pub fn lower_bound<T: Ord>(
    start: &mut dyn IteratorStl<T>,
    end: &dyn IteratorStl<T>,
    key: &T,
) -> Box<dyn IteratorStl<T>> {
    let mut cur = start.copy_iter();
    while !cur.is_end() {
        let elem = cur.get();
        if elem >= key {
            return cur;
        }
        cur.increment();
    }
    end.copy_iter()
}

/// Binary search for the first position where an element is > key
///
/// Mirrors `generic.stl.Algorithms.upper_bound()` from Ghidra.
/// Iterates through elements starting from `start` until `end`, and returns
/// an iterator pointing to the first element where `element.cmp(&key) > Ordering::Equal`,
/// or `end` if no such element is found.
pub fn upper_bound<T: Ord>(
    start: &mut dyn IteratorStl<T>,
    end: &dyn IteratorStl<T>,
    key: &T,
) -> Box<dyn IteratorStl<T>> {
    let mut cur = start.copy_iter();
    while !cur.is_end() {
        let elem = cur.get();
        if elem > key {
            return cur;
        }
        cur.increment();
    }
    end.copy_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIter {
        data: Vec<i32>,
        pos: usize,
    }

    impl TestIter {
        fn new(data: Vec<i32>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl IteratorStl<i32> for TestIter {
        fn get(&self) -> &i32 {
            &self.data[self.pos]
        }

        fn set(&mut self, value: i32) {
            self.data[self.pos] = value;
        }

        fn increment(&mut self) {
            if self.pos < self.data.len() {
                self.pos += 1;
            }
        }

        fn increment_by(&mut self, n: usize) {
            self.pos += n;
        }

        fn decrement(&mut self) {
            if self.pos > 0 {
                self.pos -= 1;
            }
        }

        fn decrement_by(&mut self, n: usize) {
            self.pos = self.pos.saturating_sub(n);
        }

        fn is_begin(&self) -> bool {
            self.pos == 0 && !self.data.is_empty()
        }

        fn is_end(&self) -> bool {
            self.pos >= self.data.len()
        }

        fn insert(&mut self, value: i32) {
            self.data.insert(self.pos, value);
        }

        fn copy_iter(&self) -> Box<dyn IteratorStl<i32>> {
            Box::new(TestIter {
                data: self.data.clone(),
                pos: self.pos,
            })
        }

        fn assign(&mut self, _other: &dyn IteratorStl<i32>) {
            unimplemented!("assign not used in algorithm tests")
        }
    }

    #[test]
    fn test_lower_bound_finds_equal() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = lower_bound(&mut start, &end, &5);
        assert_eq!(*result.get(), 5);
    }

    #[test]
    fn test_lower_bound_finds_greater() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = lower_bound(&mut start, &end, &4);
        assert_eq!(*result.get(), 5);
    }

    #[test]
    fn test_lower_bound_at_start() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = lower_bound(&mut start, &end, &1);
        assert_eq!(*result.get(), 1);
    }

    #[test]
    fn test_lower_bound_not_found() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let mut end = TestIter::new(data.clone());
        end.pos = data.len();

        let result = lower_bound(&mut start, &end, &10);
        assert!(result.is_end());
    }

    #[test]
    fn test_upper_bound_finds_greater() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = upper_bound(&mut start, &end, &5);
        assert_eq!(*result.get(), 7);
    }

    #[test]
    fn test_upper_bound_at_start() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = upper_bound(&mut start, &end, &0);
        assert_eq!(*result.get(), 1);
    }

    #[test]
    fn test_upper_bound_not_found() {
        let data = vec![1, 3, 5, 7, 9];
        let mut start = TestIter::new(data.clone());
        let mut end = TestIter::new(data.clone());
        end.pos = data.len();

        let result = upper_bound(&mut start, &end, &9);
        assert!(result.is_end());
    }

    #[test]
    fn test_upper_bound_empty_range() {
        let data = vec![];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = upper_bound(&mut start, &end, &5);
        assert!(result.is_end());
    }

    #[test]
    fn test_lower_bound_empty_range() {
        let data = vec![];
        let mut start = TestIter::new(data.clone());
        let end = TestIter::new(data.clone());

        let result = lower_bound(&mut start, &end, &5);
        assert!(result.is_end());
    }
}
