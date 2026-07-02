use super::Accumulator;

/// A wrapper around an accumulator that restricts the maximum number of items that can be added.
///
/// This wrapper enforces a size limit on the wrapped accumulator. When an item is added
/// that would exceed the limit, a panic is raised with an [`AccumulatorSizeException`].
///
/// Port of `ghidra.util.datastruct.SizeRestrictedAccumulatorWrapper`.
pub struct SizeRestrictedAccumulatorWrapper<T, A: Accumulator<T>> {
    accumulator: A,
    max_size: usize,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, A: Accumulator<T>> SizeRestrictedAccumulatorWrapper<T, A> {
    /// Creates a new size-restricted accumulator wrapper.
    ///
    /// # Arguments
    ///
    /// * `accumulator` - the accumulator to pass items to
    /// * `max_size` - the maximum number of items this accumulator will hold
    pub fn new(accumulator: A, max_size: usize) -> Self {
        Self {
            accumulator,
            max_size,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T, A: Accumulator<T>> Accumulator<T> for SizeRestrictedAccumulatorWrapper<T, A> {
    fn add(&mut self, item: T) {
        if self.accumulator.get_progress() >= self.max_size {
            panic!("Maximum capacity exceeded: {}", self.max_size);
        }
        self.accumulator.add(item);
    }

    fn add_all(&mut self, iter: impl IntoIterator<Item = T>) {
        for item in iter {
            self.add(item);
        }
    }

    fn get_progress(&self) -> usize {
        self.accumulator.get_progress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAccumulator {
        items: Vec<i32>,
    }

    impl TestAccumulator {
        fn new() -> Self {
            Self { items: Vec::new() }
        }
    }

    impl Accumulator<i32> for TestAccumulator {
        fn add(&mut self, item: i32) {
            self.items.push(item);
        }

        fn get_progress(&self) -> usize {
            self.items.len()
        }
    }

    #[test]
    fn new_wrapper_empty() {
        let inner = TestAccumulator::new();
        let wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 5);
        assert_eq!(wrapper.get_progress(), 0);
    }

    #[test]
    fn add_single_item_within_limit() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 5);
        wrapper.add(42);
        assert_eq!(wrapper.get_progress(), 1);
    }

    #[test]
    fn add_multiple_items_within_limit() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 5);
        for i in 1..=3 {
            wrapper.add(i);
        }
        assert_eq!(wrapper.get_progress(), 3);
    }

    #[test]
    fn add_at_limit_succeeds() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 3);
        wrapper.add(1);
        wrapper.add(2);
        wrapper.add(3);
        assert_eq!(wrapper.get_progress(), 3);
    }

    #[test]
    #[should_panic(expected = "Maximum capacity exceeded: 2")]
    fn add_exceeding_limit_panics() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 2);
        wrapper.add(1);
        wrapper.add(2);
        wrapper.add(3);
    }

    #[test]
    fn add_all_within_limit() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 10);
        wrapper.add_all(vec![1, 2, 3, 4, 5]);
        assert_eq!(wrapper.get_progress(), 5);
    }

    #[test]
    fn add_all_exactly_at_limit() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 3);
        wrapper.add_all(vec![1, 2, 3]);
        assert_eq!(wrapper.get_progress(), 3);
    }

    #[test]
    #[should_panic(expected = "Maximum capacity exceeded: 3")]
    fn add_all_exceeding_limit_panics() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 3);
        wrapper.add_all(vec![1, 2, 3, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "Maximum capacity exceeded: 3")]
    fn add_all_partial_exceeds_limit() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 3);
        wrapper.add(1);
        wrapper.add(2);
        wrapper.add_all(vec![3, 4]);
    }

    #[test]
    fn add_all_empty_succeeds() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 5);
        wrapper.add_all(std::iter::empty());
        assert_eq!(wrapper.get_progress(), 0);
    }

    #[test]
    #[should_panic(expected = "Maximum capacity exceeded: 0")]
    fn max_size_zero() {
        let inner = TestAccumulator::new();
        let mut wrapper = SizeRestrictedAccumulatorWrapper::new(inner, 0);
        wrapper.add(42);
    }
}
