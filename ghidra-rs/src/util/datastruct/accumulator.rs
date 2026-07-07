/// A receiver into which data can be placed as it is discovered during a search.
///
/// Unlike a method that returns a collected [`Vec`] only after all work is
/// done, an `Accumulator` is passed *into* a search routine so the caller can
/// observe results as they arrive without waiting for the full search to
/// complete.
///
/// Implementations that receive items from multiple threads must synchronize
/// their internal storage appropriately.
pub trait Accumulator<T> {
    /// Adds a single item to this accumulator.
    fn add(&mut self, item: T);

    /// Adds every item produced by `iter` to this accumulator.
    ///
    /// The default implementation calls [`add`](Self::add) for each item.
    fn add_all(&mut self, iter: impl IntoIterator<Item = T>) {
        for item in iter {
            self.add(item);
        }
    }

    /// Returns the number of items that have been added to this accumulator.
    fn get_progress(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecAccumulator<T> {
        items: Vec<T>,
    }

    impl<T> VecAccumulator<T> {
        fn new() -> Self {
            Self { items: Vec::new() }
        }
    }

    impl<T> Accumulator<T> for VecAccumulator<T> {
        fn add(&mut self, item: T) {
            self.items.push(item);
        }

        fn get_progress(&self) -> usize {
            self.items.len()
        }
    }

    #[test]
    fn add_single_increments_progress() {
        let mut acc: VecAccumulator<i32> = VecAccumulator::new();
        assert_eq!(acc.get_progress(), 0);
        acc.add(1);
        assert_eq!(acc.get_progress(), 1);
        acc.add(2);
        assert_eq!(acc.get_progress(), 2);
    }

    #[test]
    fn add_all_appends_each_item() {
        let mut acc = VecAccumulator::new();
        acc.add_all([10, 20, 30]);
        assert_eq!(acc.get_progress(), 3);
        assert_eq!(acc.items, vec![10, 20, 30]);
    }

    #[test]
    fn add_all_empty_iter_leaves_progress_unchanged() {
        let mut acc: VecAccumulator<i32> = VecAccumulator::new();
        acc.add_all(std::iter::empty());
        assert_eq!(acc.get_progress(), 0);
    }

    #[test]
    fn add_all_after_add_accumulates_all() {
        let mut acc = VecAccumulator::new();
        acc.add(0);
        acc.add_all([1, 2, 3]);
        assert_eq!(acc.get_progress(), 4);
        assert_eq!(acc.items, vec![0, 1, 2, 3]);
    }
}
