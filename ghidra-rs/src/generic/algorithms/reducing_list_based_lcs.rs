use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::reducing_lcs::{ReducingLcs, ReducingLcsOps};

struct ListOps;

impl<T: PartialEq + Clone> ReducingLcsOps<Vec<T>, T> for ListOps {
    fn reduce(&self, i: &Vec<T>, start: usize, end: usize) -> Vec<T> {
        i[start..end].to_vec()
    }

    fn length_of(&self, i: &Vec<T>) -> usize {
        i.len()
    }

    fn value_of(&self, i: &Vec<T>, offset: usize) -> T {
        i[offset].clone()
    }

    fn matches(&self, x: &T, y: &T) -> bool {
        x == y
    }
}

/// An implementation of [`ReducingLcs`] that takes as its input a vector of items,
/// where the vector is the 'sequence' being checked for the Longest Common Subsequence.
pub struct ReducingListBasedLcs<T> {
    lcs: ReducingLcs<Vec<T>, T, ListOps>,
}

impl<T: PartialEq + Clone> ReducingListBasedLcs<T> {
    /// Creates a new instance with two input sequences.
    pub fn new(x: Vec<T>, y: Vec<T>) -> Self {
        Self {
            lcs: ReducingLcs::new(ListOps, x, y),
        }
    }

    /// Returns the longest common subsequence, re-attaching the shared prefix/suffix
    /// that were trimmed away before computing the reduced LCS.
    pub fn get_lcs(&self, monitor: &dyn TaskMonitor) -> Result<Vec<T>, CancelledException> {
        self.lcs.get_lcs(monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn test_identical_lists() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(vec![1, 2, 3, 4], vec![1, 2, 3, 4]);
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_similar_lists() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(
            vec!['A', 'B', 'C', 'D'],
            vec!['A', 'C', 'B', 'D'],
        );
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec!['A', 'B', 'D']);
    }

    #[test]
    fn test_different_lists() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(
            vec![1, 2, 3, 4, 5],
            vec![3, 4, 5, 6, 7],
        );
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec![3, 4, 5]);
    }

    #[test]
    fn test_empty_lists() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(vec![1, 2, 3], vec![]);
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_no_common_subsequence() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(vec![1, 2, 3], vec![4, 5, 6]);
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_list_with_duplicates() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(
            vec![1, 1, 2, 2, 3],
            vec![1, 2, 2, 3, 3],
        );
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec![1, 2, 2, 3]);
    }

    #[test]
    fn test_string_lists() {
        let monitor = DummyMonitor;
        let lcs = ReducingListBasedLcs::new(
            vec!["hello", "world", "rust"],
            vec!["hello", "beautiful", "rust"],
        );
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, vec!["hello", "rust"]);
    }

    #[test]
    fn test_insertion_only() {
        let monitor = DummyMonitor;
        let original = vec![1, 2, 3];
        let with_insertion = vec![1, 2, 99, 3];
        let lcs = ReducingListBasedLcs::new(original.clone(), with_insertion);
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_deletion_only() {
        let monitor = DummyMonitor;
        let original = vec![1, 2, 3, 4];
        let with_deletion = vec![1, 3, 4];
        let lcs = ReducingListBasedLcs::new(original, with_deletion.clone());
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result, with_deletion);
    }
}
