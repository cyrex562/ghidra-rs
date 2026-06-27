/// Iterates multiple sorted arrays of comparable items simultaneously.
///
/// At each [`Iterator::next`] call the iterator finds the overall minimum (or maximum
/// when going backward) value across the current head of every input array and returns
/// one slot per input array: `Some(value)` when that array's head matched the extremum,
/// `None` otherwise.
///
/// All input arrays must be sorted in ascending order before being passed to the
/// constructor.
pub struct MultiComparableArrayIterator<T: Ord + Clone> {
    comp_arrays: Vec<Vec<T>>,
    /// One-element lookahead buffer per input array.
    comps: Vec<Option<T>>,
    /// Current index into each array.  `i64` so backward iteration can safely reach -1
    /// without underflow, mirroring the Java source's signed `int` semantics.
    indices: Vec<i64>,
    forward: bool,
}

impl<T: Ord + Clone> MultiComparableArrayIterator<T> {
    /// Creates a forward (min → max) iterator over `arrays`.
    pub fn new(arrays: Vec<Vec<T>>) -> Self {
        Self::with_direction(arrays, true)
    }

    /// Creates an iterator over `arrays`.
    ///
    /// `forward = true` returns items from min to max; `false` returns max to min.
    /// Every input array must be sorted in ascending order regardless of direction.
    pub fn with_direction(arrays: Vec<Vec<T>>, forward: bool) -> Self {
        let n = arrays.len();
        let indices: Vec<i64> = if forward {
            vec![0; n]
        } else {
            arrays.iter().map(|a| a.len() as i64 - 1).collect()
        };
        Self {
            comp_arrays: arrays,
            comps: vec![None; n],
            indices,
            forward,
        }
    }

    /// Returns `true` if any input array still has a remaining element.
    pub fn has_next(&self) -> bool {
        for i in 0..self.comp_arrays.len() {
            let idx = self.indices[i];
            if idx >= 0 && (idx as usize) < self.comp_arrays[i].len() {
                return true;
            }
        }
        false
    }
}

impl<T: Ord + Clone> Iterator for MultiComparableArrayIterator<T> {
    /// Each item is a `Vec` with one slot per input array.  A slot holds `Some(value)`
    /// when that array's current head equalled the overall extremum, `None` otherwise.
    type Item = Vec<Option<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.has_next() {
            return None;
        }

        let n = self.comp_arrays.len();

        // Fill the lookahead buffer for any array that hasn't been peeked yet.
        for i in 0..n {
            if self.comps[i].is_none() {
                let idx = self.indices[i];
                if idx >= 0 && (idx as usize) < self.comp_arrays[i].len() {
                    self.comps[i] = Some(self.comp_arrays[i][idx as usize].clone());
                }
            }
        }

        // Find the overall minimum (forward) or maximum (backward).
        let mut comp_next: Option<T> = None;
        let mut is_next = vec![false; n];

        for i in 0..n {
            let Some(val) = &self.comps[i] else {
                continue;
            };
            match &comp_next {
                None => {
                    comp_next = Some(val.clone());
                    is_next[i] = true;
                }
                Some(cur) => match cur.cmp(val) {
                    std::cmp::Ordering::Equal => {
                        is_next[i] = true;
                    }
                    std::cmp::Ordering::Greater if self.forward => {
                        comp_next = Some(val.clone());
                        is_next[..i].fill(false);
                        is_next[i] = true;
                    }
                    std::cmp::Ordering::Less if !self.forward => {
                        comp_next = Some(val.clone());
                        is_next[..i].fill(false);
                        is_next[i] = true;
                    }
                    _ => {}
                },
            }
        }

        // Build the result and advance indices for contributing arrays.
        let mut result = vec![None; n];
        for i in 0..n {
            if is_next[i] {
                result[i] = self.comps[i].take();
                if self.forward {
                    self.indices[i] += 1;
                } else {
                    self.indices[i] -= 1;
                }
            }
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_arrays_yield_nothing() {
        let mut iter = MultiComparableArrayIterator::<i32>::new(vec![vec![], vec![]]);
        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn single_array() {
        let mut iter = MultiComparableArrayIterator::new(vec![vec![1, 3, 5]]);
        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(vec![Some(1)]));
        assert_eq!(iter.next(), Some(vec![Some(3)]));
        assert_eq!(iter.next(), Some(vec![Some(5)]));
        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn two_arrays_no_overlap() {
        // a: [1, 3], b: [2, 4]
        let mut iter = MultiComparableArrayIterator::new(vec![vec![1, 3], vec![2, 4]]);

        assert_eq!(iter.next(), Some(vec![Some(1), None]));
        assert_eq!(iter.next(), Some(vec![None, Some(2)]));
        assert_eq!(iter.next(), Some(vec![Some(3), None]));
        assert_eq!(iter.next(), Some(vec![None, Some(4)]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn two_arrays_with_overlap() {
        // a: [1, 2, 4], b: [2, 3]  — value 2 appears in both
        let mut iter = MultiComparableArrayIterator::new(vec![vec![1, 2, 4], vec![2, 3]]);

        assert_eq!(iter.next(), Some(vec![Some(1), None]));
        assert_eq!(iter.next(), Some(vec![Some(2), Some(2)]));
        assert_eq!(iter.next(), Some(vec![None, Some(3)]));
        assert_eq!(iter.next(), Some(vec![Some(4), None]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn three_arrays_forward() {
        let a = vec![1, 3, 5];
        let b = vec![2, 3, 6];
        let c = vec![1, 4, 5];
        let mut iter = MultiComparableArrayIterator::new(vec![a, b, c]);

        // min=1 from a and c
        assert_eq!(iter.next(), Some(vec![Some(1), None, Some(1)]));
        // min=2 from b
        assert_eq!(iter.next(), Some(vec![None, Some(2), None]));
        // min=3 from a and b
        assert_eq!(iter.next(), Some(vec![Some(3), Some(3), None]));
        // min=4 from c
        assert_eq!(iter.next(), Some(vec![None, None, Some(4)]));
        // min=5 from a and c
        assert_eq!(iter.next(), Some(vec![Some(5), None, Some(5)]));
        // min=6 from b
        assert_eq!(iter.next(), Some(vec![None, Some(6), None]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn backward_two_arrays() {
        // a: [1, 3], b: [2, 4] — backward means max first
        let mut iter =
            MultiComparableArrayIterator::with_direction(vec![vec![1, 3], vec![2, 4]], false);

        assert_eq!(iter.next(), Some(vec![None, Some(4)]));
        assert_eq!(iter.next(), Some(vec![Some(3), None]));
        assert_eq!(iter.next(), Some(vec![None, Some(2)]));
        assert_eq!(iter.next(), Some(vec![Some(1), None]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn backward_with_shared_values() {
        // a: [1, 3, 5], b: [3, 5, 7]
        let mut iter =
            MultiComparableArrayIterator::with_direction(vec![vec![1, 3, 5], vec![3, 5, 7]], false);

        assert_eq!(iter.next(), Some(vec![None, Some(7)]));
        assert_eq!(iter.next(), Some(vec![Some(5), Some(5)]));
        assert_eq!(iter.next(), Some(vec![Some(3), Some(3)]));
        assert_eq!(iter.next(), Some(vec![Some(1), None]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn one_empty_one_nonempty() {
        let mut iter = MultiComparableArrayIterator::new(vec![vec![], vec![5, 10]]);
        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(vec![None, Some(5)]));
        assert_eq!(iter.next(), Some(vec![None, Some(10)]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn iterator_collect() {
        let iter = MultiComparableArrayIterator::new(vec![vec![10, 20], vec![15, 25]]);
        let all: Vec<_> = iter.collect();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0], vec![Some(10), None]);
        assert_eq!(all[1], vec![None, Some(15)]);
        assert_eq!(all[2], vec![Some(20), None]);
        assert_eq!(all[3], vec![None, Some(25)]);
    }

    #[test]
    fn strings() {
        let a = vec!["apple".to_string(), "cherry".to_string()];
        let b = vec!["banana".to_string(), "cherry".to_string()];
        let mut iter = MultiComparableArrayIterator::new(vec![a, b]);

        assert_eq!(
            iter.next(),
            Some(vec![Some("apple".to_string()), None])
        );
        assert_eq!(
            iter.next(),
            Some(vec![None, Some("banana".to_string())])
        );
        assert_eq!(
            iter.next(),
            Some(vec![
                Some("cherry".to_string()),
                Some("cherry".to_string())
            ])
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn all_arrays_same_single_element() {
        let mut iter =
            MultiComparableArrayIterator::new(vec![vec![42], vec![42], vec![42]]);
        assert_eq!(iter.next(), Some(vec![Some(42), Some(42), Some(42)]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn backward_single_element_arrays() {
        let mut iter = MultiComparableArrayIterator::with_direction(
            vec![vec![1], vec![2], vec![3]],
            false,
        );
        assert_eq!(iter.next(), Some(vec![None, None, Some(3)]));
        assert_eq!(iter.next(), Some(vec![None, Some(2), None]));
        assert_eq!(iter.next(), Some(vec![Some(1), None, None]));
        assert_eq!(iter.next(), None);
    }
}
