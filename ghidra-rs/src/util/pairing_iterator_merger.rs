use std::cmp::Ordering;

/// Merges two sorted iterators, yielding `(L, R)` pairs for which `test` holds.
///
/// Both streams must be sorted according to `compare`. On each step, if `test(l, r)` is
/// false, `compare(l, r)` decides which stream to advance: advance `L` when `cmp <= 0`,
/// advance `R` when `cmp >= 0` (advancing both when `cmp == 0`). When `test` succeeds,
/// the pair is yielded and both streams advance to find the next match.
///
/// Port of `ghidra.util.PairingIteratorMerger`.
pub struct PairingIteratorMerger<L, R> {
    left: Box<dyn Iterator<Item = L>>,
    right: Box<dyn Iterator<Item = R>>,
    next_l: Option<L>,
    next_r: Option<R>,
    compare: Box<dyn Fn(&L, &R) -> Ordering>,
    test: Box<dyn Fn(&L, &R) -> bool>,
}

impl<L, R> PairingIteratorMerger<L, R> {
    /// Creates a merger from two sorted iterators.
    ///
    /// `compare(l, r)` establishes the shared ordering of both streams.
    /// `test(l, r)` decides whether `(l, r)` is a valid pair to yield.
    pub fn new<IL, IR, C, T>(left: IL, right: IR, compare: C, test: T) -> Self
    where
        IL: Iterator<Item = L> + 'static,
        IR: Iterator<Item = R> + 'static,
        C: Fn(&L, &R) -> Ordering + 'static,
        T: Fn(&L, &R) -> bool + 'static,
    {
        let mut merger = Self {
            left: Box::new(left),
            right: Box::new(right),
            next_l: None,
            next_r: None,
            compare: Box::new(compare),
            test: Box::new(test),
        };
        merger.find_next();
        merger
    }

    fn find_next(&mut self) {
        loop {
            if self.next_l.is_none() {
                self.next_l = self.left.next();
                if self.next_l.is_none() {
                    return;
                }
            }
            if self.next_r.is_none() {
                self.next_r = self.right.next();
                if self.next_r.is_none() {
                    return;
                }
            }
            let l = self.next_l.as_ref().unwrap();
            let r = self.next_r.as_ref().unwrap();
            if (self.test)(l, r) {
                return;
            }
            let cmp = (self.compare)(l, r);
            if cmp != Ordering::Greater {
                self.next_l = None;
            }
            if cmp != Ordering::Less {
                self.next_r = None;
            }
        }
    }
}

impl<L, R> Iterator for PairingIteratorMerger<L, R> {
    type Item = (L, R);

    fn next(&mut self) -> Option<(L, R)> {
        if self.next_l.is_none() || self.next_r.is_none() {
            return None;
        }
        let l = self.next_l.take().unwrap();
        let r = self.next_r.take().unwrap();
        self.find_next();
        Some((l, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair_equal(left: Vec<i32>, right: Vec<i32>) -> Vec<(i32, i32)> {
        PairingIteratorMerger::new(
            left.into_iter(),
            right.into_iter(),
            |l, r| l.cmp(r),
            |l, r| l == r,
        )
        .collect()
    }

    #[test]
    fn pairs_equal_elements() {
        assert_eq!(
            pair_equal(vec![1, 2, 3], vec![1, 2, 3]),
            vec![(1, 1), (2, 2), (3, 3)]
        );
    }

    #[test]
    fn skips_unmatched_left() {
        // left has extra elements not in right
        assert_eq!(
            pair_equal(vec![1, 2, 3, 4], vec![2, 4]),
            vec![(2, 2), (4, 4)]
        );
    }

    #[test]
    fn skips_unmatched_right() {
        // right has extra elements not in left
        assert_eq!(
            pair_equal(vec![2, 4], vec![1, 2, 3, 4]),
            vec![(2, 2), (4, 4)]
        );
    }

    #[test]
    fn empty_left_yields_nothing() {
        assert_eq!(pair_equal(vec![], vec![1, 2, 3]), vec![]);
    }

    #[test]
    fn empty_right_yields_nothing() {
        assert_eq!(pair_equal(vec![1, 2, 3], vec![]), vec![]);
    }

    #[test]
    fn both_empty_yields_nothing() {
        assert_eq!(pair_equal(vec![], vec![]), vec![]);
    }

    #[test]
    fn no_matches_yields_nothing() {
        assert_eq!(pair_equal(vec![1, 3, 5], vec![2, 4, 6]), vec![]);
    }

    #[test]
    fn single_match() {
        assert_eq!(pair_equal(vec![1, 2, 3], vec![2]), vec![(2, 2)]);
    }

    #[test]
    fn advances_both_after_match() {
        // After yielding (2,2), both advance so next check is (3,4): no match; 3<4 -> advance L
        // L exhausted -> done. Only one pair.
        assert_eq!(pair_equal(vec![2, 3], vec![2, 4]), vec![(2, 2)]);
    }

    #[test]
    fn custom_test_predicate() {
        // pair when left is even and right is odd and left/2 == right/2
        let result: Vec<(i32, i32)> = PairingIteratorMerger::new(
            vec![2, 4, 6].into_iter(),
            vec![3, 5, 7].into_iter(),
            |l: &i32, r: &i32| l.cmp(r),
            |l: &i32, r: &i32| r - l == 1,
        )
        .collect();
        assert_eq!(result, vec![(2, 3), (4, 5), (6, 7)]);
    }

    #[test]
    fn advance_when_compare_equal_but_test_fails() {
        // compare returns Equal but test fails -> both advance
        let result: Vec<(i32, i32)> = PairingIteratorMerger::new(
            vec![1, 2, 3].into_iter(),
            vec![1, 2, 3].into_iter(),
            |_l: &i32, _r: &i32| Ordering::Equal,
            |l: &i32, r: &i32| l == r && *l > 1,
        )
        .collect();
        // (1,1): test fails (1 not > 1), both advance; (2,2): test passes; yield.
        // Both advance -> (3,3): test passes; yield.
        assert_eq!(result, vec![(2, 2), (3, 3)]);
    }

    #[test]
    fn iterator_is_fused_after_exhaustion() {
        let mut merger = PairingIteratorMerger::new(
            vec![1].into_iter(),
            vec![1].into_iter(),
            |l: &i32, r: &i32| l.cmp(r),
            |l: &i32, r: &i32| l == r,
        );
        assert_eq!(merger.next(), Some((1, 1)));
        assert_eq!(merger.next(), None);
        assert_eq!(merger.next(), None);
    }
}
