//! Internal cursor helpers shared by this module's `Table`-backed, address-ordered iterators
//! (`AddressKeyIterator`, `AddressKeyRecordIterator`, `AddressIndexPrimaryKeyIterator`,
//! `AddressIndexKeyIterator`). **Not itself a port of a Java class.**
//!
//! Java's versions of these iterators crawl a live B-tree cursor (`db.Table`'s
//! `longKeyIterator`/`indexKeyIterator`/`indexFieldIterator`/`iterator(min,max,start)`),
//! re-deriving cursor state range-by-range as `keyRangeList` is exhausted, because re-scanning
//! the whole table on every construction would be expensive against a real on-disk B-tree. This
//! port's `Table` has no such cursor primitives (its own `get_record_iterator` is already a full
//! linear scan -- see `CompositeDBAdapterV5V6`'s doc comments for the established precedent of
//! scanning instead of indexing), so there is no efficiency to preserve by mimicking the
//! range-by-range crawl. Instead, each iterator takes a single eager snapshot of every matching
//! key (or index entry) across *all* of its `KeyRange`s at once, already sorted, and drives it
//! with the [`Cursor`] "gap" position below -- observably identical to Java's per-range crawl
//! (both ultimately visit the same keys, in the same order), just simpler to get right.
//!
//! [`Cursor`] models the classic bidirectional-iterator "gap" invariant (the same one
//! `java.util.ListIterator` uses): `pos` is a slot index into a sorted `Vec`, sitting *between*
//! `items[pos - 1]` and `items[pos]`. `next()` returns `items[pos]` and moves the gap right;
//! `previous()` returns `items[pos - 1]` and moves the gap left; calling one then the other
//! returns to the same element with no net movement. [`initial_gap_by`] computes the starting
//! `pos` for a given start value and before/after flag; working through Java's
//! `Table.ShortDurationLongKeyIterator.initialize`/`next`/`previous` (which special-cases
//! "positioned exactly at an existing key" as ambiguous, resolved by whichever direction is
//! queried first) shows it always settles into exactly this gap position once a single
//! next()/previous() pair has been resolved -- so modeling the gap directly, rather than Java's
//! ambiguous dual-echo initial state, produces the same externally observable sequence of values
//! without the extra bookkeeping.

/// A "gap" cursor over a conceptual sorted sequence of length `len`. See the module docs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cursor {
    pos: usize,
    len: usize,
    /// Index of the item last returned by `advance_next`/`advance_previous`, if any and if it
    /// has not since been consumed by `on_removed`. Mirrors "the last record read via the next
    /// or previous methods" that Java's `delete()` acts on.
    last: Option<usize>,
}

impl Cursor {
    /// Constructs a cursor over a sequence of length `len`, initially positioned at gap `pos`
    /// (`0 <= pos <= len`).
    pub(crate) fn new(pos: usize, len: usize) -> Self {
        debug_assert!(pos <= len);
        Cursor { pos, len, last: None }
    }

    pub(crate) fn has_next(&self) -> bool {
        self.pos < self.len
    }

    pub(crate) fn has_previous(&self) -> bool {
        self.pos > 0
    }

    /// Advances the gap forward, returning the index of the item just passed, or `None` if
    /// already at the end.
    pub(crate) fn advance_next(&mut self) -> Option<usize> {
        if self.pos < self.len {
            let idx = self.pos;
            self.pos += 1;
            self.last = Some(idx);
            Some(idx)
        } else {
            None
        }
    }

    /// Advances the gap backward, returning the index of the item just passed, or `None` if
    /// already at the start.
    pub(crate) fn advance_previous(&mut self) -> Option<usize> {
        if self.pos > 0 {
            self.pos -= 1;
            self.last = Some(self.pos);
            Some(self.pos)
        } else {
            None
        }
    }

    /// Returns (and clears) the index last returned by `advance_next`/`advance_previous`, for
    /// `delete()` to act on. Returns `None` if nothing has been read yet, or the last-read item
    /// was already removed.
    pub(crate) fn take_last(&mut self) -> Option<usize> {
        self.last.take()
    }

    /// Notifies the cursor that the item at snapshot index `idx` has been removed from the
    /// backing store (and should also be removed from the caller's own snapshot `Vec` by the
    /// caller). Shifts `pos` left by one if the removal occurred before the gap, keeping future
    /// `advance_next`/`advance_previous` calls aligned with the (now one-shorter) snapshot.
    pub(crate) fn on_removed(&mut self, idx: usize) {
        if idx < self.pos {
            self.pos -= 1;
        }
        self.len -= 1;
    }
}

/// Computes the initial gap position (see [`Cursor`]) for a snapshot `items`, given an optional
/// start value and a before/after flag.
///
/// * `start == None`: `before` positions the gap at the very start (`0`, so `next()` yields the
///   smallest item first); `!before` positions it at the very end (`len`, so `previous()` yields
///   the largest item first).
/// * `start == Some(s)`: `before` positions the gap just before the first item `>= s`; `!before`
///   positions it just after the last item `<= s`. When no item equals `s`, both give the same
///   split point (there is nothing to be "before" or "after" relative to `s` itself).
pub(crate) fn initial_gap_by<T>(
    items: &[T],
    start: Option<i64>,
    before: bool,
    key: impl Fn(&T) -> i64,
) -> usize {
    match start {
        None => {
            if before {
                0
            } else {
                items.len()
            }
        }
        Some(s) => {
            if before {
                items.partition_point(|it| key(it) < s)
            } else {
                items.partition_point(|it| key(it) <= s)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_next_then_previous_returns_to_same_element() {
        let mut cursor = Cursor::new(2, 5); // gap before items[2]
        let idx = cursor.advance_next().unwrap();
        assert_eq!(idx, 2);
        let idx_back = cursor.advance_previous().unwrap();
        assert_eq!(idx_back, 2);
    }

    #[test]
    fn cursor_bounds() {
        let mut cursor = Cursor::new(0, 3);
        assert!(!cursor.has_previous());
        assert!(cursor.has_next());
        assert_eq!(cursor.advance_next(), Some(0));
        assert_eq!(cursor.advance_next(), Some(1));
        assert_eq!(cursor.advance_next(), Some(2));
        assert!(!cursor.has_next());
        assert_eq!(cursor.advance_next(), None);
    }

    #[test]
    fn cursor_on_removed_shifts_pos_when_before_gap() {
        let mut cursor = Cursor::new(3, 5);
        cursor.on_removed(1);
        assert_eq!(cursor.pos, 2);
        assert_eq!(cursor.len, 4);
    }

    #[test]
    fn cursor_on_removed_does_not_shift_pos_when_after_gap() {
        let mut cursor = Cursor::new(2, 5);
        cursor.on_removed(3);
        assert_eq!(cursor.pos, 2);
        assert_eq!(cursor.len, 4);
    }

    #[test]
    fn initial_gap_no_start() {
        let items = [1i64, 2, 3];
        assert_eq!(initial_gap_by(&items, None, true, |v| *v), 0);
        assert_eq!(initial_gap_by(&items, None, false, |v| *v), 3);
    }

    #[test]
    fn initial_gap_with_exact_match() {
        let items = [1i64, 2, 3];
        // before => gap sits just before the match, so next() yields it.
        assert_eq!(initial_gap_by(&items, Some(2), true, |v| *v), 1);
        // !before => gap sits just after the match, so previous() yields it.
        assert_eq!(initial_gap_by(&items, Some(2), false, |v| *v), 2);
    }

    #[test]
    fn initial_gap_with_duplicates_skips_all_matches_when_after() {
        let items = [1i64, 2, 2, 2, 5];
        assert_eq!(initial_gap_by(&items, Some(2), true, |v| *v), 1);
        assert_eq!(initial_gap_by(&items, Some(2), false, |v| *v), 4);
    }

    #[test]
    fn initial_gap_with_no_match_is_the_same_split_point_either_way() {
        let items = [1i64, 5, 9];
        assert_eq!(initial_gap_by(&items, Some(4), true, |v| *v), 1);
        assert_eq!(initial_gap_by(&items, Some(4), false, |v| *v), 1);
    }
}
