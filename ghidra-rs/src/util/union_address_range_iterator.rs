//! The iterator implementation backing several methods in `UnionAddressSetView`.
//!
//! Port of `ghidra.util.UnionAddressRangeIterator`.

use crate::generic::util::abstract_peekable_iterator::AbstractPeekableIterator;
use crate::generic::util::merge_sorting_iterator::MergeSortingIterator;
use crate::generic::util::peekable_iterator::PeekableIterator;
use crate::generic::util::peekable_iterators::PeekableIterators;
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::util::address_range_comparators::AddressRangeComparators;

/// Returns whichever of `a`/`b` sorts last (`a` on ties).
///
/// Mirrors the statically-imported `MathUtilities.cmax`; this crate's `MathUtilities` port
/// (see [`crate::util::math_utilities::MathUtilities`]) only covers the numeric-primitive
/// overloads, not the generic `<T extends Comparable<T>> T cmax(T, T)` this class uses over
/// [`Address`], so it's reproduced locally here instead.
fn cmax(a: &Address, b: &Address) -> Address {
    if a >= b {
        a.clone()
    } else {
        b.clone()
    }
}

/// Returns whichever of `a`/`b` sorts first (`a` on ties).
///
/// Mirrors the statically-imported `MathUtilities.cmin`; see [`cmax`] for why it's local to
/// this module rather than reused from the ported `MathUtilities`.
fn cmin(a: &Address, b: &Address) -> Address {
    if a <= b {
        a.clone()
    } else {
        b.clone()
    }
}

/// The seeker closure type driving [`UnionAddressRangeIterator`]'s
/// [`AbstractPeekableIterator`].
type Seeker = Box<dyn FnMut() -> Option<AddressRange>>;

/// Coalesce (by union) ranges from a single iterator.
///
/// The ranges must be returned in order: in the forward direction, by increasing min address; in
/// the reverse direction, by decreasing max address.
///
/// Port of `ghidra.util.UnionAddressRangeIterator`.
pub struct UnionAddressRangeIterator {
    inner: AbstractPeekableIterator<AddressRange, Seeker>,
}

impl UnionAddressRangeIterator {
    /// Constructs a union iterator over a single source iterator.
    ///
    /// `forward` is `true` to coalesce in the forward direction, `false` for reverse.
    ///
    /// Mirrors `UnionAddressRangeIterator(Iterator<AddressRange>, boolean)`.
    pub fn new(it: Box<dyn Iterator<Item = AddressRange>>, forward: bool) -> Self {
        let peekable: Box<dyn PeekableIterator<Item = AddressRange>> = Box::new(it.cast_or_wrap());
        Self::from_peekable(peekable, forward)
    }

    /// Union into a single range iterator several range iterators.
    ///
    /// The ranges will be coalesced so that each returned range is disconnected from any other.
    /// The ranges of each iterator must be returned in order by direction. While not recommended,
    /// the ranges of each iterator may overlap, so long as they are sorted as required by
    /// [`UnionAddressRangeIterator::new`].
    ///
    /// Mirrors `UnionAddressRangeIterator(Collection<Iterator<AddressRange>>, boolean)`.
    pub fn from_iterators(
        iterators: Vec<Box<dyn Iterator<Item = AddressRange>>>,
        forward: bool,
    ) -> Self {
        let comparator = if forward {
            AddressRangeComparators::Forward
        } else {
            AddressRangeComparators::Backward
        };
        let merged = MergeSortingIterator::new(iterators, move |a: &AddressRange, b: &AddressRange| {
            comparator.compare(a, b)
        });
        Self::from_peekable(Box::new(merged), forward)
    }

    fn from_peekable(
        mut it: Box<dyn PeekableIterator<Item = AddressRange>>,
        forward: bool,
    ) -> Self {
        let seeker: Seeker = Box::new(move || {
            // Mirrors `seekNext()`.
            let first = it.peek()?.clone();
            let mut min = first.min_address().clone();
            let mut max = first.max_address().clone();
            loop {
                it.next();
                let Some(peek) = it.peek() else {
                    break;
                };
                if peek.space() != min.space() {
                    break;
                }
                if forward {
                    if let Ok(n) = max.next() {
                        if peek.min_address() > &n {
                            break;
                        }
                    }
                    max = cmax(&max, peek.max_address());
                } else {
                    if let Ok(p) = min.previous() {
                        if peek.max_address() < &p {
                            break;
                        }
                    }
                    min = cmin(&min, peek.min_address());
                }
            }
            Some(AddressRange::new(min, max))
        });
        Self {
            inner: AbstractPeekableIterator::new(seeker),
        }
    }
}

impl Iterator for UnionAddressRangeIterator {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl PeekableIterator for UnionAddressRangeIterator {
    fn peek(&mut self) -> Option<&Self::Item> {
        self.inner.peek()
    }
}

impl AddressRangeIterator for UnionAddressRangeIterator {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn range(start: i64, end: i64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    fn boxed(v: Vec<AddressRange>) -> Box<dyn Iterator<Item = AddressRange>> {
        Box::new(v.into_iter())
    }

    #[test]
    fn single_iterator_coalesces_adjacent_ranges() {
        let mut it = UnionAddressRangeIterator::new(
            boxed(vec![range(0x1000, 0x1010), range(0x1011, 0x1020), range(0x2000, 0x2010)]),
            true,
        );
        assert_eq!(it.next(), Some(range(0x1000, 0x1020)));
        assert_eq!(it.next(), Some(range(0x2000, 0x2010)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn single_iterator_keeps_disconnected_ranges_separate() {
        let mut it = UnionAddressRangeIterator::new(
            boxed(vec![range(0x1000, 0x1010), range(0x2000, 0x2010)]),
            true,
        );
        assert_eq!(it.next(), Some(range(0x1000, 0x1010)));
        assert_eq!(it.next(), Some(range(0x2000, 0x2010)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn overlapping_ranges_coalesce_to_the_widest_span() {
        let mut it = UnionAddressRangeIterator::new(
            boxed(vec![range(0x1000, 0x1020), range(0x1010, 0x1030)]),
            true,
        );
        assert_eq!(it.next(), Some(range(0x1000, 0x1030)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn empty_source_yields_nothing() {
        let mut it = UnionAddressRangeIterator::new(boxed(vec![]), true);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn peek_does_not_advance() {
        let mut it = UnionAddressRangeIterator::new(boxed(vec![range(0x1000, 0x1010)]), true);
        assert_eq!(PeekableIterator::peek(&mut it), Some(&range(0x1000, 0x1010)));
        assert_eq!(PeekableIterator::peek(&mut it), Some(&range(0x1000, 0x1010)));
        assert_eq!(it.next(), Some(range(0x1000, 0x1010)));
        assert_eq!(PeekableIterator::peek(&mut it), None);
    }

    #[test]
    fn reverse_direction_coalesces_by_decreasing_max_address() {
        let mut it = UnionAddressRangeIterator::new(
            boxed(vec![range(0x2000, 0x2010), range(0x1000, 0x1fff)]),
            false,
        );
        assert_eq!(it.next(), Some(range(0x1000, 0x2010)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn from_iterators_merges_multiple_sources_and_coalesces() {
        let it = UnionAddressRangeIterator::from_iterators(
            vec![
                boxed(vec![range(0x1000, 0x100f), range(0x3000, 0x3010)]),
                boxed(vec![range(0x1010, 0x1020), range(0x2000, 0x2010)]),
            ],
            true,
        );
        let ranges: Vec<AddressRange> = it.collect();
        assert_eq!(
            ranges,
            vec![range(0x1000, 0x1020), range(0x2000, 0x2010), range(0x3000, 0x3010)]
        );
    }

    #[test]
    fn from_iterators_with_no_sources_yields_nothing() {
        let mut it = UnionAddressRangeIterator::from_iterators(vec![], true);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn different_address_spaces_are_not_coalesced() {
        let other_space = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let other_range = AddressRange::new(
            Address::new(other_space.clone(), 0x1000),
            Address::new(other_space, 0x1010),
        );
        let mut it =
            UnionAddressRangeIterator::new(boxed(vec![range(0x1000, 0x1010), other_range.clone()]), true);
        assert_eq!(it.next(), Some(range(0x1000, 0x1010)));
        assert_eq!(it.next(), Some(other_range));
        assert_eq!(it.next(), None);
    }
}
