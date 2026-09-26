use std::cmp::Ordering;
use std::iter::Peekable;
use std::sync::Arc;

use crate::generic::util::peekable_iterator::PeekableIterator;
use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::util::math_utilities::MathUtilities;

/// Indicates which of the two input iterators contain a range, mirroring the nested Java enum
/// `TwoWayBreakdownAddressRangeIterator.Which`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// Only the left iterator included the range.
    Left,
    /// Only the right iterator included the range.
    Right,
    /// Both iterators included the range.
    Both,
}

impl Which {
    /// Whether the left iterator includes this range. Mirrors the `includesLeft` field.
    pub fn includes_left(self) -> bool {
        matches!(self, Which::Left | Which::Both)
    }

    /// Whether the right iterator includes this range. Mirrors the `includesRight` field.
    pub fn includes_right(self) -> bool {
        matches!(self, Which::Right | Which::Both)
    }

    /// Whether this range is included in the difference `left - right`.
    ///
    /// Mirrors `Which.inSubtract()`.
    pub fn in_subtract(self) -> bool {
        self == Which::Left
    }

    /// Whether this range is included in the symmetric difference `left Δ right`.
    ///
    /// Mirrors `Which.inXor()`.
    pub fn in_xor(self) -> bool {
        self == Which::Left || self == Which::Right
    }

    /// Whether this range is included in the intersection `left ∩ right`.
    ///
    /// Mirrors `Which.inIntersect()`.
    pub fn in_intersect(self) -> bool {
        self == Which::Both
    }
}

/// An iterator that takes two iterators over address ranges and "breaks down" where they do and
/// do not overlap.
///
/// Consider one iterator L that contains only `[1,3]`, and another R that contains only `[2,4]`.
/// The two could be plotted:
///
/// ```text
///  1  2  3  4
/// [---L---]
///    [---R---]
/// ```
///
/// This yields an iterator over range/[`Which`] pairs -- [`Which`] indicates which iterators
/// include the given range ([`Which::Left`], [`Which::Right`], or [`Which::Both`]). There is no
/// "none" variant, so gaps are omitted. For the example above:
///
/// ```text
///  1  2  3  4
/// [L][-B--][R]
/// ```
///
/// This supports the computation of difference, symmetric difference, and intersection.
///
/// Unlike the Java original -- which reuses a single mutable `Map.Entry` across every yielded
/// item purely as a GC optimization, and documents that callers must not retain it -- this
/// iterator yields a fresh, independently owned `(AddressRange, Which)` pair each time. There is
/// no aliasing hazard here: retaining a previously yielded item is always safe.
///
/// Mirrors `ghidra.util.TwoWayBreakdownAddressRangeIterator`.
pub struct TwoWayBreakdownAddressRangeIterator<L, R>
where
    L: Iterator<Item = AddressRange>,
    R: Iterator<Item = AddressRange>,
{
    lit: Peekable<L>,
    rit: Peekable<R>,
    forward: bool,
    cur_space: Option<Arc<AddressSpace>>,
    /// The min/max address of the next range expected (direction-dependent).
    cur: Option<Address>,
    cached_next: Option<Option<(AddressRange, Which)>>,
}

impl<L, R> TwoWayBreakdownAddressRangeIterator<L, R>
where
    L: Iterator<Item = AddressRange>,
    R: Iterator<Item = AddressRange>,
{
    /// Creates an iterator that "breaks down" the two address range iterators.
    ///
    /// `forward` is `true` for forward iteration, `false` for reverse. The input iterators must
    /// already be ordered according to this flag.
    pub fn new(lit: L, rit: R, forward: bool) -> Self {
        let mut this = Self {
            lit: lit.peekable(),
            rit: rit.peekable(),
            forward,
            cur_space: None,
            cur: None,
            cached_next: None,
        };
        this.init_cur();
        this
    }

    fn init_cur(&mut self) {
        let mut cur: Option<Address> = None;
        if let Some(r) = self.lit.peek() {
            cur = Some(get_start(r, self.forward));
        }
        if let Some(r) = self.rit.peek() {
            let a = get_start(r, self.forward);
            cur = Some(match cur {
                None => a,
                Some(c) => first(c, a, self.forward),
            });
        }
        self.cur_space = cur.as_ref().map(|c| c.space().clone());
        self.cur = cur;
    }

    fn advance_space(&mut self) {
        advance_space_it(&mut self.lit, &self.cur_space);
        advance_space_it(&mut self.rit, &self.cur_space);
    }

    fn advance(&mut self, key: &AddressRange) {
        self.cur = get_after(key, self.forward);
        if self.cur.is_none() {
            self.advance_space();
            self.init_cur();
        }
    }

    fn ensure_cached(&mut self) {
        if self.cached_next.is_none() {
            let next = self.seek_next();
            self.cached_next = Some(next);
        }
    }

    fn seek_next(&mut self) -> Option<(AddressRange, Which)> {
        let cur = self.cur.clone()?;
        find_suitable(&mut self.lit, &cur, self.forward);
        find_suitable(&mut self.rit, &cur, self.forward);

        let ln = self.lit.peek().is_some();
        let rn = self.rit.peek().is_some();
        if !ln && !rn {
            return None;
        }
        if ln && !rn {
            let range = self.lit.next().unwrap();
            let key = truncate_range(&cur, range, self.forward);
            self.advance(&key);
            return Some((key, Which::Left));
        }
        if !ln && rn {
            let range = self.rit.next().unwrap();
            let key = truncate_range(&cur, range, self.forward);
            self.advance(&key);
            return Some((key, Which::Right));
        }

        // Advance past empty space.
        let l_peek = self.lit.peek().unwrap().clone();
        let r_peek = self.rit.peek().unwrap().clone();
        let adv = first(get_start(&l_peek, self.forward), get_start(&r_peek, self.forward), self.forward);
        let cur = last(cur, adv, self.forward);
        self.cur = Some(cur.clone());

        let lc = cmp_dir(&get_start(&l_peek, self.forward), &cur, self.forward) != Ordering::Greater;
        let rc = cmp_dir(&get_start(&r_peek, self.forward), &cur, self.forward) != Ordering::Greater;

        if lc && rc {
            let beg = last(get_start(&l_peek, self.forward), get_start(&r_peek, self.forward), self.forward);
            let end = first(get_end(&l_peek, self.forward), get_end(&r_peek, self.forward), self.forward);
            let key = truncate_range_pts(&cur, beg, end, self.forward);
            self.advance(&key);
            return Some((key, Which::Both));
        }
        if lc && !rc {
            let beg = get_start(&l_peek, self.forward);
            let before = get_before(&r_peek, beg.space(), self.forward);
            let end = first(get_end(&l_peek, self.forward), before, self.forward);
            let key = truncate_range_pts(&cur, beg, end, self.forward);
            self.advance(&key);
            return Some((key, Which::Left));
        }
        if !lc && rc {
            let beg = get_start(&r_peek, self.forward);
            let before = get_before(&l_peek, beg.space(), self.forward);
            let end = first(get_end(&r_peek, self.forward), before, self.forward);
            let key = truncate_range_pts(&cur, beg, end, self.forward);
            self.advance(&key);
            return Some((key, Which::Right));
        }
        unreachable!(
            "both lit and rit have entries at or after cur, so at least one of lc/rc must hold"
        );
    }
}

impl<L, R> Iterator for TwoWayBreakdownAddressRangeIterator<L, R>
where
    L: Iterator<Item = AddressRange>,
    R: Iterator<Item = AddressRange>,
{
    type Item = (AddressRange, Which);

    fn next(&mut self) -> Option<Self::Item> {
        self.ensure_cached();
        self.cached_next.take().flatten()
    }
}

impl<L, R> PeekableIterator for TwoWayBreakdownAddressRangeIterator<L, R>
where
    L: Iterator<Item = AddressRange>,
    R: Iterator<Item = AddressRange>,
{
    fn peek(&mut self) -> Option<&Self::Item> {
        self.ensure_cached();
        self.cached_next.as_ref().unwrap().as_ref()
    }
}

fn get_start(r: &AddressRange, forward: bool) -> Address {
    if forward {
        r.min_address().clone()
    } else {
        r.max_address().clone()
    }
}

fn get_end(r: &AddressRange, forward: bool) -> Address {
    if forward {
        r.max_address().clone()
    } else {
        r.min_address().clone()
    }
}

/// The address immediately after `r` in the direction of travel, or `None` at the extreme of the
/// address space (mirrors Java's `getAfter` returning `null` from `Address.next()`/`previous()`).
fn get_after(r: &AddressRange, forward: bool) -> Option<Address> {
    if forward {
        r.max_address().next().ok()
    } else {
        r.min_address().previous().ok()
    }
}

/// The address immediately before `r` in the direction of travel, wrapping to the extreme of
/// `before_space` if `r` already sits at the start of the space.
fn get_before(r: &AddressRange, before_space: &Arc<AddressSpace>, forward: bool) -> Address {
    if forward {
        r.min_address()
            .previous()
            .unwrap_or_else(|_| before_space.max_address())
    } else {
        r.max_address()
            .next()
            .unwrap_or_else(|_| before_space.min_address())
    }
}

fn cmp_dir(a: &Address, b: &Address, forward: bool) -> Ordering {
    if forward {
        a.cmp(b)
    } else {
        b.cmp(a)
    }
}

fn first(a: Address, b: Address, forward: bool) -> Address {
    if forward {
        MathUtilities::cmin(a, b)
    } else {
        MathUtilities::cmax(a, b)
    }
}

fn last(a: Address, b: Address, forward: bool) -> Address {
    if forward {
        MathUtilities::cmax(a, b)
    } else {
        MathUtilities::cmin(a, b)
    }
}

fn truncate_range_pts(cur: &Address, beg: Address, end: Address, forward: bool) -> AddressRange {
    if forward {
        AddressRange::new(MathUtilities::cmax(cur.clone(), beg), end)
    } else {
        AddressRange::new(end, MathUtilities::cmin(cur.clone(), beg))
    }
}

fn truncate_range(cur: &Address, rng: AddressRange, forward: bool) -> AddressRange {
    if !rng.contains(cur) {
        return rng;
    }
    if forward {
        truncate_range_pts(cur, rng.min_address().clone(), rng.max_address().clone(), forward)
    } else {
        truncate_range_pts(cur, rng.max_address().clone(), rng.min_address().clone(), forward)
    }
}

fn find_suitable<I: Iterator<Item = AddressRange>>(
    it: &mut Peekable<I>,
    cur: &Address,
    forward: bool,
) {
    loop {
        match it.peek() {
            Some(r) if cmp_dir(&get_end(r, forward), cur, forward) == Ordering::Less => {
                it.next();
            }
            _ => break,
        }
    }
}

fn advance_space_it<I: Iterator<Item = AddressRange>>(
    it: &mut Peekable<I>,
    cur_space: &Option<Arc<AddressSpace>>,
) {
    loop {
        match it.peek() {
            Some(r) if Some(r.space()) == cur_space.as_ref() => {
                it.next();
            }
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn range(start: i64, end: i64) -> AddressRange {
        AddressRange::new(addr(start), addr(end))
    }

    fn breakdown(
        left: Vec<AddressRange>,
        right: Vec<AddressRange>,
        forward: bool,
    ) -> Vec<(AddressRange, Which)> {
        TwoWayBreakdownAddressRangeIterator::new(left.into_iter(), right.into_iter(), forward)
            .collect()
    }

    fn as_tuples(entries: &[(AddressRange, Which)]) -> Vec<(i64, i64, Which)> {
        entries
            .iter()
            .map(|(r, w)| (r.min_address().offset(), r.max_address().offset(), *w))
            .collect()
    }

    #[test]
    fn which_query_methods_match_java_semantics() {
        assert!(Which::Left.in_subtract());
        assert!(!Which::Right.in_subtract());
        assert!(!Which::Both.in_subtract());

        assert!(Which::Left.in_xor());
        assert!(Which::Right.in_xor());
        assert!(!Which::Both.in_xor());

        assert!(!Which::Left.in_intersect());
        assert!(!Which::Right.in_intersect());
        assert!(Which::Both.in_intersect());

        assert!(Which::Left.includes_left() && !Which::Left.includes_right());
        assert!(!Which::Right.includes_left() && Which::Right.includes_right());
        assert!(Which::Both.includes_left() && Which::Both.includes_right());
    }

    /// From the class doc example: L=[1,3], R=[2,4] breaks down into [1,1]L [2,3]B [4,4]R.
    #[test]
    fn overlapping_ranges_break_down_per_doc_example() {
        let left = vec![range(1, 3)];
        let right = vec![range(2, 4)];

        let entries = breakdown(left, right, true);
        assert_eq!(
            as_tuples(&entries),
            vec![(1, 1, Which::Left), (2, 3, Which::Both), (4, 4, Which::Right)]
        );
    }

    #[test]
    fn disjoint_ranges_yield_left_then_right_in_order() {
        let left = vec![range(1, 2)];
        let right = vec![range(5, 6)];

        let entries = breakdown(left, right, true);
        assert_eq!(as_tuples(&entries), vec![(1, 2, Which::Left), (5, 6, Which::Right)]);
    }

    #[test]
    fn identical_ranges_are_both() {
        let left = vec![range(10, 20)];
        let right = vec![range(10, 20)];

        let entries = breakdown(left, right, true);
        assert_eq!(as_tuples(&entries), vec![(10, 20, Which::Both)]);
    }

    #[test]
    fn empty_iterators_yield_nothing() {
        let entries = breakdown(vec![], vec![], true);
        assert!(entries.is_empty());
    }

    #[test]
    fn one_sided_only_yields_that_side() {
        let left = vec![range(1, 5)];
        let entries = breakdown(left, vec![], true);
        assert_eq!(as_tuples(&entries), vec![(1, 5, Which::Left)]);

        let right = vec![range(1, 5)];
        let entries = breakdown(vec![], right, true);
        assert_eq!(as_tuples(&entries), vec![(1, 5, Which::Right)]);
    }

    #[test]
    fn multiple_ranges_break_down_in_sequence() {
        // L: [1,3] [10,12]      R: [2,4] [11,15]
        let left = vec![range(1, 3), range(10, 12)];
        let right = vec![range(2, 4), range(11, 15)];

        let entries = breakdown(left, right, true);
        assert_eq!(
            as_tuples(&entries),
            vec![
                (1, 1, Which::Left),
                (2, 3, Which::Both),
                (4, 4, Which::Right),
                (10, 10, Which::Left),
                (11, 12, Which::Both),
                (13, 15, Which::Right),
            ]
        );
    }

    #[test]
    fn backward_iteration_matches_forward_mirrored() {
        // Same ranges as the doc example, but supplied and consumed in reverse order.
        let left = vec![range(1, 3)];
        let right = vec![range(2, 4)];

        let entries = breakdown(left, right, false);
        assert_eq!(
            as_tuples(&entries),
            vec![(4, 4, Which::Right), (2, 3, Which::Both), (1, 1, Which::Left)]
        );
    }

    #[test]
    fn peekable_iterator_peek_does_not_advance() {
        let left = vec![range(1, 3)];
        let right = vec![range(2, 4)];
        let mut it = TwoWayBreakdownAddressRangeIterator::new(left.into_iter(), right.into_iter(), true);

        let peeked = it.peek().cloned();
        assert_eq!(peeked, it.next());
        assert_eq!(
            it.next().map(|(r, w)| (r.min_address().offset(), r.max_address().offset(), w)),
            Some((2, 3, Which::Both))
        );
    }
}
