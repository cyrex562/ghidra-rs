//! Mirrors `ghidra.util.database.KeySpan`: a closed span (interval) of database (primary) keys.
//!
//! In Java, `KeySpan extends Span<Long, KeySpan>`: a generic, self-referential interval type
//! (see `generic.Span`) specialized to ordinary signed `Long` keys. Since this domain never
//! varies, the domain-level operations declared on `Span.Domain` are ported here as associated
//! functions on [`Domain`] rather than as a separate generic trait, and the span-instance
//! operations declared on `Span` itself are flattened directly into the [`KeySpan`] trait --
//! following the same convention established by [`crate::generic::ulong_span::ULongSpan`] for
//! `generic.ULongSpan`. Unlike that domain, `KeySpan`'s comparisons and increment/decrement are
//! ordinary *signed* `i64` operations (Java's `Long.compare`), not unsigned ones.

use std::cmp::Ordering;

use crate::util::database::Direction;

/// A span of database keys. Mirrors the `KeySpan` interface.
pub trait KeySpan: Send + Sync {
    /// The lower (inclusive) endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn min(&self) -> i64;

    /// The upper (inclusive) endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn max(&self) -> i64;

    /// Whether this span contains no values.
    fn is_empty(&self) -> bool {
        false
    }

    /// Whether the lower endpoint excludes the domain minimum.
    fn min_is_finite(&self) -> bool {
        self.min() != Domain::MIN
    }

    /// Whether the upper endpoint excludes the domain maximum.
    fn max_is_finite(&self) -> bool {
        self.max() != Domain::MAX
    }

    /// Whether this span contains the value `n`.
    fn contains(&self, n: i64) -> bool {
        !self.is_empty() && self.min() <= n && n <= self.max()
    }

    /// Render this span, e.g. `"[5..9]"`, `"(-inf..9]"`, or `"(empty)"`.
    fn display(&self) -> String {
        Domain::display(self)
    }

    /// The intersection of this span and `other`, possibly empty.
    fn intersect(&self, other: &dyn KeySpan) -> Box<dyn KeySpan> {
        Domain::intersect(self, other)
    }

    /// Whether this span intersects `other`.
    fn intersects(&self, other: &dyn KeySpan) -> bool {
        Domain::intersects(self, other)
    }

    /// Whether this span encloses `other`.
    fn encloses(&self, other: &dyn KeySpan) -> bool {
        Domain::encloses(self, other)
    }

    /// The smallest span containing both this span and `other`.
    fn bound(&self, other: &dyn KeySpan) -> Box<dyn KeySpan> {
        Domain::bound(self, other)
    }

    /// Subtract `other` from this span, yielding 0, 1, or 2 spans.
    fn subtract(&self, other: &dyn KeySpan) -> Vec<Box<dyn KeySpan>> {
        Domain::subtract(self, other)
    }

    /// Compare two spans, ordering by (emptiness, min, max). Mirrors `Comparable<S>`.
    fn compare_to(&self, other: &dyn KeySpan) -> Ordering {
        if self.is_empty() {
            return if other.is_empty() { Ordering::Equal } else { Ordering::Less };
        }
        if other.is_empty() {
            return Ordering::Greater;
        }
        match self.min().cmp(&other.min()) {
            Ordering::Equal => self.max().cmp(&other.max()),
            ord => ord,
        }
    }
}

/// The (fixed) domain of signed-long key endpoints. Mirrors `KeySpan.Domain`.
pub struct Domain;

impl Domain {
    /// The minimum value in the domain. Mirrors `Domain::min`.
    pub const MIN: i64 = i64::MIN;
    /// The maximum value in the domain. Mirrors `Domain::max`.
    pub const MAX: i64 = i64::MAX;

    /// Compare two endpoints.
    pub fn compare(n1: i64, n2: i64) -> Ordering {
        n1.cmp(&n2)
    }

    /// The endpoint immediately following `n`, wrapping to [`MIN`](Self::MIN) at [`MAX`](Self::MAX).
    pub fn inc(n: i64) -> i64 {
        n.wrapping_add(1)
    }

    /// The endpoint immediately preceding `n`, wrapping to [`MAX`](Self::MAX) at [`MIN`](Self::MIN).
    pub fn dec(n: i64) -> i64 {
        n.wrapping_sub(1)
    }

    /// Render a single endpoint.
    pub fn to_string(n: i64) -> String {
        n.to_string()
    }

    /// Create a closed interval `[min, max]`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `max < min`.
    pub fn closed(min: i64, max: i64) -> Impl {
        assert!(min <= max, "min > max: min={min},max={max}");
        Impl { min, max }
    }

    /// A span containing only `n`.
    pub fn value(n: i64) -> Impl {
        Self::closed(n, n)
    }

    /// A span from the domain minimum up to (and including) `max`.
    pub fn at_most(max: i64) -> Impl {
        Self::closed(Self::MIN, max)
    }

    /// A span from `min` up to (and including) the domain maximum.
    pub fn at_least(min: i64) -> Impl {
        Self::closed(min, Self::MAX)
    }

    /// The span containing every value in the domain.
    pub fn all() -> Impl {
        Impl { min: Self::MIN, max: Self::MAX }
    }

    /// The span containing no values.
    pub fn empty() -> Empty {
        Empty
    }

    /// Render `s`, e.g. `"[5..9]"`, `"(-inf..9]"`, or `"(empty)"`.
    pub fn display(s: &(impl KeySpan + ?Sized)) -> String {
        if s.is_empty() {
            return "(empty)".to_string();
        }
        let min_s = if s.min() == Self::MIN { "(-inf".to_string() } else { format!("[{}", s.min()) };
        let max_s = if s.max() == Self::MAX { "+inf)".to_string() } else { format!("{}]", s.max()) };
        format!("{min_s}..{max_s}")
    }

    /// The intersection of `s1` and `s2`, possibly empty.
    pub fn intersect(s1: &(impl KeySpan + ?Sized), s2: &dyn KeySpan) -> Box<dyn KeySpan> {
        if !Self::intersects(s1, s2) {
            return Box::new(Self::empty());
        }
        Box::new(Self::closed(s1.min().max(s2.min()), s1.max().min(s2.max())))
    }

    /// Whether `s1` and `s2` intersect.
    pub fn intersects(s1: &(impl KeySpan + ?Sized), s2: &dyn KeySpan) -> bool {
        if s1.is_empty() || s2.is_empty() {
            return false;
        }
        s1.max() >= s2.min() && s2.max() >= s1.min()
    }

    /// Whether `s1` encloses `s2`.
    pub fn encloses(s1: &(impl KeySpan + ?Sized), s2: &dyn KeySpan) -> bool {
        if s1.is_empty() {
            return false;
        }
        if s2.is_empty() {
            return true;
        }
        s1.min() <= s2.min() && s1.max() >= s2.max()
    }

    /// The smallest span containing both `s1` and `s2`.
    pub fn bound(s1: &(impl KeySpan + ?Sized), s2: &dyn KeySpan) -> Box<dyn KeySpan> {
        if s1.is_empty() {
            return Self::reconstruct(s2);
        }
        if s2.is_empty() {
            return Self::reconstruct(s1);
        }
        Box::new(Self::closed(s1.min().min(s2.min()), s1.max().max(s2.max())))
    }

    /// Subtract `s2` from `s1`, yielding 0, 1, or 2 spans.
    pub fn subtract(s1: &(impl KeySpan + ?Sized), s2: &dyn KeySpan) -> Vec<Box<dyn KeySpan>> {
        if s1.is_empty() {
            return Vec::new();
        }
        if s2.is_empty() {
            return vec![Self::reconstruct(s1)];
        }
        if s1.max() < s2.min() || s2.max() < s1.min() {
            return vec![Self::reconstruct(s1)];
        }
        if s1.min() < s2.min() {
            if s1.max() > s2.max() {
                return vec![
                    Box::new(Self::closed(s1.min(), Self::dec(s2.min()))),
                    Box::new(Self::closed(Self::inc(s2.max()), s1.max())),
                ];
            }
            return vec![Box::new(Self::closed(s1.min(), Self::dec(s2.min())))];
        }
        if s1.max() > s2.max() {
            return vec![Box::new(Self::closed(Self::inc(s2.max()), s1.max()))];
        }
        Vec::new()
    }

    fn reconstruct(s: &(impl KeySpan + ?Sized)) -> Box<dyn KeySpan> {
        if s.is_empty() {
            Box::new(Empty)
        } else {
            Box::new(Impl { min: s.min(), max: s.max() })
        }
    }
}

/// The singleton empty span of keys. Mirrors `KeySpan.Empty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Empty;

impl KeySpan for Empty {
    fn min(&self) -> i64 {
        panic!("empty span has no minimum")
    }

    fn max(&self) -> i64 {
        panic!("empty span has no maximum")
    }

    fn is_empty(&self) -> bool {
        true
    }
}

/// A non-empty span of keys. Mirrors `KeySpan.Impl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Impl {
    pub min: i64,
    pub max: i64,
}

impl KeySpan for Impl {
    fn min(&self) -> i64 {
        self.min
    }

    fn max(&self) -> i64 {
        self.max
    }
}

/// The span containing every value in the domain. Mirrors `KeySpan.ALL`.
pub const ALL: Impl = Impl { min: Domain::MIN, max: Domain::MAX };

/// The singleton empty span. Mirrors `KeySpan.EMPTY`.
pub const EMPTY: Empty = Empty;

/// Get the span for a closed interval. Mirrors `KeySpan.closed`.
///
/// # Panics
/// Panics if `max < min`.
pub fn closed(from: i64, to: i64) -> Impl {
    Domain::closed(from, to)
}

/// Get the span for a sub collection. Mirrors `KeySpan.sub`.
///
/// `from` must precede `to`, unless `direction` is [`Direction::Backward`], in which case the
/// opposite is required. The endpoints may be equal but unless both are inclusive, the result is
/// [`EMPTY`]. The two endpoints are not automatically inverted to correct ordering.
pub fn sub(from: i64, from_inclusive: bool, to: i64, to_inclusive: bool, direction: Direction) -> Box<dyn KeySpan> {
    if from == to && (!from_inclusive || !to_inclusive) {
        return Box::new(EMPTY);
    }
    if direction == Direction::Forward {
        Box::new(Domain::closed(
            if from_inclusive { from } else { from.wrapping_add(1) },
            if to_inclusive { to } else { to.wrapping_sub(1) },
        ))
    } else {
        Box::new(Domain::closed(
            if to_inclusive { to } else { to.wrapping_add(1) },
            if from_inclusive { from } else { from.wrapping_sub(1) },
        ))
    }
}

/// Get the span for the head of a collection. Mirrors `KeySpan.head`.
///
/// When `direction` is [`Direction::Backward`] this behaves as if a tail collection; however,
/// the implication is that iteration will start from the maximum and proceed toward the given
/// bound.
pub fn head(to: i64, to_inclusive: bool, direction: Direction) -> Box<dyn KeySpan> {
    if to == Domain::MIN && !to_inclusive {
        return Box::new(EMPTY);
    }
    if direction == Direction::Forward {
        Box::new(Domain::closed(Domain::MIN, if to_inclusive { to } else { to.wrapping_sub(1) }))
    } else {
        Box::new(Domain::closed(if to_inclusive { to } else { to.wrapping_add(1) }, Domain::MAX))
    }
}

/// Get the span for the tail of a collection. Mirrors `KeySpan.tail`.
///
/// When `direction` is [`Direction::Backward`] this behaves as if a head collection; however,
/// the implication is that iteration will start from the bound and proceed toward the minimum.
pub fn tail(from: i64, from_inclusive: bool, direction: Direction) -> Box<dyn KeySpan> {
    if from == Domain::MAX && !from_inclusive {
        return Box::new(EMPTY);
    }
    if direction == Direction::Forward {
        Box::new(Domain::closed(if from_inclusive { from } else { from.wrapping_add(1) }, Domain::MAX))
    } else {
        Box::new(Domain::closed(Domain::MIN, if from_inclusive { from } else { from.wrapping_sub(1) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock span computed from a base offset and width, distinct from [`Impl`], proving
    /// [`KeySpan`] is object-safe and its default methods work for arbitrary implementors.
    struct RelativeSpan {
        base: i64,
        width: i64,
    }

    impl KeySpan for RelativeSpan {
        fn min(&self) -> i64 {
            self.base
        }

        fn max(&self) -> i64 {
            self.base + self.width - 1
        }
    }

    #[test]
    fn test_object_safety_via_trait_object() {
        let boxed: Box<dyn KeySpan> = Box::new(RelativeSpan { base: 100, width: 5 });
        assert_eq!(boxed.min(), 100);
        assert_eq!(boxed.max(), 104);
        assert!(boxed.contains(102));
        assert!(!boxed.contains(105));
    }

    #[test]
    fn test_all_and_empty_constants() {
        assert_eq!(ALL.min(), i64::MIN);
        assert_eq!(ALL.max(), i64::MAX);
        assert!(EMPTY.is_empty());
    }

    #[test]
    #[should_panic]
    fn test_empty_min_panics() {
        EMPTY.min();
    }

    #[test]
    fn test_closed_and_contains() {
        let s = closed(5, 9);
        assert!(s.contains(5));
        assert!(s.contains(9));
        assert!(!s.contains(4));
        assert!(!s.contains(10));
        assert!(s.min_is_finite());
        assert!(s.max_is_finite());
        assert!(!ALL.min_is_finite());
        assert!(!ALL.max_is_finite());
    }

    #[test]
    #[should_panic]
    fn test_closed_max_less_than_min_panics() {
        closed(5, 4);
    }

    #[test]
    fn test_display() {
        assert_eq!(closed(5, 9).display(), "[5..9]");
        assert_eq!(ALL.display(), "(-inf..+inf)");
        assert_eq!(EMPTY.display(), "(empty)");
    }

    #[test]
    fn test_intersect_and_intersects() {
        let a = closed(1, 10);
        let b = closed(5, 15);
        assert!(a.intersects(&b));
        let i = a.intersect(&b);
        assert_eq!(i.min(), 5);
        assert_eq!(i.max(), 10);

        let c = closed(20, 30);
        assert!(!a.intersects(&c));
        assert!(a.intersect(&c).is_empty());
    }

    #[test]
    fn test_encloses_and_bound() {
        let outer = closed(1, 100);
        let inner = closed(10, 20);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));

        let bound = inner.bound(&closed(200, 210));
        assert_eq!(bound.min(), 10);
        assert_eq!(bound.max(), 210);
    }

    #[test]
    fn test_subtract_splits_in_two() {
        let whole = closed(1, 10);
        let middle = closed(4, 6);
        let parts = whole.subtract(&middle);
        assert_eq!(parts.len(), 2);
        assert_eq!((parts[0].min(), parts[0].max()), (1, 3));
        assert_eq!((parts[1].min(), parts[1].max()), (7, 10));
    }

    #[test]
    fn test_compare_to() {
        let a = closed(1, 5);
        let b = closed(1, 10);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(EMPTY.compare_to(&a), Ordering::Less);
        assert_eq!(a.compare_to(&EMPTY), Ordering::Greater);
    }

    #[test]
    fn test_sub_forward_and_backward() {
        let fwd = sub(1, true, 10, true, Direction::Forward);
        assert_eq!((fwd.min(), fwd.max()), (1, 10));

        let fwd_exclusive = sub(1, false, 10, false, Direction::Forward);
        assert_eq!((fwd_exclusive.min(), fwd_exclusive.max()), (2, 9));

        let bwd = sub(10, true, 1, true, Direction::Backward);
        assert_eq!((bwd.min(), bwd.max()), (1, 10));

        let empty = sub(5, true, 5, false, Direction::Forward);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_head_and_tail() {
        let h = head(10, true, Direction::Forward);
        assert_eq!((h.min(), h.max()), (Domain::MIN, 10));

        let t = tail(10, true, Direction::Forward);
        assert_eq!((t.min(), t.max()), (10, Domain::MAX));

        let h_bwd = head(10, true, Direction::Backward);
        assert_eq!((h_bwd.min(), h_bwd.max()), (10, Domain::MAX));

        let t_bwd = tail(10, true, Direction::Backward);
        assert_eq!((t_bwd.min(), t_bwd.max()), (Domain::MIN, 10));
    }
}
