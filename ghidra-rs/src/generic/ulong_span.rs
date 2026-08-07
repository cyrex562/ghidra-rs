//! Mirrors `generic.ULongSpan` from Ghidra: a closed span (interval) of unsigned 64-bit
//! integers.
//!
//! In Java, `ULongSpan extends Span<Long, ULongSpan>`: a generic, self-referential interval
//! type specialized to a single fixed domain (unsigned longs). Since this domain never varies,
//! the domain-level operations declared on `Span.Domain` are ported here as associated
//! functions on [`Domain`] rather than as a separate generic trait, and the span-instance
//! operations declared on `Span` itself are flattened directly into the [`ULongSpan`] trait.
//! Java's `Long` endpoints are ported as `u64`, so ordinary numeric comparison and arithmetic
//! already carry the domain's unsigned semantics (no `compareUnsigned` equivalent is needed).

use std::cmp::Ordering;

/// A span of unsigned longs. Mirrors the `ULongSpan` interface.
pub trait ULongSpan: Send + Sync {
    /// The lower (inclusive) endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn min(&self) -> u64;

    /// The upper (inclusive) endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn max(&self) -> u64;

    /// Whether this span contains no values.
    fn is_empty(&self) -> bool {
        false
    }

    /// The number of values in the span.
    fn length(&self) -> u64 {
        self.max().wrapping_sub(self.min()).wrapping_add(1)
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
    fn contains(&self, n: u64) -> bool {
        !self.is_empty() && self.min() <= n && n <= self.max()
    }

    /// Render this span, e.g. `"[5..9]"`, `"(-inf..9]"`, or `"(empty)"`.
    fn display(&self) -> String {
        Domain::display(self)
    }

    /// The intersection of this span and `other`, possibly empty.
    fn intersect(&self, other: &dyn ULongSpan) -> Box<dyn ULongSpan> {
        Domain::intersect(self, other)
    }

    /// Whether this span intersects `other`.
    fn intersects(&self, other: &dyn ULongSpan) -> bool {
        Domain::intersects(self, other)
    }

    /// Whether this span encloses `other`.
    fn encloses(&self, other: &dyn ULongSpan) -> bool {
        Domain::encloses(self, other)
    }

    /// The smallest span containing both this span and `other`.
    fn bound(&self, other: &dyn ULongSpan) -> Box<dyn ULongSpan> {
        Domain::bound(self, other)
    }

    /// Subtract `other` from this span, yielding 0, 1, or 2 spans.
    fn subtract(&self, other: &dyn ULongSpan) -> Vec<Box<dyn ULongSpan>> {
        Domain::subtract(self, other)
    }

    /// Compare two spans, ordering by (emptiness, min, max). Mirrors `Comparable<S>`.
    fn compare_to(&self, other: &dyn ULongSpan) -> Ordering {
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

/// The (fixed) domain of unsigned-long endpoints. Mirrors `ULongSpan.Domain`.
pub struct Domain;

impl Domain {
    /// The minimum value in the domain. Mirrors `Domain::min`.
    pub const MIN: u64 = 0;
    /// The maximum value in the domain. Mirrors `Domain::max`.
    pub const MAX: u64 = u64::MAX;

    /// Compare two endpoints.
    pub fn compare(n1: u64, n2: u64) -> Ordering {
        n1.cmp(&n2)
    }

    /// The endpoint immediately following `n`, wrapping to [`MIN`](Self::MIN) at [`MAX`](Self::MAX).
    pub fn inc(n: u64) -> u64 {
        n.wrapping_add(1)
    }

    /// The endpoint immediately preceding `n`, wrapping to [`MAX`](Self::MAX) at [`MIN`](Self::MIN).
    pub fn dec(n: u64) -> u64 {
        n.wrapping_sub(1)
    }

    /// Render a single endpoint.
    pub fn to_string(n: u64) -> String {
        n.to_string()
    }

    /// Create a closed interval `[min, max]`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `max < min`.
    pub fn closed(min: u64, max: u64) -> Impl {
        assert!(min <= max, "min > max: min={min},max={max}");
        Impl { min, max }
    }

    /// A span containing only `n`.
    pub fn value(n: u64) -> Impl {
        Self::closed(n, n)
    }

    /// A span from the domain minimum up to (and including) `max`.
    pub fn at_most(max: u64) -> Impl {
        Self::closed(Self::MIN, max)
    }

    /// A span from `min` up to (and including) the domain maximum.
    pub fn at_least(min: u64) -> Impl {
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
    pub fn display(s: &(impl ULongSpan + ?Sized)) -> String {
        if s.is_empty() {
            return "(empty)".to_string();
        }
        let min_s = if s.min() == Self::MIN { "(-inf".to_string() } else { format!("[{}", s.min()) };
        let max_s = if s.max() == Self::MAX { "+inf)".to_string() } else { format!("{}]", s.max()) };
        format!("{min_s}..{max_s}")
    }

    /// The intersection of `s1` and `s2`, possibly empty.
    pub fn intersect(s1: &(impl ULongSpan + ?Sized), s2: &dyn ULongSpan) -> Box<dyn ULongSpan> {
        if !Self::intersects(s1, s2) {
            return Box::new(Self::empty());
        }
        Box::new(Self::closed(s1.min().max(s2.min()), s1.max().min(s2.max())))
    }

    /// Whether `s1` and `s2` intersect.
    pub fn intersects(s1: &(impl ULongSpan + ?Sized), s2: &dyn ULongSpan) -> bool {
        if s1.is_empty() || s2.is_empty() {
            return false;
        }
        s1.max() >= s2.min() && s2.max() >= s1.min()
    }

    /// Whether `s1` encloses `s2`.
    pub fn encloses(s1: &(impl ULongSpan + ?Sized), s2: &dyn ULongSpan) -> bool {
        if s1.is_empty() {
            return false;
        }
        if s2.is_empty() {
            return true;
        }
        s1.min() <= s2.min() && s1.max() >= s2.max()
    }

    /// The smallest span containing both `s1` and `s2`.
    pub fn bound(s1: &(impl ULongSpan + ?Sized), s2: &dyn ULongSpan) -> Box<dyn ULongSpan> {
        if s1.is_empty() {
            return Self::reconstruct(s2);
        }
        if s2.is_empty() {
            return Self::reconstruct(s1);
        }
        Box::new(Self::closed(s1.min().min(s2.min()), s1.max().max(s2.max())))
    }

    /// Subtract `s2` from `s1`, yielding 0, 1, or 2 spans.
    pub fn subtract(s1: &(impl ULongSpan + ?Sized), s2: &dyn ULongSpan) -> Vec<Box<dyn ULongSpan>> {
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

    fn reconstruct(s: &(impl ULongSpan + ?Sized)) -> Box<dyn ULongSpan> {
        if s.is_empty() {
            Box::new(Empty)
        } else {
            Box::new(Impl { min: s.min(), max: s.max() })
        }
    }
}

/// The singleton empty span of unsigned longs. Mirrors `ULongSpan.Empty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Empty;

impl ULongSpan for Empty {
    fn min(&self) -> u64 {
        panic!("empty span has no minimum")
    }

    fn max(&self) -> u64 {
        panic!("empty span has no maximum")
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn length(&self) -> u64 {
        0
    }
}

/// A non-empty span of unsigned longs. Mirrors `ULongSpan.Impl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Impl {
    pub min: u64,
    pub max: u64,
}

impl ULongSpan for Impl {
    fn min(&self) -> u64 {
        self.min
    }

    fn max(&self) -> u64 {
        self.max
    }
}

/// The span containing every value in the domain. Mirrors `ULongSpan.ALL`.
pub const ALL: Impl = Impl { min: Domain::MIN, max: Domain::MAX };

/// The singleton empty span. Mirrors `ULongSpan.EMPTY`.
pub const EMPTY: Empty = Empty;

/// Create a closed interval of unsigned longs. Mirrors `ULongSpan.span`.
///
/// # Panics
/// Panics if `max < min`.
pub fn span(min: u64, max: u64) -> Impl {
    Domain::closed(min, max)
}

/// Create a closed interval of unsigned longs having the given length. Mirrors
/// `ULongSpan.extent`.
///
/// # Panics
/// Panics if the upper endpoint would exceed [`Domain::MAX`].
pub fn extent(min: u64, length: u64) -> Impl {
    Domain::closed(min, min.wrapping_add(length).wrapping_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock span computed from a base offset and width, distinct from [`Impl`], proving
    /// [`ULongSpan`] is object-safe and its default methods work for arbitrary implementors.
    struct RelativeSpan {
        base: u64,
        width: u64,
    }

    impl ULongSpan for RelativeSpan {
        fn min(&self) -> u64 {
            self.base
        }

        fn max(&self) -> u64 {
            self.base + self.width - 1
        }
    }

    #[test]
    fn test_span_and_extent_agree() {
        let a = span(10, 19);
        let b = extent(10, 10);
        assert_eq!(a, b);
        assert_eq!(a.length(), 10);
    }

    #[test]
    #[should_panic]
    fn test_span_max_less_than_min_panics() {
        span(5, 4);
    }

    #[test]
    fn test_all_and_empty_constants() {
        assert_eq!(ALL.min(), 0);
        assert_eq!(ALL.max(), u64::MAX);
        assert!(EMPTY.is_empty());
        assert_eq!(EMPTY.length(), 0);
    }

    #[test]
    #[should_panic]
    fn test_empty_min_panics() {
        EMPTY.min();
    }

    #[test]
    fn test_contains_and_finiteness() {
        let s = span(5, 9);
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
    fn test_display() {
        assert_eq!(span(5, 9).display(), "[5..9]");
        assert_eq!(ALL.display(), "(-inf..+inf)");
        assert_eq!(EMPTY.display(), "(empty)");
    }

    #[test]
    fn test_object_safety_via_trait_object() {
        let boxed: Box<dyn ULongSpan> = Box::new(RelativeSpan { base: 100, width: 5 });
        assert_eq!(boxed.min(), 100);
        assert_eq!(boxed.max(), 104);
        assert_eq!(boxed.length(), 5);
        assert!(boxed.contains(102));
        assert!(!boxed.contains(105));
    }

    #[test]
    fn test_intersect_and_intersects() {
        let a = span(1, 10);
        let b = span(5, 15);
        assert!(a.intersects(&b));
        let i = a.intersect(&b);
        assert_eq!(i.min(), 5);
        assert_eq!(i.max(), 10);

        let c = span(20, 30);
        assert!(!a.intersects(&c));
        assert!(a.intersect(&c).is_empty());
    }

    #[test]
    fn test_encloses() {
        let outer = span(1, 100);
        let inner = span(10, 20);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
        assert!(outer.encloses(&EMPTY));
        assert!(!EMPTY.encloses(&inner));
    }

    #[test]
    fn test_bound() {
        let a = span(1, 5);
        let b = span(20, 25);
        let bound = a.bound(&b);
        assert_eq!(bound.min(), 1);
        assert_eq!(bound.max(), 25);

        let bound_with_empty = a.bound(&EMPTY);
        assert_eq!(bound_with_empty.min(), 1);
        assert_eq!(bound_with_empty.max(), 5);
    }

    #[test]
    fn test_subtract_splits_in_two() {
        let whole = span(1, 10);
        let middle = span(4, 6);
        let parts = whole.subtract(&middle);
        assert_eq!(parts.len(), 2);
        assert_eq!((parts[0].min(), parts[0].max()), (1, 3));
        assert_eq!((parts[1].min(), parts[1].max()), (7, 10));
    }

    #[test]
    fn test_subtract_no_overlap_returns_original() {
        let a = span(1, 5);
        let b = span(10, 15);
        let parts = a.subtract(&b);
        assert_eq!(parts.len(), 1);
        assert_eq!((parts[0].min(), parts[0].max()), (1, 5));
    }

    #[test]
    fn test_subtract_full_overlap_returns_empty() {
        let a = span(5, 10);
        let b = span(1, 20);
        let parts = a.subtract(&b);
        assert!(parts.is_empty());
    }

    #[test]
    fn test_compare_to() {
        let a = span(1, 5);
        let b = span(1, 10);
        let c = span(2, 3);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(a.compare_to(&c), Ordering::Less);
        assert_eq!(EMPTY.compare_to(&a), Ordering::Less);
        assert_eq!(a.compare_to(&EMPTY), Ordering::Greater);
        assert_eq!(EMPTY.compare_to(&EMPTY), Ordering::Equal);
    }
}
