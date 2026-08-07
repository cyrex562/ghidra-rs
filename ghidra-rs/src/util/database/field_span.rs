//! Mirrors `ghidra.util.database.FieldSpan` from Ghidra: a span of database field values.
//!
//! In Java, `FieldSpan extends EndSpan<Field, FieldSpan>`, and `EndSpan<N, S> extends
//! Span<End<N>, S>`: a generic, self-referential interval type whose endpoints are
//! [`End<Field>`](crate::generic::end::End), not raw `Field` values. This is necessary because
//! `Field` has no well-defined successor: consider a string field ordered lexicographically --
//! there is no string that immediately precedes `"Span"`, since for any string with the prefix
//! `"Spam"` another character can be appended to find a string still preceding `"Span"`. So
//! [`End::inc`]/[`End::dec`] adjust only the endpoint's epsilon coefficient (open vs. closed),
//! never the underlying value, and open bounds are represented directly rather than simulated by
//! incrementing/decrementing a value.
//!
//! Following the same convention established by [`crate::util::database::KeySpan`] and
//! [`crate::generic::ulong_span::ULongSpan`] for their respective (discrete) domains, the
//! domain-level operations declared on `Span.Domain`/`EndDomain` are ported here as associated
//! functions on [`Domain`] rather than as a separate generic trait, and the span-instance
//! operations declared on `Span`/`EndSpan` are flattened directly into the [`FieldSpan`] trait.

use std::cmp::Ordering;

use crate::framework::db::field::Field;
use crate::generic::end::{self, End, Epsilon, Point, Unbound};
use crate::util::database::Direction;

/// A span of database field values. Mirrors the `FieldSpan` interface.
pub trait FieldSpan: Send + Sync {
    /// The lower endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn min(&self) -> &dyn End<Field>;

    /// The upper endpoint.
    ///
    /// # Panics
    /// Mirrors `NoSuchElementException`: panics if [`is_empty`](Self::is_empty) is `true`.
    fn max(&self) -> &dyn End<Field>;

    /// Whether this span contains no values.
    fn is_empty(&self) -> bool {
        false
    }

    /// Whether the lower endpoint excludes the domain minimum (negative infinity).
    fn min_is_finite(&self) -> bool {
        !Domain::is_neg_inf(self.min())
    }

    /// Whether the upper endpoint excludes the domain maximum (positive infinity).
    fn max_is_finite(&self) -> bool {
        !Domain::is_pos_inf(self.max())
    }

    /// Whether this span contains the given endpoint. Mirrors `Span.contains(End<Field>)`.
    fn contains_end(&self, n: &dyn End<Field>) -> bool {
        Domain::contains_end(self, n)
    }

    /// Whether this span contains the given field value. Mirrors `EndSpan.containsPoint(Field)`.
    fn contains(&self, n: &Field) -> bool {
        Domain::contains(self, n)
    }

    /// Render this span, e.g. `"[5..9]"`, `"(-inf..9]"`, or `"(empty)"`.
    fn display(&self) -> String {
        Domain::display(self)
    }

    /// The intersection of this span and `other`, possibly empty.
    fn intersect(&self, other: &dyn FieldSpan) -> Box<dyn FieldSpan> {
        Domain::intersect(self, other)
    }

    /// Whether this span intersects `other`.
    fn intersects(&self, other: &dyn FieldSpan) -> bool {
        Domain::intersects(self, other)
    }

    /// Whether this span encloses `other`.
    fn encloses(&self, other: &dyn FieldSpan) -> bool {
        Domain::encloses(self, other)
    }

    /// The smallest span containing both this span and `other`.
    fn bound(&self, other: &dyn FieldSpan) -> Box<dyn FieldSpan> {
        Domain::bound(self, other)
    }

    /// Subtract `other` from this span, yielding 0, 1, or 2 spans.
    fn subtract(&self, other: &dyn FieldSpan) -> Vec<Box<dyn FieldSpan>> {
        Domain::subtract(self, other)
    }

    /// Compare two spans, ordering by (emptiness, min, max). Mirrors `Comparable<S>`.
    fn compare_to(&self, other: &dyn FieldSpan) -> Ordering {
        Domain::compare_spans(self, other)
    }
}

/// The domain of field values, admitting open endpoints. Mirrors `FieldSpan.Domain`.
pub struct Domain;

impl Domain {
    /// The endpoint representing no lower bound. Mirrors `EndDomain.min` (`End.negativeInfinity`).
    pub fn min() -> Box<dyn End<Field>> {
        end::negative_infinity()
    }

    /// The endpoint representing no upper bound. Mirrors `EndDomain.max` (`End.positiveInfinity`).
    pub fn max() -> Box<dyn End<Field>> {
        end::positive_infinity()
    }

    /// Compare two endpoints. Mirrors `EndDomain.compare`.
    pub fn compare(n1: &dyn End<Field>, n2: &dyn End<Field>) -> Ordering {
        n1.compare_to(n2, &|a: &Field, b: &Field| a.cmp(b))
    }

    fn is_neg_inf(e: &dyn End<Field>) -> bool {
        matches!(e.as_any().downcast_ref::<Unbound>(), Some(Unbound::NegInf))
    }

    fn is_pos_inf(e: &dyn End<Field>) -> bool {
        matches!(e.as_any().downcast_ref::<Unbound>(), Some(Unbound::PosInf))
    }

    /// Increment an endpoint. Mirrors `EndDomain.inc`.
    pub fn inc(n: &dyn End<Field>) -> Box<dyn End<Field>> {
        n.inc()
    }

    /// Decrement an endpoint. Mirrors `EndDomain.dec`.
    pub fn dec(n: &dyn End<Field>) -> Box<dyn End<Field>> {
        n.dec()
    }

    /// Clone an endpoint. `End<Field>` is sealed in practice to [`Unbound`] and `Point<Field>`.
    fn clone_end(e: &dyn End<Field>) -> Box<dyn End<Field>> {
        if let Some(u) = e.as_any().downcast_ref::<Unbound>() {
            return Box::new(*u);
        }
        if let Some(p) = e.as_any().downcast_ref::<Point<Field>>() {
            return Box::new(Point { val: p.val.clone(), epsilon: p.epsilon });
        }
        unreachable!("End<Field> is sealed in practice to Unbound and Point endpoints")
    }

    fn min_end(a: &dyn End<Field>, b: &dyn End<Field>) -> Box<dyn End<Field>> {
        if Self::compare(a, b) == Ordering::Less { Self::clone_end(a) } else { Self::clone_end(b) }
    }

    fn max_end(a: &dyn End<Field>, b: &dyn End<Field>) -> Box<dyn End<Field>> {
        if Self::compare(a, b) == Ordering::Less { Self::clone_end(b) } else { Self::clone_end(a) }
    }

    /// Create a closed interval `[min, max]`. Mirrors `FieldSpan.Domain.closed` (which validates
    /// `isValidMin`/`isValidMax` before delegating to `Span.Domain.closed`'s own `min <= max`
    /// check).
    ///
    /// # Panics
    /// Panics if `min` is not a valid lower endpoint, `max` is not a valid upper endpoint, or
    /// `max < min`.
    pub fn closed(min: Box<dyn End<Field>>, max: Box<dyn End<Field>>) -> Impl {
        assert!(min.is_valid_min(), "Invalid min");
        assert!(max.is_valid_max(), "Invalid max");
        assert!(Self::compare(min.as_ref(), max.as_ref()) != Ordering::Greater, "min > max");
        Impl { min, max }
    }

    /// The span containing every value in the domain. Mirrors `FieldSpan.Domain.all`.
    pub fn all() -> Impl {
        Impl { min: Self::min(), max: Self::max() }
    }

    /// The span containing no values. Mirrors `FieldSpan.Domain.empty`.
    pub fn empty() -> Empty {
        Empty
    }

    fn end_to_string(e: &dyn End<Field>) -> String {
        match e.as_any().downcast_ref::<Point<Field>>() {
            Some(p) => format!("{:?}", p.val),
            None => "?".to_string(),
        }
    }

    /// Render `s`, e.g. `"[5..9]"`, `"(-inf..9]"`, or `"(empty)"`.
    pub fn display(s: &(impl FieldSpan + ?Sized)) -> String {
        if s.is_empty() {
            return "(empty)".to_string();
        }
        format!(
            "{}..{}",
            s.min().to_min_string(&Self::end_to_string),
            s.max().to_max_string(&Self::end_to_string)
        )
    }

    /// Whether `s` contains the endpoint `n`. Mirrors `Span.contains(End<Field>)`.
    pub fn contains_end(s: &(impl FieldSpan + ?Sized), n: &dyn End<Field>) -> bool {
        !s.is_empty()
            && Self::compare(s.min(), n) != Ordering::Greater
            && Self::compare(n, s.max()) != Ordering::Greater
    }

    /// Whether `s` contains the field value `n`. Mirrors `EndSpan.containsPoint(Field)`.
    pub fn contains(s: &(impl FieldSpan + ?Sized), n: &Field) -> bool {
        Self::contains_end(s, &Point { val: n.clone(), epsilon: Epsilon::Zero })
    }

    /// The intersection of `s1` and `s2`, possibly empty.
    pub fn intersect(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> Box<dyn FieldSpan> {
        if !Self::intersects(s1, s2) {
            return Box::new(Self::empty());
        }
        Box::new(Self::closed(Self::max_end(s1.min(), s2.min()), Self::min_end(s1.max(), s2.max())))
    }

    /// Whether `s1` and `s2` intersect.
    pub fn intersects(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> bool {
        if s1.is_empty() || s2.is_empty() {
            return false;
        }
        Self::compare(s1.max(), s2.min()) != Ordering::Less && Self::compare(s2.max(), s1.min()) != Ordering::Less
    }

    /// Whether `s1` encloses `s2`.
    pub fn encloses(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> bool {
        if s1.is_empty() {
            return false;
        }
        if s2.is_empty() {
            return true;
        }
        Self::compare(s1.min(), s2.min()) != Ordering::Greater && Self::compare(s1.max(), s2.max()) != Ordering::Less
    }

    /// The smallest span containing both `s1` and `s2`.
    pub fn bound(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> Box<dyn FieldSpan> {
        if s1.is_empty() {
            return Self::reconstruct(s2);
        }
        if s2.is_empty() {
            return Self::reconstruct(s1);
        }
        Box::new(Self::closed(Self::min_end(s1.min(), s2.min()), Self::max_end(s1.max(), s2.max())))
    }

    /// Subtract `s2` from `s1`, yielding 0, 1, or 2 spans.
    pub fn subtract(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> Vec<Box<dyn FieldSpan>> {
        if s1.is_empty() {
            return Vec::new();
        }
        if s2.is_empty() {
            return vec![Self::reconstruct(s1)];
        }
        if Self::compare(s1.max(), s2.min()) == Ordering::Less || Self::compare(s2.max(), s1.min()) == Ordering::Less
        {
            return vec![Self::reconstruct(s1)];
        }
        if Self::compare(s1.min(), s2.min()) == Ordering::Less {
            if Self::compare(s1.max(), s2.max()) == Ordering::Greater {
                return vec![
                    Box::new(Self::closed(Self::clone_end(s1.min()), Self::dec(s2.min()))),
                    Box::new(Self::closed(Self::inc(s2.max()), Self::clone_end(s1.max()))),
                ];
            }
            return vec![Box::new(Self::closed(Self::clone_end(s1.min()), Self::dec(s2.min())))];
        }
        if Self::compare(s1.max(), s2.max()) == Ordering::Greater {
            return vec![Box::new(Self::closed(Self::inc(s2.max()), Self::clone_end(s1.max())))];
        }
        Vec::new()
    }

    /// Compare two spans, ordering by (emptiness, min, max). Mirrors `Span.compareTo`.
    pub fn compare_spans(s1: &(impl FieldSpan + ?Sized), s2: &dyn FieldSpan) -> Ordering {
        if s1.is_empty() {
            return if s2.is_empty() { Ordering::Equal } else { Ordering::Less };
        }
        if s2.is_empty() {
            return Ordering::Greater;
        }
        match Self::compare(s1.min(), s2.min()) {
            Ordering::Equal => Self::compare(s1.max(), s2.max()),
            ord => ord,
        }
    }

    fn reconstruct(s: &(impl FieldSpan + ?Sized)) -> Box<dyn FieldSpan> {
        if s.is_empty() {
            Box::new(Empty)
        } else {
            Box::new(Impl { min: Self::clone_end(s.min()), max: Self::clone_end(s.max()) })
        }
    }
}

/// The singleton empty span of field values. Mirrors `FieldSpan.Empty`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Empty;

impl FieldSpan for Empty {
    fn min(&self) -> &dyn End<Field> {
        panic!("empty span has no minimum")
    }

    fn max(&self) -> &dyn End<Field> {
        panic!("empty span has no maximum")
    }

    fn is_empty(&self) -> bool {
        true
    }
}

/// A span of field values. Mirrors `FieldSpan.Impl`.
pub struct Impl {
    pub min: Box<dyn End<Field>>,
    pub max: Box<dyn End<Field>>,
}

impl FieldSpan for Impl {
    fn min(&self) -> &dyn End<Field> {
        self.min.as_ref()
    }

    fn max(&self) -> &dyn End<Field> {
        self.max.as_ref()
    }
}

/// The singleton empty span. Mirrors `FieldSpan.EMPTY`.
pub const EMPTY: Empty = Empty;

/// The span containing every value in the domain. Mirrors `FieldSpan.ALL`.
pub fn all() -> Impl {
    Domain::all()
}

/// Get the span for a sub collection. Mirrors `FieldSpan.sub`.
///
/// `from` must precede `to`, unless `direction` is [`Direction::Backward`], in which case the
/// opposite is required. The endpoints may be equal but unless both are inclusive, the result is
/// [`EMPTY`]. The two endpoints are not automatically inverted to correct ordering.
pub fn sub(from: Field, from_inclusive: bool, to: Field, to_inclusive: bool, direction: Direction) -> Box<dyn FieldSpan> {
    if from == to && (!from_inclusive || !to_inclusive) {
        return Box::new(EMPTY);
    }
    if direction == Direction::Forward {
        Box::new(Domain::closed(end::lower(from, from_inclusive), end::upper(to, to_inclusive)))
    } else {
        Box::new(Domain::closed(end::lower(to, to_inclusive), end::upper(from, from_inclusive)))
    }
}

/// Get the span for the head of a collection. Mirrors `FieldSpan.head`.
///
/// When `direction` is [`Direction::Backward`] this behaves as if a tail collection; however,
/// the implication is that iteration will start from the maximum and proceed toward the given
/// bound.
pub fn head(to: Field, to_inclusive: bool, direction: Direction) -> Box<dyn FieldSpan> {
    if direction == Direction::Forward {
        Box::new(Domain::closed(end::negative_infinity(), end::upper(to, to_inclusive)))
    } else {
        Box::new(Domain::closed(end::lower(to, to_inclusive), end::positive_infinity()))
    }
}

/// Get the span for the tail of a collection. Mirrors `FieldSpan.tail`.
///
/// When `direction` is [`Direction::Backward`] this behaves as if a head collection; however,
/// the implication is that iteration will start from the bound and proceed toward the minimum.
pub fn tail(from: Field, from_inclusive: bool, direction: Direction) -> Box<dyn FieldSpan> {
    if direction == Direction::Forward {
        Box::new(Domain::closed(end::lower(from, from_inclusive), end::positive_infinity()))
    } else {
        Box::new(Domain::closed(end::negative_infinity(), end::upper(from, from_inclusive)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(n: i64) -> Field {
        Field::Long(Some(n))
    }

    /// A mock span computed from a base offset and width, distinct from [`Impl`], proving
    /// [`FieldSpan`] is object-safe and its default methods work for arbitrary implementors.
    struct RelativeSpan {
        min: Box<dyn End<Field>>,
        max: Box<dyn End<Field>>,
    }

    impl RelativeSpan {
        fn new(base: i64, width: i64) -> Self {
            RelativeSpan { min: end::lower(f(base), true), max: end::upper(f(base + width - 1), true) }
        }
    }

    impl FieldSpan for RelativeSpan {
        fn min(&self) -> &dyn End<Field> {
            self.min.as_ref()
        }

        fn max(&self) -> &dyn End<Field> {
            self.max.as_ref()
        }
    }

    #[test]
    fn test_object_safety_via_trait_object() {
        let boxed: Box<dyn FieldSpan> = Box::new(RelativeSpan::new(100, 5));
        assert!(boxed.contains(&f(102)));
        assert!(!boxed.contains(&f(105)));
    }

    #[test]
    fn test_all_and_empty() {
        let all = all();
        assert!(!all.min_is_finite());
        assert!(!all.max_is_finite());
        assert!(EMPTY.is_empty());
    }

    #[test]
    #[should_panic]
    fn test_empty_min_panics() {
        EMPTY.min();
    }

    #[test]
    fn test_sub_closed_and_contains() {
        let s = sub(f(5), true, f(9), true, Direction::Forward);
        assert!(s.contains(&f(5)));
        assert!(s.contains(&f(9)));
        assert!(!s.contains(&f(4)));
        assert!(!s.contains(&f(10)));
        assert!(s.min_is_finite());
        assert!(s.max_is_finite());
    }

    #[test]
    fn test_sub_open_endpoints_exclude_boundary() {
        // (5..9) exclusive on both ends: 5 and 9 are excluded, but the span is not "empty" --
        // it just has no representable min()/max() Field via containment at the boundary.
        let s = sub(f(5), false, f(9), false, Direction::Forward);
        assert!(!s.contains(&f(5)));
        assert!(!s.contains(&f(9)));
        assert!(s.contains(&f(6)));
        assert!(s.contains(&f(8)));
    }

    #[test]
    fn test_sub_equal_exclusive_is_empty() {
        let s = sub(f(5), true, f(5), false, Direction::Forward);
        assert!(s.is_empty());
    }

    #[test]
    fn test_sub_backward_swaps_endpoints() {
        let fwd = sub(f(1), true, f(10), true, Direction::Forward);
        let bwd = sub(f(10), true, f(1), true, Direction::Backward);
        assert_eq!(fwd.compare_to(bwd.as_ref()), Ordering::Equal);
    }

    #[test]
    fn test_head_and_tail() {
        let h = head(f(10), true, Direction::Forward);
        assert!(h.contains(&f(10)));
        assert!(!h.min_is_finite());
        assert!(h.max_is_finite());

        let t = tail(f(10), true, Direction::Forward);
        assert!(t.contains(&f(10)));
        assert!(t.min_is_finite());
        assert!(!t.max_is_finite());
    }

    #[test]
    fn test_intersect_and_intersects() {
        let a = sub(f(1), true, f(10), true, Direction::Forward);
        let b = sub(f(5), true, f(15), true, Direction::Forward);
        assert!(a.intersects(b.as_ref()));
        let i = a.intersect(b.as_ref());
        assert!(i.contains(&f(5)));
        assert!(i.contains(&f(10)));
        assert!(!i.contains(&f(4)));
        assert!(!i.contains(&f(11)));

        let c = sub(f(20), true, f(30), true, Direction::Forward);
        assert!(!a.intersects(c.as_ref()));
        assert!(a.intersect(c.as_ref()).is_empty());
    }

    #[test]
    fn test_encloses_and_bound() {
        let outer = sub(f(1), true, f(100), true, Direction::Forward);
        let inner = sub(f(10), true, f(20), true, Direction::Forward);
        assert!(outer.encloses(inner.as_ref()));
        assert!(!inner.encloses(outer.as_ref()));

        let bound = inner.bound(sub(f(200), true, f(210), true, Direction::Forward).as_ref());
        assert!(bound.contains(&f(10)));
        assert!(bound.contains(&f(210)));
        assert!(bound.contains(&f(150)));
        assert!(!bound.contains(&f(5)));
        assert!(!bound.contains(&f(300)));
    }

    #[test]
    fn test_subtract_splits_in_two() {
        let whole = sub(f(1), true, f(10), true, Direction::Forward);
        let middle = sub(f(4), true, f(6), true, Direction::Forward);
        let parts = whole.subtract(middle.as_ref());
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains(&f(1)));
        assert!(parts[0].contains(&f(3)));
        assert!(!parts[0].contains(&f(4)));
        assert!(parts[1].contains(&f(7)));
        assert!(parts[1].contains(&f(10)));
    }

    #[test]
    fn test_compare_to() {
        let a = sub(f(1), true, f(5), true, Direction::Forward);
        let b = sub(f(1), true, f(10), true, Direction::Forward);
        assert_eq!(a.compare_to(a.as_ref()), Ordering::Equal);
        assert_eq!(a.compare_to(b.as_ref()), Ordering::Less);
        assert_eq!(EMPTY.compare_to(a.as_ref()), Ordering::Less);
        assert_eq!(a.compare_to(&EMPTY), Ordering::Greater);
    }

    #[test]
    fn test_display() {
        let s = sub(f(5), true, f(9), true, Direction::Forward);
        assert_eq!(s.display(), "[Long(Some(5))..Long(Some(9))]");
        assert_eq!(EMPTY.display(), "(empty)");
    }
}
