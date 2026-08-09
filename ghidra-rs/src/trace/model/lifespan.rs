//! A closed range on snapshot keys, indicating a duration of time.
//!
//! Java source: `ghidra.trace.model.Lifespan`.
//!
//! In the original this is `public sealed interface Lifespan extends Span<Long, Lifespan>,
//! Iterable<Long>`, permitting exactly two implementors: the singleton `Lifespan.Empty` and the
//! `record Lifespan.Impl(long lmin, long lmax)`. A `sealed` hierarchy with a known permit list is
//! a closed set of alternatives, which in Rust is an `enum` -- see `scripts/shape_rules.py`
//! rule R2 and the shape table in AGENTS.md.
//!
//! It was previously ported as `pub trait Lifespan` with boxed trait-object returns. That shape
//! reopened a set Java had deliberately closed, and it was contagious: 613 trait-object uses
//! were written against it, every implementor in the crate was a test double because nothing
//! could construct a real one, and `TraceLabelSymbolView` had to promote three of Java's
//! *default* methods to required ones with a doc comment explaining that `Lifespan` had "no
//! concrete, generically-constructible implementor yet". None of that failed a build or a test.
//!
//! As an enum it is `Copy`, so it is passed by value like the `long`-pair it is.
//!
//! The `Empty` variant is faithful to Java's `Lifespan.Empty`, whose `lmin()`/`lmax()` throw
//! `NoSuchElementException`; here they panic. Use [`Lifespan::min_snap`]/[`Lifespan::max_snap`] for the
//! total, `Option`-returning form.

use std::cmp::Ordering;
use std::fmt;
use std::ops::RangeInclusive;

/// A closed range `[min, max]` on snapshot keys.
///
/// Mirrors Java's sealed `Lifespan`: either the singleton empty span, or an inclusive pair of
/// endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lifespan {
    /// The empty lifespan, containing no snapshot keys.
    ///
    /// Java's `Lifespan.Empty.INSTANCE`.
    Empty,
    /// An inclusive range of snapshot keys.
    ///
    /// Java's `Lifespan.Impl(lmin, lmax)`. Held to `min <= max` by every constructor here.
    Span {
        /// The lower (inclusive) endpoint.
        min: i64,
        /// The upper (inclusive) endpoint.
        max: i64,
    },
}

impl Lifespan {
    /// The lifespan covering every snapshot key.
    ///
    /// Java's `Lifespan.ALL`.
    pub const ALL: Lifespan = Lifespan::Span { min: i64::MIN, max: i64::MAX };

    /// The lifespan containing no snapshot keys.
    ///
    /// Java's `Lifespan.EMPTY`.
    pub const EMPTY: Lifespan = Lifespan::Empty;

    /// The lifespan for the given snap bounds.
    ///
    /// Java's `Lifespan.span(long, long)`, via `Domain.closed`.
    ///
    /// # Panics
    /// Panics if `max_snap < min_snap`, as Java's `Domain.closed` throws
    /// `IllegalArgumentException`. Use [`Lifespan::try_span`] to handle that case.
    pub fn span(min_snap: i64, max_snap: i64) -> Lifespan {
        Lifespan::try_span(min_snap, max_snap)
            .unwrap_or_else(|| panic!("max < min: min={min_snap},max={max_snap}"))
    }

    /// The lifespan for the given snap bounds, or `None` if they are inverted.
    ///
    /// The non-panicking form of [`Lifespan::span`].
    pub fn try_span(min_snap: i64, max_snap: i64) -> Option<Lifespan> {
        (min_snap <= max_snap).then_some(Lifespan::Span { min: min_snap, max: max_snap })
    }

    /// The lifespan covering only the given snap.
    ///
    /// Java's `Lifespan.at(long)`.
    pub fn at(snap: i64) -> Lifespan {
        Lifespan::Span { min: snap, max: snap }
    }

    /// The lifespan from 0 up to and including the given snap.
    ///
    /// Java's `Lifespan.since(long)`. A scratch snap takes a lower endpoint of [`i64::MIN`];
    /// otherwise the lower endpoint is 0, which excludes scratch space.
    pub fn since(snap: i64) -> Lifespan {
        Lifespan::Span { min: if is_scratch(snap) { i64::MIN } else { 0 }, max: snap }
    }

    /// The lifespan from the given snap into the indefinite future.
    ///
    /// Java's `Lifespan.nowOn(long)`.
    pub fn now_on(snap: i64) -> Lifespan {
        Lifespan::Span { min: snap, max: i64::MAX }
    }

    /// The lifespan from the given snap into the indefinite future, considering scratch space.
    ///
    /// Java's `Lifespan.nowOnMaybeScratch(long)`. A scratch snap takes an upper endpoint of -1,
    /// the last scratch snapshot; otherwise this matches [`Lifespan::now_on`].
    pub fn now_on_maybe_scratch(snap: i64) -> Lifespan {
        Lifespan::Span { min: snap, max: if is_scratch(snap) { -1 } else { i64::MAX } }
    }

    /// The lifespan from the given snap into the indefinite past, including scratch.
    ///
    /// Java's `Lifespan.toNow(long)`.
    pub fn to_now(snap: i64) -> Lifespan {
        Lifespan::Span { min: i64::MIN, max: snap }
    }

    /// The lifespan excluding the given snap and every snap after it.
    ///
    /// Java's `Lifespan.before(long)`; empty when `snap` is already the domain minimum.
    pub fn before(snap: i64) -> Lifespan {
        if snap == i64::MIN {
            Lifespan::Empty
        } else {
            Lifespan::Span { min: i64::MIN, max: snap - 1 }
        }
    }

    /// The lower (inclusive) endpoint of this span.
    ///
    /// # Panics
    /// Panics on [`Lifespan::Empty`], as Java's `Empty.lmin()` throws `NoSuchElementException`.
    pub fn lmin(&self) -> i64 {
        match self {
            Lifespan::Span { min, .. } => *min,
            Lifespan::Empty => panic!("lmin() on an empty lifespan"),
        }
    }

    /// The upper (inclusive) endpoint of this span.
    ///
    /// # Panics
    /// Panics on [`Lifespan::Empty`], as Java's `Empty.lmax()` throws `NoSuchElementException`.
    pub fn lmax(&self) -> i64 {
        match self {
            Lifespan::Span { max, .. } => *max,
            Lifespan::Empty => panic!("lmax() on an empty lifespan"),
        }
    }

    /// The lower endpoint, or `None` when empty. The total form of [`Lifespan::lmin`].
    ///
    /// Named `min_snap` rather than `min` because an inherent `min(&self)` loses method
    /// resolution to `Ord::min(self, other)`: at receiver step `Lifespan`, the by-value trait
    /// method is a candidate and the `&self` inherent one is not, so `span.min()` would silently
    /// resolve to `Ord::min` and fail to compile at every call site.
    pub fn min_snap(&self) -> Option<i64> {
        match self {
            Lifespan::Span { min, .. } => Some(*min),
            Lifespan::Empty => None,
        }
    }

    /// The upper endpoint, or `None` when empty. The total form of [`Lifespan::lmax`].
    ///
    /// Named `max_snap` for the same reason as [`Lifespan::min_snap`].
    pub fn max_snap(&self) -> Option<i64> {
        match self {
            Lifespan::Span { max, .. } => Some(*max),
            Lifespan::Empty => None,
        }
    }

    /// Checks whether the given snapshot key falls within this span.
    pub fn contains(&self, n: i64) -> bool {
        match self {
            Lifespan::Span { min, max } => *min <= n && n <= *max,
            Lifespan::Empty => false,
        }
    }

    /// Checks whether this span contains no snapshot keys.
    pub fn is_empty(&self) -> bool {
        matches!(self, Lifespan::Empty)
    }

    /// Checks whether the lower endpoint excludes the domain minimum ([`i64::MIN`]).
    pub fn min_is_finite(&self) -> bool {
        self.min_snap().is_some_and(|m| m != i64::MIN)
    }

    /// Checks whether the upper endpoint excludes the domain maximum ([`i64::MAX`]).
    pub fn max_is_finite(&self) -> bool {
        self.max_snap().is_some_and(|m| m != i64::MAX)
    }

    /// This span with its lower endpoint replaced.
    ///
    /// Java's `default Lifespan withMin(long)`.
    ///
    /// # Panics
    /// Panics if the result would be inverted, or if this span is empty.
    pub fn with_min(&self, min: i64) -> Lifespan {
        Lifespan::span(min, self.lmax())
    }

    /// This span with its upper endpoint replaced.
    ///
    /// Java's `default Lifespan withMax(long)`.
    ///
    /// # Panics
    /// Panics if the result would be inverted, or if this span is empty.
    pub fn with_max(&self, max: i64) -> Lifespan {
        Lifespan::span(self.lmin(), max)
    }

    /// The parts of this span not covered by `other`, in ascending order.
    ///
    /// Java's `default List<Lifespan> subtract(Lifespan)`, inherited from `Span`. Yields 0, 1, or
    /// 2 spans: none when `other` covers this one, two when `other` splits it. Mirrors
    /// [`Domain::subtract`](crate::generic::ulong_span::Domain::subtract), the same `Span`
    /// operation already ported for the unsigned-long domain.
    pub fn subtract(&self, other: Lifespan) -> Vec<Lifespan> {
        let (Lifespan::Span { min, max }, Lifespan::Span { min: omin, max: omax }) =
            (*self, other)
        else {
            // Nothing to subtract from an empty span; nothing removed by an empty one.
            return match self {
                Lifespan::Empty => Vec::new(),
                _ => vec![*self],
            };
        };
        if max < omin || omax < min {
            return vec![*self];
        }
        let mut result = Vec::with_capacity(2);
        if min < omin {
            // omin > min >= i64::MIN, so omin - 1 cannot underflow.
            result.push(Lifespan::Span { min, max: omin - 1 });
        }
        if max > omax {
            // omax < max <= i64::MAX, so omax + 1 cannot overflow.
            result.push(Lifespan::Span { min: omax + 1, max });
        }
        result
    }

    /// Iterates the snapshot keys contained in this span.
    ///
    /// Java's `Iterable<Long>`. An empty span yields an empty (rather than absent) iterator, so
    /// callers need no special case.
    pub fn iter(&self) -> RangeInclusive<i64> {
        match self {
            Lifespan::Span { min, max } => *min..=*max,
            // An inverted RangeInclusive is empty, which is exactly the wanted behaviour.
            Lifespan::Empty => 1..=0,
        }
    }
}

impl IntoIterator for Lifespan {
    type Item = i64;
    type IntoIter = RangeInclusive<i64>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Orders spans by lower endpoint, then upper endpoint, treating empty spans as least.
impl Ord for Lifespan {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Lifespan::Empty, Lifespan::Empty) => Ordering::Equal,
            (Lifespan::Empty, _) => Ordering::Less,
            (_, Lifespan::Empty) => Ordering::Greater,
            (Lifespan::Span { min: a1, max: a2 }, Lifespan::Span { min: b1, max: b2 }) => {
                a1.cmp(b1).then_with(|| a2.cmp(b2))
            }
        }
    }
}

impl PartialOrd for Lifespan {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for Lifespan {
    fn default() -> Self {
        Lifespan::Empty
    }
}

impl fmt::Display for Lifespan {
    /// Mirrors Java's `Impl.toString`/`Empty.toString`: `[min,max]`, with an unbounded endpoint
    /// rendered `-inf`/`+inf`, and `(EMPTY)` for the empty span.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lifespan::Empty => f.write_str("(EMPTY)"),
            Lifespan::Span { min, max } => {
                write!(f, "[")?;
                if *min == i64::MIN {
                    write!(f, "-inf")?;
                } else {
                    write!(f, "{min}")?;
                }
                write!(f, ",")?;
                if *max == i64::MAX {
                    write!(f, "+inf")?;
                } else {
                    write!(f, "{max}")?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Checks whether a snapshot key is designated as scratch space.
///
/// Conventionally, negative snaps are scratch space.
pub fn is_scratch(snap: i64) -> bool {
    snap < 0
}

#[cfg(test)]
mod tests {
    use super::{is_scratch, Lifespan};
    use std::cmp::Ordering;

    #[test]
    fn contains_within_bounds() {
        let s = Lifespan::span(10, 20);
        assert!(s.contains(10));
        assert!(s.contains(20));
        assert!(!s.contains(9));
        assert!(!s.contains(21));
    }

    #[test]
    fn empty_contains_nothing_and_reports_empty() {
        let e = Lifespan::EMPTY;
        assert!(e.is_empty());
        assert!(!e.contains(0));
        assert!(!e.contains(i64::MIN));
        assert_eq!(e.min_snap(), None);
        assert_eq!(e.max_snap(), None);
    }

    #[test]
    #[should_panic(expected = "lmin() on an empty lifespan")]
    fn lmin_on_empty_panics_as_java_throws() {
        Lifespan::EMPTY.lmin();
    }

    #[test]
    fn with_min_and_with_max_replace_one_endpoint() {
        let s = Lifespan::span(10, 20);
        assert_eq!(s.with_min(5), Lifespan::span(5, 20));
        assert_eq!(s.with_max(30), Lifespan::span(10, 30));
    }

    #[test]
    #[should_panic(expected = "max < min")]
    fn inverted_span_panics_as_java_throws() {
        Lifespan::span(20, 10);
    }

    #[test]
    fn try_span_reports_inversion_instead_of_panicking() {
        assert_eq!(Lifespan::try_span(10, 20), Some(Lifespan::span(10, 20)));
        assert_eq!(Lifespan::try_span(20, 10), None);
    }

    #[test]
    fn iter_yields_all_snaps_in_range() {
        assert_eq!(Lifespan::span(3, 6).iter().collect::<Vec<_>>(), vec![3, 4, 5, 6]);
        assert_eq!(Lifespan::at(7).iter().collect::<Vec<_>>(), vec![7]);
        assert_eq!(Lifespan::EMPTY.iter().next(), None);
    }

    #[test]
    fn finiteness_tracks_the_domain_bounds() {
        assert!(Lifespan::span(0, 10).min_is_finite());
        assert!(Lifespan::span(0, 10).max_is_finite());
        assert!(!Lifespan::ALL.min_is_finite());
        assert!(!Lifespan::ALL.max_is_finite());
        assert!(!Lifespan::now_on(5).max_is_finite());
        assert!(Lifespan::now_on(5).min_is_finite());
    }

    #[test]
    fn constructors_match_the_java_endpoints() {
        assert_eq!(Lifespan::at(4), Lifespan::span(4, 4));
        assert_eq!(Lifespan::now_on(4), Lifespan::span(4, i64::MAX));
        assert_eq!(Lifespan::to_now(4), Lifespan::span(i64::MIN, 4));
        // since(): a non-scratch snap excludes scratch space by starting at 0.
        assert_eq!(Lifespan::since(4), Lifespan::span(0, 4));
        assert_eq!(Lifespan::since(-4), Lifespan::span(i64::MIN, -4));
        // nowOnMaybeScratch(): a scratch snap stops at -1, the last scratch snapshot.
        assert_eq!(Lifespan::now_on_maybe_scratch(-4), Lifespan::span(-4, -1));
        assert_eq!(Lifespan::now_on_maybe_scratch(4), Lifespan::span(4, i64::MAX));
        assert_eq!(Lifespan::before(4), Lifespan::span(i64::MIN, 3));
        assert_eq!(Lifespan::before(i64::MIN), Lifespan::EMPTY);
        assert_eq!(Lifespan::ALL, Lifespan::span(i64::MIN, i64::MAX));
    }

    #[test]
    fn ordering_puts_empty_first_then_sorts_by_endpoints() {
        assert_eq!(Lifespan::EMPTY.cmp(&Lifespan::span(0, 1)), Ordering::Less);
        assert_eq!(Lifespan::span(0, 1).cmp(&Lifespan::EMPTY), Ordering::Greater);
        assert_eq!(Lifespan::EMPTY.cmp(&Lifespan::EMPTY), Ordering::Equal);
        assert_eq!(Lifespan::span(0, 5).cmp(&Lifespan::span(1, 2)), Ordering::Less);
        assert_eq!(Lifespan::span(0, 5).cmp(&Lifespan::span(0, 9)), Ordering::Less);
        assert_eq!(Lifespan::span(0, 5).cmp(&Lifespan::span(0, 5)), Ordering::Equal);
    }

    #[test]
    fn display_marks_unbounded_endpoints() {
        assert_eq!(Lifespan::span(2, 7).to_string(), "[2,7]");
        assert_eq!(Lifespan::ALL.to_string(), "[-inf,+inf]");
        assert_eq!(Lifespan::now_on(3).to_string(), "[3,+inf]");
        assert_eq!(Lifespan::to_now(3).to_string(), "[-inf,3]");
        assert_eq!(Lifespan::EMPTY.to_string(), "(EMPTY)");
    }

    #[test]
    fn scratch_space_is_the_negative_snaps() {
        assert!(is_scratch(-1));
        assert!(!is_scratch(0));
        assert!(!is_scratch(1));
    }

    #[test]
    fn subtract_yields_zero_one_or_two_spans() {
        let whole = Lifespan::span(0, 10);
        // Disjoint: nothing removed.
        assert_eq!(whole.subtract(Lifespan::span(20, 30)), vec![whole]);
        // Fully covered: nothing left.
        assert_eq!(whole.subtract(Lifespan::span(-5, 15)), Vec::<Lifespan>::new());
        assert_eq!(whole.subtract(Lifespan::span(0, 10)), Vec::<Lifespan>::new());
        // Trimmed at the top.
        assert_eq!(whole.subtract(Lifespan::span(5, 20)), vec![Lifespan::span(0, 4)]);
        // Trimmed at the bottom.
        assert_eq!(whole.subtract(Lifespan::span(-5, 5)), vec![Lifespan::span(6, 10)]);
        // Split in two, lower part first.
        assert_eq!(
            whole.subtract(Lifespan::span(4, 6)),
            vec![Lifespan::span(0, 3), Lifespan::span(7, 10)]
        );
    }

    #[test]
    fn subtract_handles_the_empty_span_on_either_side() {
        assert_eq!(Lifespan::EMPTY.subtract(Lifespan::span(0, 10)), Vec::<Lifespan>::new());
        assert_eq!(Lifespan::span(0, 10).subtract(Lifespan::EMPTY), vec![Lifespan::span(0, 10)]);
    }
}
