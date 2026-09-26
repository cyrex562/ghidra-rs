//! Mirrors `generic.End` from Ghidra: an endpoint for spans, supporting open endpoints.
//!
//! An endpoint is a value plus an optional epsilon, where epsilon is "the smallest non-zero
//! value". Closed endpoints carry no epsilon. Open endpoints add or subtract epsilon, depending
//! on whether the endpoint is a lower or upper bound, respectively. For example, the interval
//! `(2, +inf)` has the lower endpoint `2 + epsilon` so that `2` is excluded, but any value
//! greater than `2` is included.
//!
//! The domain for values needing open intervals is not necessarily discreet, so [`inc`] and
//! [`dec`] only ever change the coefficient on epsilon, never the underlying value. Negative
//! epsilon is disallowed on lower bounds and positive epsilon on upper bounds, both to keep such
//! intervals meaningful and so [`inc`]/[`dec`] never need to touch the value itself.
//!
//! [`inc`]: End::inc
//! [`dec`]: End::dec
//!
//! The nested `EndSpan`/`EndDomain` abstractions from the Java source, which build interval and
//! domain machinery on top of `Span`, are not ported here: `Span` itself is not yet ported, and
//! nothing in this crate depends on those nested abstractions yet. This file ports the `End<T>`
//! endpoint contract itself, which is what other code depends on.

use std::any::Any;
use std::cmp::Ordering;

/// An endpoint for spans, admitting open, closed, or unbounded boundaries. Mirrors `End<T>`.
///
/// Object-safe: methods that would return `End<T>` return `Box<dyn End<T>>` instead, and
/// comparisons take the value comparator as a parameter rather than requiring `T: Ord`.
pub trait End<T>: Send + Sync {
    /// Returns this endpoint as [`std::any::Any`], so that [`compare_to`](Self::compare_to)
    /// implementations can downcast `that` to a concrete endpoint type.
    ///
    /// Mirrors the `instanceof`/identity checks (`that == NEG_INF`, `that instanceof Point<T>
    /// point`) in Java's `compareTo` overrides.
    fn as_any(&self) -> &dyn Any;

    /// Render this endpoint as a lower (minimum) bound. Mirrors `toMinString`.
    fn to_min_string(&self, n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String;

    /// Render this endpoint as an upper (maximum) bound. Mirrors `toMaxString`.
    fn to_max_string(&self, n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String;

    /// Increment this endpoint, only by changing the coefficient of epsilon. Mirrors `inc`.
    ///
    /// # Panics
    /// Mirrors `UnsupportedOperationException`: panics if this endpoint has no successor (e.g.
    /// positive infinity, or a `Point` whose epsilon is already positive).
    fn inc(&self) -> Box<dyn End<T>>;

    /// Decrement this endpoint, only by changing the coefficient of epsilon. Mirrors `dec`.
    ///
    /// # Panics
    /// Mirrors `UnsupportedOperationException`: panics if this endpoint has no predecessor (e.g.
    /// negative infinity, or a `Point` whose epsilon is already negative).
    fn dec(&self) -> Box<dyn End<T>>;

    /// Compare two endpoints: infinities first, then values via `comparator`, then the
    /// coefficient of epsilon. Mirrors `compareTo`.
    fn compare_to(&self, that: &dyn End<T>, comparator: &dyn Fn(&T, &T) -> Ordering) -> Ordering;

    /// Whether this endpoint is allowed as a lower endpoint. Mirrors `isValidMin`.
    fn is_valid_min(&self) -> bool;

    /// Whether this endpoint is allowed as an upper endpoint. Mirrors `isValidMax`.
    fn is_valid_max(&self) -> bool;

    /// Whether this endpoint includes its value. Mirrors `isInclusive`.
    fn is_inclusive(&self) -> bool;
}

/// Get the endpoint representing no lower bound. Mirrors `End.negativeInfinity`.
///
/// Always denotes the same logical value; clients can rely on [`Unbound::NegInf`] identity when
/// checking for equality via [`End::as_any`].
pub fn negative_infinity<T: Send + Sync + 'static>() -> Box<dyn End<T>> {
    Box::new(Unbound::NegInf)
}

/// Get the endpoint representing no upper bound. Mirrors `End.positiveInfinity`.
///
/// Always denotes the same logical value; clients can rely on [`Unbound::PosInf`] identity when
/// checking for equality via [`End::as_any`].
pub fn positive_infinity<T: Send + Sync + 'static>() -> Box<dyn End<T>> {
    Box::new(Unbound::PosInf)
}

/// Construct a lower endpoint. Mirrors `End.lower`.
pub fn lower<T: Clone + Send + Sync + 'static>(value: T, inclusive: bool) -> Box<dyn End<T>> {
    Box::new(Point { val: value, epsilon: if inclusive { Epsilon::Zero } else { Epsilon::Positive } })
}

/// Construct an upper endpoint. Mirrors `End.upper`.
pub fn upper<T: Clone + Send + Sync + 'static>(value: T, inclusive: bool) -> Box<dyn End<T>> {
    Box::new(Point { val: value, epsilon: if inclusive { Epsilon::Zero } else { Epsilon::Negative } })
}

/// The two values of infinity. Mirrors the `Unbound` enum, which in Java implements
/// `End<Void>` and is unchecked-cast to `End<T>` for any `T` since it never touches a value of
/// type `T`. Here it implements `End<T>` directly for every `T`, via a blanket impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unbound {
    /// No lower bound.
    NegInf,
    /// No upper bound.
    PosInf,
}

impl<T: Send + Sync + 'static> End<T> for Unbound {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_min_string(&self, _n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String {
        match self {
            Unbound::NegInf => "(-inf".to_string(),
            Unbound::PosInf => "(#ERROR+inf".to_string(),
        }
    }

    fn to_max_string(&self, _n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String {
        match self {
            Unbound::NegInf => "#ERROR-inf)".to_string(),
            Unbound::PosInf => "+inf)".to_string(),
        }
    }

    fn inc(&self) -> Box<dyn End<T>> {
        match self {
            Unbound::NegInf => Box::new(Unbound::NegInf),
            Unbound::PosInf => panic!("UnsupportedOperationException: inc on positive infinity"),
        }
    }

    fn dec(&self) -> Box<dyn End<T>> {
        match self {
            Unbound::NegInf => panic!("UnsupportedOperationException: dec on negative infinity"),
            Unbound::PosInf => Box::new(Unbound::PosInf),
        }
    }

    fn compare_to(&self, that: &dyn End<T>, _comparator: &dyn Fn(&T, &T) -> Ordering) -> Ordering {
        let that_unbound = that.as_any().downcast_ref::<Unbound>();
        match self {
            Unbound::NegInf => {
                if that_unbound == Some(&Unbound::NegInf) { Ordering::Equal } else { Ordering::Less }
            }
            Unbound::PosInf => {
                if that_unbound == Some(&Unbound::PosInf) { Ordering::Equal } else { Ordering::Greater }
            }
        }
    }

    fn is_valid_min(&self) -> bool {
        matches!(self, Unbound::NegInf)
    }

    fn is_valid_max(&self) -> bool {
        matches!(self, Unbound::PosInf)
    }

    fn is_inclusive(&self) -> bool {
        false
    }
}

/// The three allowed coefficients of epsilon. Mirrors the `Epsilon` enum, in declaration order
/// (`Negative < Zero < Positive`) so that derived [`Ord`] matches Java's ordinal-based
/// `Comparable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Epsilon {
    /// `value - 1*epsilon`, for open upper endpoints.
    Negative,
    /// `value + 0*epsilon`, for closed endpoints.
    Zero,
    /// `value + 1*epsilon`, for open lower endpoints.
    Positive,
}

impl Epsilon {
    /// Compute the epsilon for an incremented endpoint.
    ///
    /// # Panics
    /// Mirrors `UnsupportedOperationException`: panics if this is already [`Epsilon::Positive`].
    pub fn inc(self) -> Epsilon {
        match self {
            Epsilon::Negative => Epsilon::Zero,
            Epsilon::Zero => Epsilon::Positive,
            Epsilon::Positive => panic!("UnsupportedOperationException: inc on Epsilon::Positive"),
        }
    }

    /// Compute the epsilon for a decremented endpoint.
    ///
    /// # Panics
    /// Mirrors `UnsupportedOperationException`: panics if this is already [`Epsilon::Negative`].
    pub fn dec(self) -> Epsilon {
        match self {
            Epsilon::Negative => panic!("UnsupportedOperationException: dec on Epsilon::Negative"),
            Epsilon::Zero => Epsilon::Negative,
            Epsilon::Positive => Epsilon::Zero,
        }
    }
}

/// An endpoint representing a bound value, offset by an [`Epsilon`] coefficient that signals
/// exclusivity. Mirrors the `Point<T>` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point<T> {
    /// The value of the endpoint.
    pub val: T,
    /// Determines whether the endpoint is included.
    pub epsilon: Epsilon,
}

impl<T: Clone + Send + Sync + 'static> End<T> for Point<T> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_min_string(&self, n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String {
        match self.epsilon {
            Epsilon::Negative => format!("(#ERROR{}", n_to_string(self)),
            Epsilon::Zero => format!("[{}", n_to_string(self)),
            Epsilon::Positive => format!("({}", n_to_string(self)),
        }
    }

    fn to_max_string(&self, n_to_string: &dyn Fn(&dyn End<T>) -> String) -> String {
        match self.epsilon {
            Epsilon::Negative => format!("{})", n_to_string(self)),
            Epsilon::Zero => format!("{}]", n_to_string(self)),
            Epsilon::Positive => format!("#ERROR{})", n_to_string(self)),
        }
    }

    fn inc(&self) -> Box<dyn End<T>> {
        Box::new(Point { val: self.val.clone(), epsilon: self.epsilon.inc() })
    }

    fn dec(&self) -> Box<dyn End<T>> {
        Box::new(Point { val: self.val.clone(), epsilon: self.epsilon.dec() })
    }

    fn compare_to(&self, that: &dyn End<T>, comparator: &dyn Fn(&T, &T) -> Ordering) -> Ordering {
        if let Some(unbound) = that.as_any().downcast_ref::<Unbound>() {
            return match unbound {
                Unbound::NegInf => Ordering::Greater,
                Unbound::PosInf => Ordering::Less,
            };
        }
        if let Some(point) = that.as_any().downcast_ref::<Point<T>>() {
            let result = comparator(&self.val, &point.val);
            if result != Ordering::Equal {
                return result;
            }
            return self.epsilon.cmp(&point.epsilon);
        }
        unreachable!("End<T> is sealed in practice to Unbound and Point endpoints")
    }

    fn is_valid_min(&self) -> bool {
        self.epsilon != Epsilon::Negative
    }

    fn is_valid_max(&self) -> bool {
        self.epsilon != Epsilon::Positive
    }

    fn is_inclusive(&self) -> bool {
        self.epsilon == Epsilon::Zero
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp_i32(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    fn n_to_string(n: &dyn End<i32>) -> String {
        match n.as_any().downcast_ref::<Point<i32>>() {
            Some(p) => p.val.to_string(),
            None => "?".to_string(),
        }
    }

    #[test]
    fn test_lower_upper_ordering_and_strings() {
        let neg_inf = negative_infinity::<i32>();
        let pos_inf = positive_infinity::<i32>();
        let closed_lower = lower(2, true);
        let open_lower = lower(2, false);
        let closed_upper = upper(5, true);

        assert_eq!(neg_inf.compare_to(closed_lower.as_ref(), &cmp_i32), Ordering::Less);
        assert_eq!(closed_lower.compare_to(pos_inf.as_ref(), &cmp_i32), Ordering::Less);
        assert_eq!(closed_lower.compare_to(open_lower.as_ref(), &cmp_i32), Ordering::Less);
        assert_eq!(open_lower.compare_to(closed_lower.as_ref(), &cmp_i32), Ordering::Greater);

        assert_eq!(closed_lower.to_min_string(&n_to_string), "[2");
        assert_eq!(open_lower.to_min_string(&n_to_string), "(2");
        assert_eq!(closed_upper.to_max_string(&n_to_string), "5]");
        assert_eq!(neg_inf.to_min_string(&n_to_string), "(-inf");
        assert_eq!(pos_inf.to_max_string(&n_to_string), "+inf)");
    }

    #[test]
    fn test_inc_dec_round_trip_on_point() {
        let open_lower = lower(2, false);
        assert!(!open_lower.is_valid_max());
        assert!(open_lower.is_valid_min());
        assert!(!open_lower.is_inclusive());

        let decremented = open_lower.dec();
        assert!(decremented.is_inclusive());
        assert_eq!(decremented.compare_to(lower(2, true).as_ref(), &cmp_i32), Ordering::Equal);

        let incremented = decremented.inc();
        assert_eq!(incremented.compare_to(open_lower.as_ref(), &cmp_i32), Ordering::Equal);
    }

    #[test]
    #[should_panic]
    fn test_positive_infinity_inc_panics() {
        let pos_inf = positive_infinity::<i32>();
        pos_inf.inc();
    }

    #[test]
    #[should_panic]
    fn test_epsilon_negative_dec_panics() {
        Epsilon::Negative.dec();
    }

    /// A mock endpoint, distinct from [`Point`]/[`Unbound`], proving [`End`] is object-safe.
    /// Always compares as strictly less than any other endpoint and denotes an exclusive,
    /// invalid-as-either-bound marker -- exercising real (if degenerate) behavior rather than a
    /// trivially-true stub.
    struct AlwaysLeast;

    impl End<i32> for AlwaysLeast {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn to_min_string(&self, _n_to_string: &dyn Fn(&dyn End<i32>) -> String) -> String {
            "<least".to_string()
        }

        fn to_max_string(&self, _n_to_string: &dyn Fn(&dyn End<i32>) -> String) -> String {
            "least>".to_string()
        }

        fn inc(&self) -> Box<dyn End<i32>> {
            Box::new(AlwaysLeast)
        }

        fn dec(&self) -> Box<dyn End<i32>> {
            Box::new(AlwaysLeast)
        }

        fn compare_to(&self, _that: &dyn End<i32>, _comparator: &dyn Fn(&i32, &i32) -> Ordering) -> Ordering {
            Ordering::Less
        }

        fn is_valid_min(&self) -> bool {
            false
        }

        fn is_valid_max(&self) -> bool {
            false
        }

        fn is_inclusive(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_mock_end_is_object_safe() {
        let endpoints: Vec<Box<dyn End<i32>>> = vec![
            negative_infinity(),
            lower(1, true),
            Box::new(AlwaysLeast),
            positive_infinity(),
        ];
        assert_eq!(endpoints[2].compare_to(endpoints[0].as_ref(), &cmp_i32), Ordering::Less);
        assert!(!endpoints[2].is_valid_min());
        assert_eq!(endpoints[2].to_min_string(&n_to_string), "<least");
    }
}
