//! A closed range on snapshot keys, indicating a duration of time.
//!
//! Java source: `ghidra.trace.model.Lifespan`.
//!
//! In the original, `Lifespan` is a sealed interface extending `generic.Span<Long, Lifespan>` and
//! `Iterable<Long>`, with nested `Domain`/`Empty`/`Impl` types plus `LifeSet`/`MutableLifeSet`
//! machinery built on `generic.Span.SpanSet`. Those nested types are concrete implementations and
//! collection machinery, not the interface contract itself, so only the interface's own contract
//! is ported here. Per the original's own note, we favor primitive `i64` endpoints directly
//! (mirroring the Java doc's "primitive getters ... to work on those primitives directly") rather
//! than boxed values, so no reference to the (unported) `generic.Span` interface is needed in this
//! trait's signatures.
use std::cmp::Ordering;

/// A closed range `[lmin, lmax]` on snapshot keys.
pub trait Lifespan {
    /// The lower (inclusive) endpoint of this span.
    fn lmin(&self) -> i64;

    /// The upper (inclusive) endpoint of this span.
    fn lmax(&self) -> i64;

    /// Checks whether the given snapshot key falls within this span.
    fn contains(&self, n: i64) -> bool;

    /// Checks whether the lower endpoint excludes the domain minimum (`i64::MIN`).
    fn min_is_finite(&self) -> bool {
        self.lmin() != i64::MIN
    }

    /// Checks whether the upper endpoint excludes the domain maximum (`i64::MAX`).
    fn max_is_finite(&self) -> bool {
        self.lmax() != i64::MAX
    }

    /// Checks whether this span contains no snapshot keys.
    fn is_empty(&self) -> bool {
        false
    }

    /// Builds a new span with the given lower endpoint and this span's upper endpoint.
    fn with_min(&self, min: i64) -> Box<dyn Lifespan>;

    /// Builds a new span with this span's lower endpoint and the given upper endpoint.
    fn with_max(&self, max: i64) -> Box<dyn Lifespan>;

    /// Iterates the snapshot keys contained in this span.
    fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_>;

    /// Orders spans by lower endpoint, then upper endpoint, treating empty spans as least.
    fn compare_to(&self, other: &dyn Lifespan) -> Ordering {
        match (self.is_empty(), other.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self
                .lmin()
                .cmp(&other.lmin())
                .then_with(|| self.lmax().cmp(&other.lmax())),
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[test]
    fn contains_within_bounds() {
        let s = MockLifespan { min: 10, max: 20 };
        assert!(s.contains(10));
        assert!(s.contains(20));
        assert!(!s.contains(9));
        assert!(!s.contains(21));
    }

    #[test]
    fn with_min_and_with_max_replace_one_endpoint() {
        let s = MockLifespan { min: 10, max: 20 };
        let new_min = s.with_min(5);
        assert_eq!(new_min.lmin(), 5);
        assert_eq!(new_min.lmax(), 20);

        let new_max = s.with_max(30);
        assert_eq!(new_max.lmin(), 10);
        assert_eq!(new_max.lmax(), 30);
    }

    #[test]
    fn iter_yields_all_snaps_in_range() {
        let s = MockLifespan { min: 1, max: 3 };
        let snaps: Vec<i64> = s.iter().collect();
        assert_eq!(snaps, vec![1, 2, 3]);
    }

    #[test]
    fn compare_orders_by_min_then_max() {
        let a = MockLifespan { min: 0, max: 50 };
        let b = MockLifespan { min: 0, max: 100 };
        let c = MockLifespan { min: 1, max: 10 };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&c), Ordering::Less);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }

    #[test]
    fn min_max_is_finite_detects_unbounded_endpoints() {
        let bounded = MockLifespan { min: 0, max: 100 };
        assert!(bounded.min_is_finite());
        assert!(bounded.max_is_finite());

        let unbounded = MockLifespan {
            min: i64::MIN,
            max: i64::MAX,
        };
        assert!(!unbounded.min_is_finite());
        assert!(!unbounded.max_is_finite());
    }

    #[test]
    fn is_scratch_detects_negative_snaps() {
        assert!(is_scratch(-1));
        assert!(!is_scratch(0));
        assert!(!is_scratch(1));
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let boxed: Box<dyn Lifespan> = Box::new(MockLifespan { min: 0, max: 5 });
        assert_eq!(boxed.lmin(), 0);
        assert_eq!(boxed.lmax(), 5);
        assert!(boxed.contains(3));
    }
}
