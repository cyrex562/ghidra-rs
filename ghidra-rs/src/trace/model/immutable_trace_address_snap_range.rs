//! The concrete, immutable [`TraceAddressSnapRange`] implementation, ported as a trait because it
//! was selected as a cycle cut-point: in the original Java, `TraceAddressSnapSpace.forAddressSpace`
//! constructs an `ImmutableTraceAddressSnapRange`, and several of `ImmutableTraceAddressSnapRange`'s
//! own constructors call back into `TraceAddressSnapSpace.forAddressSpace` to fill in a default
//! coordinate space, so the two Java classes reference each other.
//!
//! Java source: `ghidra.trace.model.ImmutableTraceAddressSnapRange`.
//!
//! `TraceAddressSnapSpace` (see [`seam_stubs::TraceAddressSnapSpace`](crate::trace::seam_stubs::TraceAddressSnapSpace))
//! is not yet ported, so the Java constructors and the `centered` factory that rely on it for a
//! default coordinate space are not reproduced here. What *is* space-independent is ported in
//! full: the instance-level `equals`/`hashCode`/`toString`/`getSpace` contract (as the
//! [`ImmutableTraceAddressSnapRange`] trait) and the two static helpers that only manipulate
//! addresses and snaps directly ([`range_centered`] and [`span_centered`]). This mirrors the
//! precedent already set by [`TraceAddressSnapRange::immutable`], which was likewise left as a
//! required (rather than default) method for the same reason.
//!
//! `spanCentered` returns a Java `Lifespan`, but `Lifespan.span`/`Lifespan.at` are static
//! factories on nested, unported implementation types (see the header comment on
//! [`lifespan`](crate::trace::model::lifespan)), so [`span_centered`] returns the raw `(min, max)`
//! snap bounds instead of a boxed `Lifespan`, leaving construction to the caller.
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::util::database::spatial::rect::euclidean_space2d::EuclideanSpace2D;

/// The instance-level contract of `ghidra.trace.model.ImmutableTraceAddressSnapRange`: a
/// [`TraceAddressSnapRange`] that additionally exposes its coordinate space and value-based
/// `equals`/`hashCode`/`toString`.
pub trait ImmutableTraceAddressSnapRange: TraceAddressSnapRange {
    /// Returns the coordinate space used to compare/measure this rectangle's `Address`/snap axes.
    fn get_space(&self) -> Box<dyn EuclideanSpace2D<X = Address, Y = i64, Rect = AddressRange>>;

    /// Value equality, ported from the `Rectangle2D.doEquals` default this class delegates to:
    /// two rectangles are equal iff their `x1`, `x2`, `y1`, `y2` bounds all match.
    fn equals(&self, other: &dyn TraceAddressSnapRange) -> bool {
        self.get_x1() == other.get_x1()
            && self.get_x2() == other.get_x2()
            && self.get_y1() == other.get_y1()
            && self.get_y2() == other.get_y2()
    }

    /// Ported from the `Rectangle2D.doHashCode` default this class delegates to:
    /// `Objects.hash(x1, x2, y1, y2)`.
    fn hash_code(&self) -> i32 {
        objects_hash(&[
            self.get_x1().offset(),
            self.get_x2().offset(),
            self.get_y1(),
            self.get_y2(),
        ])
    }

    /// Ported from `toString`, which delegates to [`description`](TraceAddressSnapRange::description).
    fn to_string(&self) -> String {
        self.description()
    }
}

/// Mirrors `java.util.Objects.hash(Object...)` combined with `Long.hashCode(long)`, as used by
/// `Rectangle2D.doHashCode`.
fn objects_hash(values: &[i64]) -> i32 {
    let mut result: i32 = 1;
    for &v in values {
        let long_hash = (v ^ (v >> 32)) as i32;
        result = 31i32.wrapping_mul(result).wrapping_add(long_hash);
    }
    result
}

/// Computes the address range spanning `breadth` addresses on either side of `address`, clamped
/// to the bounds of `address`'s address space.
///
/// Ported from the static `rangeCentered(Address, int)`.
pub fn range_centered(address: &Address, breadth: i32) -> AddressRange {
    let space = address.space();
    let min_addr = space.min_address();
    let max_addr = space.max_address();
    let breadth = breadth as i64;

    let min = if (address.subtract(&min_addr) as u64) <= (breadth as u64) {
        min_addr
    } else {
        address
            .subtract_no_wrap(breadth)
            .expect("breadth was already checked to stay within the address space")
    };
    let max = if (max_addr.subtract(address) as u64) <= (breadth as u64) {
        max_addr
    } else {
        address
            .add_no_wrap(breadth)
            .expect("breadth was already checked to stay within the address space")
    };
    AddressRange::new(min, max)
}

/// Computes the inclusive snap bounds `[snap - breadth, snap + breadth]`, saturating at
/// `i64::MIN`/`i64::MAX` instead of overflowing.
///
/// Ported from the static `spanCentered(long, int)`; see the module documentation for why this
/// returns raw bounds rather than a boxed `Lifespan`.
pub fn span_centered(snap: i64, breadth: i32) -> (i64, i64) {
    let breadth = breadth as i64;

    let min = if (snap.wrapping_sub(i64::MIN) as u64) <= (breadth as u64) {
        i64::MIN
    } else {
        snap - breadth
    };
    let max = if (i64::MAX.wrapping_sub(snap) as u64) <= (breadth as u64) {
        i64::MAX
    } else {
        snap + breadth
    };
    (min, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cmp::Ordering;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[derive(Clone)]
    struct MockSpace {
        full: AddressRange,
    }

    impl EuclideanSpace2D for MockSpace {
        type X = Address;
        type Y = i64;
        type Rect = AddressRange;

        fn compare_x(&self, x1: &Address, x2: &Address) -> Ordering {
            x1.cmp(x2)
        }
        fn compare_y(&self, y1: &i64, y2: &i64) -> Ordering {
            y1.cmp(y2)
        }
        fn dist_x(&self, x1: &Address, x2: &Address) -> f64 {
            x2.subtract(x1).unsigned_abs() as f64
        }
        fn dist_y(&self, y1: &i64, y2: &i64) -> f64 {
            (y2 - y1).unsigned_abs() as f64
        }
        fn mid_x(&self, x1: &Address, x2: &Address) -> Address {
            x1.clone()
        }
        fn mid_y(&self, y1: &i64, y2: &i64) -> i64 {
            y1 + (y2 - y1) / 2
        }
        fn get_full(&self) -> AddressRange {
            self.full.clone()
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl crate::trace::model::lifespan::Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }
        fn lmax(&self) -> i64 {
            self.max
        }
        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }
        fn with_min(&self, min: i64) -> Box<dyn crate::trace::model::lifespan::Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }
        fn with_max(&self, max: i64) -> Box<dyn crate::trace::model::lifespan::Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        y1: i64,
        y2: i64,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Box<dyn crate::trace::model::lifespan::Lifespan> {
            Box::new(MockLifespan {
                min: self.y1,
                max: self.y2,
            })
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }

        fn get_x1(&self) -> Address {
            self.range.min_address().clone()
        }

        fn get_x2(&self) -> Address {
            self.range.max_address().clone()
        }

        fn get_y1(&self) -> i64 {
            self.y1
        }

        fn get_y2(&self) -> i64 {
            self.y2
        }

        fn immutable(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockRange {
                range: AddressRange::new(x1, x2),
                y1,
                y2,
            })
        }
    }

    impl ImmutableTraceAddressSnapRange for MockRange {
        fn get_space(&self) -> Box<dyn EuclideanSpace2D<X = Address, Y = i64, Rect = AddressRange>> {
            Box::new(MockSpace {
                full: self.range.clone(),
            })
        }
    }

    fn make_range(min: i64, max: i64, y1: i64, y2: i64) -> MockRange {
        let space = ram_space();
        MockRange {
            range: AddressRange::new(Address::new(space.clone(), min), Address::new(space, max)),
            y1,
            y2,
        }
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let r = make_range(0x1000, 0x2000, 0, 10);
        let boxed: Box<dyn ImmutableTraceAddressSnapRange> = Box::new(r);
        assert_eq!(boxed.get_x1().offset(), 0x1000);
        assert_eq!(boxed.to_string(), "[ram:1000:2000]0..10");
        let _ = boxed.get_space();
    }

    #[test]
    fn equals_true_for_same_bounds() {
        let a = make_range(0x1000, 0x2000, 0, 10);
        let b = make_range(0x1000, 0x2000, 0, 10);
        assert!(a.equals(&b));
    }

    #[test]
    fn equals_false_when_a_bound_differs() {
        let a = make_range(0x1000, 0x2000, 0, 10);
        let b = make_range(0x1000, 0x2000, 0, 11);
        assert!(!a.equals(&b));
    }

    #[test]
    fn hash_code_matches_for_equal_ranges() {
        let a = make_range(0x1000, 0x2000, 5, 15);
        let b = make_range(0x1000, 0x2000, 5, 15);
        assert_eq!(a.hash_code(), b.hash_code());
    }

    #[test]
    fn hash_code_differs_for_different_ranges() {
        let a = make_range(0x1000, 0x2000, 5, 15);
        let b = make_range(0x1000, 0x3000, 5, 15);
        assert_ne!(a.hash_code(), b.hash_code());
    }

    #[test]
    fn range_centered_clamps_at_space_minimum() {
        let space = ram_space();
        let addr = Address::new(space, 5);
        let range = range_centered(&addr, 10);
        assert_eq!(range.min_address().offset(), 0);
        assert_eq!(range.max_address().offset(), 15);
    }

    #[test]
    fn range_centered_does_not_clamp_when_within_bounds() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let range = range_centered(&addr, 10);
        assert_eq!(range.min_address().offset(), 0x1000 - 10);
        assert_eq!(range.max_address().offset(), 0x1000 + 10);
    }

    #[test]
    fn span_centered_stays_within_bounds_when_far_from_edges() {
        let (min, max) = span_centered(1000, 50);
        assert_eq!(min, 950);
        assert_eq!(max, 1050);
    }

    #[test]
    fn span_centered_saturates_at_i64_min() {
        let (min, max) = span_centered(i64::MIN + 5, 50);
        assert_eq!(min, i64::MIN);
        assert_eq!(max, i64::MIN + 55);
    }

    #[test]
    fn span_centered_saturates_at_i64_max() {
        let (min, max) = span_centered(i64::MAX - 5, 50);
        assert_eq!(min, i64::MAX - 55);
        assert_eq!(max, i64::MAX);
    }
}
