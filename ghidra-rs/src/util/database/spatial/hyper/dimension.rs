use std::cmp::Ordering;

use super::{HyperBox, HyperPoint};

/// A single coordinate dimension of a hyper-dimensional spatial index, giving meaning to one
/// axis of a [`HyperBox`]/[`HyperPoint`] pair.
///
/// Port of `ghidra.util.database.spatial.hyper.Dimension<T, P, B>`.
///
/// This is the general, `T`-typed sibling of the narrower
/// [`crate::util::seam_stubs::Dimension`] placeholder: that placeholder exists only because
/// [`crate::util::database::spatial::hyper::euclidean_hyper_space::EuclideanHyperSpace`] must
/// hold a heterogeneous `List<Dimension<?, P, B>>`-equivalent (a `T` type parameter can't appear
/// in an object-safe, boxed-trait-object surface used that way), so it collapses every
/// `T`-typed method into a `String`-keyed or `f64`-returning equivalent. This trait is the real,
/// fully `T`-typed port instead -- usable directly by a single concrete dimension
/// implementation (not stored heterogeneously), matching the shape already established by
/// [`crate::util::database::spatial::hyper::long_dimension::LongDimension`] (default methods
/// built on a handful of required ones), generalized from `LongDimension`'s fixed `i64`
/// coordinate type to an arbitrary `T`.
///
/// Unlike `LongDimension` (whose methods are all associated functions, since `i64` needs no
/// per-instance state), `Dimension<T, P, B>` methods take `&self`: a concrete dimension (e.g. one
/// keyed off a `String` or `u64` coordinate) commonly needs per-instance state such as which of a
/// point's several fields this dimension reads, matching the shape already used by
/// [`crate::util::database::spatial::hyper::string_dimension::StringDimension`]/
/// [`crate::util::database::spatial::hyper::u_long_dimension::ULongDimension`].
pub trait Dimension<T, P: HyperPoint, B: HyperBox<P>> {
    /// Returns this dimension's coordinate value of the given point. Mirrors `value(P)`.
    fn value(&self, point: &P) -> T;

    /// Returns this dimension's lower-bound coordinate of `box_`. Mirrors `lower(B)`.
    fn lower(&self, box_: &B) -> T {
        self.value(&box_.l_corner())
    }

    /// Returns this dimension's upper-bound coordinate of `box_`. Mirrors `upper(B)`.
    fn upper(&self, box_: &B) -> T {
        self.value(&box_.u_corner())
    }

    /// Compares two coordinate values along this dimension. Mirrors `compare(T, T)`.
    fn compare(&self, a: &T, b: &T) -> Ordering;

    /// Returns the (approximate) distance between an upper and lower coordinate value. Mirrors
    /// `distance(T, T)`.
    fn distance(&self, upper: &T, lower: &T) -> f64;

    /// Returns the midpoint between two coordinate values. Mirrors `mid(T, T)`.
    fn mid(&self, a: &T, b: &T) -> T;

    /// Returns the midpoint between `box_`'s lower and upper bounds. Mirrors `boxMid(B)`.
    fn box_mid(&self, box_: &B) -> T {
        self.mid(&self.lower(box_), &self.upper(box_))
    }

    /// Returns the smaller of `a` and `b`, mirroring Java's `compare(a, b) < 0 ? a : b`.
    ///
    /// Note the faithfully-preserved quirk: when `a` and `b` compare equal, this (like the Java
    /// original) returns `b`, not `a`.
    fn min(&self, a: T, b: T) -> T {
        if self.compare(&a, &b) == Ordering::Less {
            a
        } else {
            b
        }
    }

    /// Returns the larger of `a` and `b`, mirroring Java's `compare(a, b) > 0 ? a : b`.
    ///
    /// Note the faithfully-preserved quirk: when `a` and `b` compare equal, this (like the Java
    /// original) returns `b`, not `a`.
    fn max(&self, a: T, b: T) -> T {
        if self.compare(&a, &b) == Ordering::Greater {
            a
        } else {
            b
        }
    }

    /// Returns the absolute minimum coordinate value for this dimension. Mirrors
    /// `absoluteMin()`.
    fn absolute_min(&self) -> T;

    /// Returns the absolute maximum coordinate value for this dimension. Mirrors
    /// `absoluteMax()`.
    fn absolute_max(&self) -> T;

    /// Returns the distance between two points along this dimension. Mirrors `pointDistance(P,
    /// P)`.
    fn point_distance(&self, a: &P, b: &P) -> f64 {
        self.distance(&self.value(a), &self.value(b))
    }

    /// Returns whether `box_` contains `point` along this dimension. Mirrors `contains(B, P)`.
    fn contains(&self, box_: &B, point: &P) -> bool {
        let value = self.value(point);
        if self.compare(&value, &self.lower(box_)) == Ordering::Less {
            return false;
        }
        if self.compare(&value, &self.upper(box_)) == Ordering::Greater {
            return false;
        }
        true
    }

    /// Returns whether `a` and `b` intersect along this dimension. Mirrors `intersect(B, B)`.
    fn intersect(&self, a: &B, b: &B) -> bool {
        if self.compare(&self.lower(a), &self.upper(b)) == Ordering::Greater {
            return false;
        }
        if self.compare(&self.upper(a), &self.lower(b)) == Ordering::Less {
            return false;
        }
        true
    }

    /// Returns whether `outer` fully encloses `inner` along this dimension. Mirrors `encloses(B,
    /// B)`.
    fn encloses(&self, outer: &B, inner: &B) -> bool {
        if self.compare(&self.lower(outer), &self.lower(inner)) == Ordering::Greater {
            return false;
        }
        if self.compare(&self.upper(outer), &self.upper(inner)) == Ordering::Less {
            return false;
        }
        true
    }

    /// Returns the lower bound of the intersection of `a` and `b` along this dimension. Mirrors
    /// `intersectionLower(B, B)`.
    fn intersection_lower(&self, a: &B, b: &B) -> T {
        self.max(self.lower(a), self.lower(b))
    }

    /// Returns the upper bound of the intersection of `a` and `b` along this dimension. Mirrors
    /// `intersectionUpper(B, B)`.
    fn intersection_upper(&self, a: &B, b: &B) -> T {
        self.min(self.upper(a), self.upper(b))
    }

    /// Returns the lower bound of the union of `a` and `b` along this dimension. Mirrors
    /// `unionLower(B, B)`.
    fn union_lower(&self, a: &B, b: &B) -> T {
        self.min(self.lower(a), self.lower(b))
    }

    /// Returns the upper bound of the union of `a` and `b` along this dimension. Mirrors
    /// `unionUpper(B, B)`.
    fn union_upper(&self, a: &B, b: &B) -> T {
        self.max(self.upper(a), self.upper(b))
    }

    /// Returns this dimension's extent (upper minus lower) of `box_`. Mirrors `measure(B)`.
    fn measure(&self, box_: &B) -> f64 {
        self.distance(&self.upper(box_), &self.lower(box_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::util::database::spatial::hyper::euclidean_hyper_space::EuclideanHyperSpace;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockPoint(f64);
    impl HyperPoint for MockPoint {}

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockBox {
        lo: f64,
        hi: f64,
    }

    impl HyperBox<MockPoint> for MockBox {
        fn space(&self) -> Arc<dyn EuclideanHyperSpace<MockPoint, MockBox>> {
            unimplemented!("not exercised by this dimension-only smoke test")
        }
        fn l_corner(&self) -> MockPoint {
            MockPoint(self.lo)
        }
        fn u_corner(&self) -> MockPoint {
            MockPoint(self.hi)
        }
        fn immutable(&self, l_corner: MockPoint, u_corner: MockPoint) -> Self {
            MockBox { lo: l_corner.0, hi: u_corner.0 }
        }
    }

    /// An `f64`-coordinate dimension reading a point's only field, exercising every default
    /// method against `f64`'s natural `PartialOrd`/subtraction.
    struct AxisDim;

    impl Dimension<f64, MockPoint, MockBox> for AxisDim {
        fn value(&self, point: &MockPoint) -> f64 {
            point.0
        }
        fn compare(&self, a: &f64, b: &f64) -> Ordering {
            a.partial_cmp(b).unwrap()
        }
        fn distance(&self, upper: &f64, lower: &f64) -> f64 {
            upper - lower
        }
        fn mid(&self, a: &f64, b: &f64) -> f64 {
            a + (b - a) / 2.0
        }
        fn absolute_min(&self) -> f64 {
            f64::MIN
        }
        fn absolute_max(&self) -> f64 {
            f64::MAX
        }
    }

    #[test]
    fn value_reads_point_coordinate() {
        assert_eq!(AxisDim.value(&MockPoint(3.5)), 3.5);
    }

    #[test]
    fn lower_and_upper_read_box_corners() {
        let b = MockBox { lo: 1.0, hi: 9.0 };
        assert_eq!(AxisDim.lower(&b), 1.0);
        assert_eq!(AxisDim.upper(&b), 9.0);
    }

    #[test]
    fn box_mid_is_midpoint_of_bounds() {
        let b = MockBox { lo: 0.0, hi: 10.0 };
        assert_eq!(AxisDim.box_mid(&b), 5.0);
    }

    #[test]
    fn min_and_max_basic() {
        assert_eq!(AxisDim.min(1.0, 2.0), 1.0);
        assert_eq!(AxisDim.max(1.0, 2.0), 2.0);
    }

    #[test]
    fn min_and_max_tie_returns_second_argument() {
        // Faithful to the Java quirk: `compare(a, b) < 0 ? a : b` (and `> 0 ? a : b`) both
        // resolve a tie to `b`, not `a`.
        assert_eq!(AxisDim.min(5.0, 5.0), 5.0);
        assert_eq!(AxisDim.max(5.0, 5.0), 5.0);

        // Demonstrate with a wrapper type where "which one" is observable.
        #[derive(Clone, Copy, Debug)]
        struct Tagged(f64, &'static str);
        struct TaggedDim;
        impl Dimension<Tagged, MockPoint, MockBox> for TaggedDim {
            fn value(&self, _point: &MockPoint) -> Tagged {
                unimplemented!()
            }
            fn compare(&self, a: &Tagged, b: &Tagged) -> Ordering {
                a.0.partial_cmp(&b.0).unwrap()
            }
            fn distance(&self, _upper: &Tagged, _lower: &Tagged) -> f64 {
                0.0
            }
            fn mid(&self, a: &Tagged, _b: &Tagged) -> Tagged {
                *a
            }
            fn absolute_min(&self) -> Tagged {
                Tagged(f64::MIN, "min")
            }
            fn absolute_max(&self) -> Tagged {
                Tagged(f64::MAX, "max")
            }
        }
        let a = Tagged(3.0, "a");
        let b = Tagged(3.0, "b");
        assert_eq!(TaggedDim.min(a, b).1, "b");
        assert_eq!(TaggedDim.max(a, b).1, "b");
    }

    #[test]
    fn absolute_min_and_max() {
        assert_eq!(AxisDim.absolute_min(), f64::MIN);
        assert_eq!(AxisDim.absolute_max(), f64::MAX);
    }

    #[test]
    fn point_distance_delegates_to_distance() {
        // Java's `pointDistance(a, b)` is `distance(value(a), value(b))` -- a pure positional
        // delegation, NOT a magnitude-ordered "larger minus smaller". With this mock's
        // `distance(upper, lower) = upper - lower`, passing the smaller point first yields a
        // negative result, exactly mirroring what the real Java method would do.
        assert_eq!(AxisDim.point_distance(&MockPoint(2.0), &MockPoint(9.0)), -7.0);
        assert_eq!(AxisDim.point_distance(&MockPoint(9.0), &MockPoint(2.0)), 7.0);
    }

    #[test]
    fn contains_respects_bounds() {
        let b = MockBox { lo: 0.0, hi: 10.0 };
        assert!(AxisDim.contains(&b, &MockPoint(5.0)));
        assert!(AxisDim.contains(&b, &MockPoint(0.0)));
        assert!(AxisDim.contains(&b, &MockPoint(10.0)));
        assert!(!AxisDim.contains(&b, &MockPoint(-1.0)));
        assert!(!AxisDim.contains(&b, &MockPoint(11.0)));
    }

    #[test]
    fn intersect_detects_overlap() {
        let a = MockBox { lo: 0.0, hi: 5.0 };
        let b = MockBox { lo: 3.0, hi: 8.0 };
        let c = MockBox { lo: 6.0, hi: 8.0 };
        assert!(AxisDim.intersect(&a, &b));
        assert!(!AxisDim.intersect(&a, &c));
    }

    #[test]
    fn encloses_checks_full_containment() {
        let outer = MockBox { lo: 0.0, hi: 10.0 };
        let inner = MockBox { lo: 2.0, hi: 8.0 };
        assert!(AxisDim.encloses(&outer, &inner));
        assert!(!AxisDim.encloses(&inner, &outer));
    }

    #[test]
    fn intersection_and_union_bounds() {
        let a = MockBox { lo: 0.0, hi: 5.0 };
        let b = MockBox { lo: 3.0, hi: 8.0 };
        assert_eq!(AxisDim.intersection_lower(&a, &b), 3.0);
        assert_eq!(AxisDim.intersection_upper(&a, &b), 5.0);
        assert_eq!(AxisDim.union_lower(&a, &b), 0.0);
        assert_eq!(AxisDim.union_upper(&a, &b), 8.0);
    }

    #[test]
    fn measure_is_upper_minus_lower() {
        let b = MockBox { lo: 2.0, hi: 9.0 };
        assert_eq!(AxisDim.measure(&b), 7.0);
    }

    #[test]
    fn trait_object_usable_behind_dyn() {
        let dim: &dyn Dimension<f64, MockPoint, MockBox> = &AxisDim;
        let b = MockBox { lo: 1.0, hi: 3.0 };
        assert_eq!(dim.measure(&b), 2.0);
    }
}
