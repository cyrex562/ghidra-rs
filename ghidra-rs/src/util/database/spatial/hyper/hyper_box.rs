use std::sync::Arc;

use super::{EuclideanHyperSpace, HyperPoint};

/// A multi-dimensional axis-aligned box.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.HyperBox<P, B>`.
///
/// The Java interface is `HyperBox<P extends HyperPoint, B extends HyperBox<P, B>>`, an
/// F-bounded type extending `BoundingShape<B>`. In Rust the F-bound collapses to `Self`, matching
/// the workaround used by [`super::super::rect::Rectangle2D`] for the analogous cyclic bound:
/// `Self: BoundingShape` is intentionally NOT declared as a supertrait here (it would clash with
/// this trait's own `get_area`/`get_margin`/`encloses`/etc. default methods of the same name), so
/// an implementor that wants to satisfy [`super::super::BoundingShape`] implements it separately,
/// delegating to the default methods below.
pub trait HyperBox<P: HyperPoint>: Sized {
    /// The coordinate space this box lives in, mirroring `space()`.
    fn space(&self) -> Arc<dyn EuclideanHyperSpace<P, Self>>;

    /// The lower corner of this box, mirroring `lCorner()`.
    fn l_corner(&self) -> P;

    /// The upper corner of this box, mirroring `uCorner()`.
    fn u_corner(&self) -> P;

    /// Constructs a new box with the given corners in the same space, mirroring
    /// `immutable(P, P)`.
    fn immutable(&self, l_corner: P, u_corner: P) -> Self;

    /// Mirrors `HyperBox.doEquals`: two boxes are equal if they share the same space (by
    /// identity) and have equal bounds in every dimension.
    ///
    /// The Java version accepts any `Object` and checks `instanceof HyperBox<?, ?>` at runtime
    /// because of type erasure; Rust's type system enforces the equivalent constraint at compile
    /// time (both sides must already be the same `Self`) instead.
    fn do_equals(&self, other: &Self) -> bool {
        let this_space = self.space();
        let that_space = other.space();
        if !Arc::ptr_eq(&this_space, &that_space) {
            return false;
        }
        this_space.boxes_equal(self, other)
    }

    /// Mirrors `HyperBox.doHashCode`: hashes the interleaved lower/upper bound keys across every
    /// dimension, matching `Objects.hash(space().collectBounds(this))`.
    fn do_hash_code(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.space().collect_bounds(self).hash(&mut hasher);
        hasher.finish()
    }

    /// Returns `true` if this box contains `p`, mirroring `contains(P)`.
    fn contains(&self, p: &P) -> bool {
        self.space().box_contains(self, p)
    }

    /// Returns the area of this box, mirroring `getArea()`.
    fn get_area(&self) -> f64 {
        self.space().box_area(self)
    }

    /// Returns the margin (sum of dimension extents) of this box, mirroring `getMargin()`.
    fn get_margin(&self) -> f64 {
        self.space().box_margin(self)
    }

    /// Returns the center point of this box, mirroring `getCenter()`.
    fn center(&self) -> P {
        self.space().box_center(self)
    }

    /// Computes the area of the smallest box enclosing both this box and `shape`, mirroring
    /// `computeAreaUnionBounds(B)`.
    fn compute_area_union_bounds(&self, shape: &Self) -> f64 {
        self.space().compute_area_union_bounds(self, shape)
    }

    /// Computes the area of the intersection of this box and `shape`, mirroring
    /// `computeAreaIntersection(B)`.
    fn compute_area_intersection(&self, shape: &Self) -> f64 {
        self.space().compute_area_intersection(self, shape)
    }

    /// Computes the distance between the centroids of this box and `shape`, mirroring
    /// `computeCentroidDistance(B)`.
    fn compute_centroid_distance(&self, shape: &Self) -> f64 {
        self.space().sq_distance(&self.center(), &shape.center())
    }

    /// Returns the smallest box that contains both this box and `shape`, mirroring
    /// `unionBounds(B)`.
    fn union_bounds(&self, shape: &Self) -> Self {
        self.space().box_union_bounds(self, shape)
    }

    /// Returns `true` if this box fully encloses `shape`, mirroring `encloses(B)`.
    fn encloses(&self, shape: &Self) -> bool {
        self.space().box_encloses(self, shape)
    }

    /// Returns the intersection of this box and `shape`, mirroring `intersection(B)`.
    fn intersection(&self, shape: &Self) -> Self {
        self.space().box_intersection(self, shape)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::util::seam_stubs::Dimension;

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
            line1d()
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

    struct AxisDim;
    impl Dimension<MockPoint, MockBox> for AxisDim {
        fn lower_key(&self, box_: &MockBox) -> String {
            box_.lo.to_string()
        }
        fn upper_key(&self, box_: &MockBox) -> String {
            box_.hi.to_string()
        }
        fn contains(&self, box_: &MockBox, point: &MockPoint) -> bool {
            point.0 >= box_.lo && point.0 <= box_.hi
        }
        fn measure(&self, box_: &MockBox) -> f64 {
            box_.hi - box_.lo
        }
        fn measure_union(&self, a: &MockBox, b: &MockBox) -> f64 {
            a.hi.max(b.hi) - a.lo.min(b.lo)
        }
        fn measure_intersection(&self, a: &MockBox, b: &MockBox) -> f64 {
            let lo = a.lo.max(b.lo);
            let hi = a.hi.min(b.hi);
            if lo > hi {
                0.0
            } else {
                hi - lo
            }
        }
        fn point_distance(&self, a: &MockPoint, b: &MockPoint) -> f64 {
            (a.0 - b.0).abs()
        }
        fn encloses(&self, outer: &MockBox, inner: &MockBox) -> bool {
            outer.lo <= inner.lo && outer.hi >= inner.hi
        }
    }

    struct Line1D {
        dims: Vec<Box<dyn Dimension<MockPoint, MockBox>>>,
    }

    impl EuclideanHyperSpace<MockPoint, MockBox> for Line1D {
        fn dimensions(&self) -> &[Box<dyn Dimension<MockPoint, MockBox>>] {
            &self.dims
        }
        fn full(&self) -> MockBox {
            MockBox { lo: f64::MIN, hi: f64::MAX }
        }
        fn box_center(&self, box_: &MockBox) -> MockPoint {
            MockPoint((box_.lo + box_.hi) / 2.0)
        }
        fn box_union_bounds(&self, a: &MockBox, b: &MockBox) -> MockBox {
            MockBox { lo: a.lo.min(b.lo), hi: a.hi.max(b.hi) }
        }
        fn box_intersection(&self, b: &MockBox, shape: &MockBox) -> MockBox {
            MockBox { lo: b.lo.max(shape.lo), hi: b.hi.min(shape.hi) }
        }
    }

    /// Shared singleton space, mirroring the way Java implementors thread `this` through as
    /// `space()`'s return value without needing a self-referential struct here.
    fn line1d() -> Arc<Line1D> {
        static SPACE: OnceLock<Arc<Line1D>> = OnceLock::new();
        SPACE
            .get_or_init(|| Arc::new(Line1D { dims: vec![Box::new(AxisDim)] }))
            .clone()
    }

    #[test]
    fn do_equals_true_for_equal_bounds() {
        let a = MockBox { lo: 1.0, hi: 2.0 };
        let b = MockBox { lo: 1.0, hi: 2.0 };
        assert!(a.do_equals(&b));
    }

    #[test]
    fn do_equals_false_for_different_bounds() {
        let a = MockBox { lo: 1.0, hi: 2.0 };
        let b = MockBox { lo: 1.0, hi: 3.0 };
        assert!(!a.do_equals(&b));
    }

    #[test]
    fn do_hash_code_matches_for_equal_boxes() {
        let a = MockBox { lo: 1.5, hi: 3.5 };
        let b = MockBox { lo: 1.5, hi: 3.5 };
        assert_eq!(a.do_hash_code(), b.do_hash_code());
    }

    #[test]
    fn do_hash_code_differs_for_different_boxes() {
        let a = MockBox { lo: 1.5, hi: 3.5 };
        let b = MockBox { lo: 1.5, hi: 4.0 };
        assert_ne!(a.do_hash_code(), b.do_hash_code());
    }

    #[test]
    fn contains_respects_bounds() {
        let b = MockBox { lo: 0.0, hi: 10.0 };
        assert!(b.contains(&MockPoint(5.0)));
        assert!(!b.contains(&MockPoint(15.0)));
    }

    #[test]
    fn area_and_margin() {
        let b = MockBox { lo: 2.0, hi: 5.0 };
        assert_eq!(b.get_area(), 4.0); // 1 + (5-2)
        assert_eq!(b.get_margin(), 4.0);
    }

    #[test]
    fn center_is_midpoint() {
        let b = MockBox { lo: 0.0, hi: 10.0 };
        assert_eq!(b.center(), MockPoint(5.0));
    }

    #[test]
    fn union_bounds_and_intersection() {
        let outer = MockBox { lo: 0.0, hi: 10.0 };
        let inner = MockBox { lo: 2.0, hi: 8.0 };

        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));

        assert_eq!(outer.union_bounds(&inner), outer);
        assert_eq!(outer.intersection(&inner), inner);
    }

    #[test]
    fn compute_area_union_and_intersection() {
        let a = MockBox { lo: 0.0, hi: 4.0 };
        let b = MockBox { lo: 2.0, hi: 6.0 };
        assert_eq!(a.compute_area_union_bounds(&b), 7.0); // 1 + (6-0)
        assert_eq!(a.compute_area_intersection(&b), 3.0); // 1 + (4-2)
    }

    #[test]
    fn compute_centroid_distance_squared() {
        let a = MockBox { lo: 0.0, hi: 2.0 }; // center 1.0
        let b = MockBox { lo: 3.0, hi: 5.0 }; // center 4.0
        assert_eq!(a.compute_centroid_distance(&b), 9.0);
    }

    #[test]
    fn immutable_constructs_new_box() {
        let b = MockBox { lo: 0.0, hi: 10.0 };
        let n = b.immutable(MockPoint(1.0), MockPoint(9.0));
        assert_eq!(n, MockBox { lo: 1.0, hi: 9.0 });
    }

    #[test]
    fn object_safety_of_dependencies_via_boxed_space() {
        // Proves the space this box reports is itself usable as a trait object.
        let b = MockBox { lo: 0.0, hi: 4.0 };
        let space: Arc<dyn EuclideanHyperSpace<MockPoint, MockBox>> = b.space();
        assert_eq!(space.box_area(&b), 5.0);
    }
}
