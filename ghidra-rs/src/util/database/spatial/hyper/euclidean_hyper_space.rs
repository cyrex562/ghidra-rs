use super::HyperPoint;
use crate::util::seam_stubs::{Dimension, HyperBox};

/// A Euclidean-like multi-dimensional coordinate space over points `P` and boxes `B`.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.EuclideanHyperSpace`.
///
/// The space is defined entirely by its ordered list of [`Dimension`]s: every default method
/// here folds over [`dimensions`][Self::dimensions], delegating the per-dimension arithmetic to
/// the (currently placeholder) [`Dimension`] trait.
pub trait EuclideanHyperSpace<P: HyperPoint, B: HyperBox> {
    /// The dimensions making up this space, mirroring `getDimensions()`.
    fn dimensions(&self) -> &[Box<dyn Dimension<P, B>>];

    /// The box spanning the entire space, mirroring `getFull()`.
    fn full(&self) -> B;

    /// The center point of `box_`, mirroring `boxCenter(B)`.
    fn box_center(&self, box_: &B) -> P;

    /// The smallest box enclosing both `a` and `b`, mirroring `boxUnionBounds(B, B)`.
    fn box_union_bounds(&self, a: &B, b: &B) -> B;

    /// The box formed by intersecting `b` and `shape`, mirroring `boxIntersection(B, B)`.
    fn box_intersection(&self, b: &B, shape: &B) -> B;

    /// Whether `a` and `b` have identical bounds in every dimension, mirroring `boxesEqual(B, B)`.
    fn boxes_equal(&self, a: &B, b: &B) -> bool {
        self.dimensions().iter().all(|dim| {
            dim.lower_key(a) == dim.lower_key(b) && dim.upper_key(a) == dim.upper_key(b)
        })
    }

    /// The interleaved lower/upper bound keys of `box_` across every dimension, mirroring
    /// `collectBounds(B)` (which returns `Object[]`; string keys stand in for the erased
    /// per-dimension coordinate type, see [`Dimension`]).
    fn collect_bounds(&self, box_: &B) -> Vec<String> {
        let mut result = Vec::with_capacity(self.dimensions().len() * 2);
        for dim in self.dimensions() {
            result.push(dim.lower_key(box_));
            result.push(dim.upper_key(box_));
        }
        result
    }

    /// Whether `box_` contains `point` in every dimension, mirroring `boxContains(B, P)`.
    fn box_contains(&self, box_: &B, point: &P) -> bool {
        self.dimensions().iter().all(|dim| dim.contains(box_, point))
    }

    /// The area of `box_`, mirroring `boxArea(B)`.
    fn box_area(&self, box_: &B) -> f64 {
        self.dimensions()
            .iter()
            .fold(1.0, |acc, dim| acc * (1.0 + dim.measure(box_)))
    }

    /// The margin (sum of dimension extents) of `box_`, mirroring `boxMargin(B)`.
    fn box_margin(&self, box_: &B) -> f64 {
        self.dimensions()
            .iter()
            .fold(0.0, |acc, dim| acc + (1.0 + dim.measure(box_)))
    }

    /// The extent of the union of `a` and `b` along `dim`, mirroring `measureUnion(Dimension, B, B)`.
    fn measure_union(&self, dim: &dyn Dimension<P, B>, a: &B, b: &B) -> f64 {
        dim.measure_union(a, b)
    }

    /// The area of the smallest box enclosing both `a` and `b`, mirroring
    /// `computeAreaUnionBounds(B, B)`.
    fn compute_area_union_bounds(&self, a: &B, b: &B) -> f64 {
        self.dimensions()
            .iter()
            .fold(1.0, |acc, dim| acc * (1.0 + self.measure_union(dim.as_ref(), a, b)))
    }

    /// The extent of the intersection of `a` and `b` along `dim`, or `0` if they don't overlap,
    /// mirroring `measureIntersection(Dimension, B, B)`.
    fn measure_intersection(&self, dim: &dyn Dimension<P, B>, a: &B, b: &B) -> f64 {
        dim.measure_intersection(a, b)
    }

    /// The area of the intersection of `a` and `b`, or `0` if they don't overlap along any
    /// dimension, mirroring `computeAreaIntersection(B, B)`.
    fn compute_area_intersection(&self, a: &B, b: &B) -> f64 {
        let mut result = 1.0;
        for dim in self.dimensions() {
            let measure = self.measure_intersection(dim.as_ref(), a, b);
            if measure == 0.0 {
                return 0.0;
            }
            result *= 1.0 + measure;
        }
        result
    }

    /// The squared distance between `a` and `b`, mirroring `sqDistance(P, P)`.
    fn sq_distance(&self, a: &P, b: &P) -> f64 {
        self.dimensions().iter().fold(0.0, |acc, dim| {
            let dist = dim.point_distance(a, b);
            acc + dist * dist
        })
    }

    /// Whether `outer` encloses `inner` in every dimension, mirroring `boxEncloses(B, B)`.
    fn box_encloses(&self, outer: &B, inner: &B) -> bool {
        self.dimensions().iter().all(|dim| dim.encloses(outer, inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockPoint(f64);
    impl HyperPoint for MockPoint {}

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockBox {
        lo: f64,
        hi: f64,
    }
    impl HyperBox for MockBox {}

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

    impl Line1D {
        fn new() -> Self {
            Line1D {
                dims: vec![Box::new(AxisDim)],
            }
        }
    }

    impl EuclideanHyperSpace<MockPoint, MockBox> for Line1D {
        fn dimensions(&self) -> &[Box<dyn Dimension<MockPoint, MockBox>>] {
            &self.dims
        }
        fn full(&self) -> MockBox {
            MockBox {
                lo: f64::MIN,
                hi: f64::MAX,
            }
        }
        fn box_center(&self, box_: &MockBox) -> MockPoint {
            MockPoint((box_.lo + box_.hi) / 2.0)
        }
        fn box_union_bounds(&self, a: &MockBox, b: &MockBox) -> MockBox {
            MockBox {
                lo: a.lo.min(b.lo),
                hi: a.hi.max(b.hi),
            }
        }
        fn box_intersection(&self, b: &MockBox, shape: &MockBox) -> MockBox {
            MockBox {
                lo: b.lo.max(shape.lo),
                hi: b.hi.min(shape.hi),
            }
        }
    }

    #[test]
    fn box_area_and_margin_of_single_dimension() {
        // Proves object-safety: EuclideanHyperSpace can be used as a trait object.
        let space: Box<dyn EuclideanHyperSpace<MockPoint, MockBox>> = Box::new(Line1D::new());
        let b = MockBox { lo: 2.0, hi: 5.0 };
        assert_eq!(space.box_area(&b), 4.0); // 1 + (5-2)
        assert_eq!(space.box_margin(&b), 4.0);
    }

    #[test]
    fn box_contains_respects_bounds() {
        let space = Line1D::new();
        let b = MockBox { lo: 0.0, hi: 10.0 };
        assert!(space.box_contains(&b, &MockPoint(5.0)));
        assert!(!space.box_contains(&b, &MockPoint(15.0)));
    }

    #[test]
    fn boxes_equal_compares_all_dimensions() {
        let space = Line1D::new();
        let a = MockBox { lo: 1.0, hi: 2.0 };
        let b = MockBox { lo: 1.0, hi: 2.0 };
        let c = MockBox { lo: 1.0, hi: 3.0 };
        assert!(space.boxes_equal(&a, &b));
        assert!(!space.boxes_equal(&a, &c));
    }

    #[test]
    fn collect_bounds_interleaves_lower_upper() {
        let space = Line1D::new();
        let b = MockBox { lo: 1.5, hi: 3.5 };
        assert_eq!(
            space.collect_bounds(&b),
            vec!["1.5".to_string(), "3.5".to_string()]
        );
    }

    #[test]
    fn compute_area_union_and_intersection() {
        let space = Line1D::new();
        let a = MockBox { lo: 0.0, hi: 4.0 };
        let b = MockBox { lo: 2.0, hi: 6.0 };
        assert_eq!(space.compute_area_union_bounds(&a, &b), 7.0); // 1 + (6-0)
        assert_eq!(space.compute_area_intersection(&a, &b), 3.0); // 1 + (4-2)

        let disjoint = MockBox { lo: 10.0, hi: 12.0 };
        assert_eq!(space.compute_area_intersection(&a, &disjoint), 0.0);
    }

    #[test]
    fn sq_distance_between_points() {
        let space = Line1D::new();
        assert_eq!(space.sq_distance(&MockPoint(1.0), &MockPoint(4.0)), 9.0);
    }

    #[test]
    fn box_encloses_and_box_operations() {
        let space = Line1D::new();
        let outer = MockBox { lo: 0.0, hi: 10.0 };
        let inner = MockBox { lo: 2.0, hi: 8.0 };
        assert!(space.box_encloses(&outer, &inner));
        assert!(!space.box_encloses(&inner, &outer));

        let union = space.box_union_bounds(&outer, &inner);
        assert_eq!(union, outer);

        let intersection = space.box_intersection(&outer, &inner);
        assert_eq!(intersection, inner);

        let center = space.box_center(&outer);
        assert_eq!(center, MockPoint(5.0));
    }
}
