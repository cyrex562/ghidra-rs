use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use super::euclidean_space2d::EuclideanSpace2D;
use super::immutable_point_2d::ImmutablePoint2D;
use super::point2d::Point2D;

/// A 2D axis-aligned rectangle over a generic coordinate space.
///
/// Corresponds to `ghidra.util.database.spatial.rect.Rectangle2D`.
///
/// The Java interface is `Rectangle2D<X, Y, R extends Rectangle2D<X, Y, R>>`, an
/// F-bounded type extending `BoundingShape<R>`. In Rust the F-bound collapses to
/// `Self`: implementors provide `X`, `Y`, and `Space` as associated types, and
/// every default method that took an `R` argument in Java takes `&Self` here.
///
/// The `extends BoundingShape<R>` relationship is intentionally NOT reproduced
/// as a Rust supertrait bound: [`super::super::BoundingShape`] declares
/// `get_area`, `get_margin`, `encloses`, etc. as required (non-default) methods,
/// so a `Self: BoundingShape` bound would not let this trait's identically-named
/// default methods satisfy them, and would only invite ambiguous-method-call
/// errors for any type implementing both. An implementor that wants to satisfy
/// `BoundingShape` should implement it separately, delegating to the default
/// methods below (mirroring the workaround already used by
/// [`super::super::BoundedShape`] for the same cyclic-bound problem).
pub trait Rectangle2D: Sized {
    /// The type of X-axis coordinate values.
    type X;
    /// The type of Y-axis coordinate values.
    type Y;
    /// The coordinate space this rectangle lives in.
    type Space: EuclideanSpace2D<X = Self::X, Y = Self::Y>;

    /// Returns the lower X bound.
    fn get_x1(&self) -> &Self::X;

    /// Returns the upper X bound.
    fn get_x2(&self) -> &Self::X;

    /// Returns the lower Y bound.
    fn get_y1(&self) -> &Self::Y;

    /// Returns the upper Y bound.
    fn get_y2(&self) -> &Self::Y;

    /// Returns the coordinate space this rectangle lives in.
    fn get_space(&self) -> &Self::Space;

    /// Constructs a new rectangle with the given bounds in the same space.
    fn immutable(&self, x1: Self::X, x2: Self::X, y1: Self::Y, y2: Self::Y) -> Self;

    /// Mirrors `Rectangle2D.doEquals`: compares all four coordinate fields
    /// against another rectangle sharing the same coordinate types.
    ///
    /// The Java version accepts any `Object` and checks `instanceof
    /// Rectangle2D` at runtime because of type erasure; Rust's type system
    /// enforces the equivalent constraint (`R::X == Self::X`, `R::Y ==
    /// Self::Y`) at compile time instead.
    fn rect_eq<R>(&self, other: &R) -> bool
    where
        R: Rectangle2D<X = Self::X, Y = Self::Y>,
        Self::X: PartialEq,
        Self::Y: PartialEq,
    {
        self.get_x1() == other.get_x1()
            && self.get_x2() == other.get_x2()
            && self.get_y1() == other.get_y1()
            && self.get_y2() == other.get_y2()
    }

    /// Mirrors `Rectangle2D.doHashCode`: hashes the four coordinate fields in
    /// declaration order, matching `Objects.hash(x1, x2, y1, y2)` semantics.
    fn rect_hash<H: Hasher>(&self, state: &mut H)
    where
        Self::X: Hash,
        Self::Y: Hash,
    {
        self.get_x1().hash(state);
        self.get_x2().hash(state);
        self.get_y1().hash(state);
        self.get_y2().hash(state);
    }

    /// Returns `true` if this rectangle contains `point`.
    fn contains_point<P>(&self, point: &P) -> bool
    where
        P: Point2D<X = Self::X, Y = Self::Y>,
    {
        self.contains(point.get_x(), point.get_y())
    }

    /// Returns `true` if this rectangle contains the coordinate `(x, y)`.
    fn contains(&self, x: &Self::X, y: &Self::Y) -> bool {
        if self.get_space().compare_x(x, self.get_x1()) == Ordering::Less {
            return false;
        }
        if self.get_space().compare_x(x, self.get_x2()) == Ordering::Greater {
            return false;
        }
        if self.get_space().compare_y(y, self.get_y1()) == Ordering::Less {
            return false;
        }
        if self.get_space().compare_y(y, self.get_y2()) == Ordering::Greater {
            return false;
        }
        true
    }

    /// Returns the area of this rectangle. Corresponds to `Rectangle2D.getArea`.
    fn get_area(&self) -> f64 {
        let width = self.get_space().dist_x(self.get_x2(), self.get_x1()) + 1.0;
        let height = self.get_space().dist_y(self.get_y2(), self.get_y1()) + 1.0;
        width * height
    }

    /// Returns the margin (sum of edge lengths) of this rectangle.
    /// Corresponds to `Rectangle2D.getMargin`.
    fn get_margin(&self) -> f64 {
        let width = self.get_space().dist_x(self.get_x2(), self.get_x1()) + 1.0;
        let height = self.get_space().dist_y(self.get_y2(), self.get_y1()) + 1.0;
        width + height
    }

    /// Returns the center point of this rectangle.
    /// Corresponds to `Rectangle2D.getCenter`.
    fn get_center(&self) -> ImmutablePoint2D<Self::Space>
    where
        Self::Space: Clone,
    {
        let x = self.get_space().mid_x(self.get_x1(), self.get_x2());
        let y = self.get_space().mid_y(self.get_y1(), self.get_y2());
        ImmutablePoint2D::new(x, y, self.get_space().clone())
    }

    /// Computes the area of the smallest bounding box that contains both this
    /// rectangle and `other`. Corresponds to `Rectangle2D.computeAreaUnionBounds`.
    fn compute_area_union_bounds(&self, other: &Self) -> f64 {
        let union_x1 = self.get_space().min_x(self.get_x1(), other.get_x1());
        let union_x2 = self.get_space().max_x(self.get_x2(), other.get_x2());
        let union_y1 = self.get_space().min_y(self.get_y1(), other.get_y1());
        let union_y2 = self.get_space().max_y(self.get_y2(), other.get_y2());
        let width = self.get_space().dist_x(union_x2, union_x1) + 1.0;
        let height = self.get_space().dist_y(union_y2, union_y1) + 1.0;
        width * height
    }

    /// Computes the area of the intersection of this rectangle and `other`, or
    /// `0` if they do not overlap.
    /// Corresponds to `Rectangle2D.computeAreaIntersection`.
    fn compute_area_intersection(&self, other: &Self) -> f64 {
        let int_x1 = self.get_space().max_x(self.get_x1(), other.get_x1());
        let int_x2 = self.get_space().min_x(self.get_x2(), other.get_x2());
        let int_y1 = self.get_space().max_y(self.get_y1(), other.get_y1());
        let int_y2 = self.get_space().min_y(self.get_y2(), other.get_y2());
        if self.get_space().compare_x(int_x1, int_x2) == Ordering::Greater
            || self.get_space().compare_y(int_y1, int_y2) == Ordering::Greater
        {
            return 0.0;
        }
        let width = self.get_space().dist_x(int_x2, int_x1) + 1.0;
        let height = self.get_space().dist_y(int_y2, int_y1) + 1.0;
        width * height
    }

    /// Computes the distance between the centroids of this rectangle and `other`.
    /// Corresponds to `Rectangle2D.computeCentroidDistance`.
    fn compute_centroid_distance(&self, other: &Self) -> f64
    where
        Self::Space: Clone,
    {
        self.get_center().compute_distance(&other.get_center())
    }

    /// Returns the smallest rectangle that contains both this rectangle and
    /// `other`. Corresponds to `Rectangle2D.unionBounds`.
    fn union_bounds(&self, other: &Self) -> Self
    where
        Self::X: Clone,
        Self::Y: Clone,
    {
        let union_x1 = self.get_space().min_x(self.get_x1(), other.get_x1()).clone();
        let union_x2 = self.get_space().max_x(self.get_x2(), other.get_x2()).clone();
        let union_y1 = self.get_space().min_y(self.get_y1(), other.get_y1()).clone();
        let union_y2 = self.get_space().max_y(self.get_y2(), other.get_y2()).clone();
        self.immutable(union_x1, union_x2, union_y1, union_y2)
    }

    /// Returns `true` if this rectangle intersects (overlaps) `other`.
    /// Corresponds to `Rectangle2D.intersects`.
    fn intersects(&self, other: &Self) -> bool {
        if self.get_space().compare_x(self.get_x1(), other.get_x2()) == Ordering::Greater {
            return false;
        }
        if self.get_space().compare_x(self.get_x2(), other.get_x1()) == Ordering::Less {
            return false;
        }
        if self.get_space().compare_y(self.get_y1(), other.get_y2()) == Ordering::Greater {
            return false;
        }
        if self.get_space().compare_y(self.get_y2(), other.get_y1()) == Ordering::Less {
            return false;
        }
        true
    }

    /// Returns the intersection of this rectangle and `other`.
    ///
    /// # Panics
    ///
    /// Panics if the rectangles do not overlap, mirroring the
    /// `NoSuchElementException` thrown by `Rectangle2D.intersection` in Java.
    fn intersection(&self, other: &Self) -> Self
    where
        Self::X: Clone,
        Self::Y: Clone,
    {
        let int_x1 = self.get_space().max_x(self.get_x1(), other.get_x1()).clone();
        let int_x2 = self.get_space().min_x(self.get_x2(), other.get_x2()).clone();
        let int_y1 = self.get_space().max_y(self.get_y1(), other.get_y1()).clone();
        let int_y2 = self.get_space().min_y(self.get_y2(), other.get_y2()).clone();
        if self.get_space().compare_x(&int_x1, &int_x2) == Ordering::Greater
            || self.get_space().compare_y(&int_y1, &int_y2) == Ordering::Greater
        {
            panic!("rectangles do not intersect");
        }
        self.immutable(int_x1, int_x2, int_y1, int_y2)
    }

    /// Checks if this rectangle encloses another rectangle.
    ///
    /// Corresponds to `Rectangle2D.encloses(R)`.
    fn encloses(&self, other: &Self) -> bool {
        encloses(self, other)
    }

    /// Checks if this rectangle is enclosed by another rectangle.
    ///
    /// Corresponds to `Rectangle2D.enclosedBy`.
    fn enclosed_by(&self, other: &Self) -> bool {
        encloses(other, self)
    }
}

/// Checks if `outer` encloses `inner`, using `outer`'s coordinate space for
/// all comparisons.
///
/// Corresponds to the static `Rectangle2D.encloses(Rectangle2D, Rectangle2D)`.
pub fn encloses<O, I>(outer: &O, inner: &I) -> bool
where
    O: Rectangle2D,
    I: Rectangle2D<X = O::X, Y = O::Y>,
{
    if outer.get_space().compare_x(outer.get_x1(), inner.get_x1()) == Ordering::Greater {
        return false;
    }
    if outer.get_space().compare_x(outer.get_x2(), inner.get_x2()) == Ordering::Less {
        return false;
    }
    if outer.get_space().compare_y(outer.get_y1(), inner.get_y1()) == Ordering::Greater {
        return false;
    }
    if outer.get_space().compare_y(outer.get_y2(), inner.get_y2()) == Ordering::Less {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;

    use super::*;

    #[derive(Clone)]
    struct IntSpace;

    struct FullRect;

    impl EuclideanSpace2D for IntSpace {
        type X = i64;
        type Y = i64;
        type Rect = FullRect;

        fn compare_x(&self, x1: &i64, x2: &i64) -> Ordering {
            x1.cmp(x2)
        }
        fn compare_y(&self, y1: &i64, y2: &i64) -> Ordering {
            y1.cmp(y2)
        }
        fn dist_x(&self, x1: &i64, x2: &i64) -> f64 {
            (x2 - x1).unsigned_abs() as f64
        }
        fn dist_y(&self, y1: &i64, y2: &i64) -> f64 {
            (y2 - y1).unsigned_abs() as f64
        }
        fn mid_x(&self, x1: &i64, x2: &i64) -> i64 {
            x1 + (x2 - x1) / 2
        }
        fn mid_y(&self, y1: &i64, y2: &i64) -> i64 {
            y1 + (y2 - y1) / 2
        }
        fn get_full(&self) -> FullRect {
            FullRect
        }
    }

    struct Rect {
        x1: i64,
        x2: i64,
        y1: i64,
        y2: i64,
        space: IntSpace,
    }

    impl Rectangle2D for Rect {
        type X = i64;
        type Y = i64;
        type Space = IntSpace;

        fn get_x1(&self) -> &i64 {
            &self.x1
        }
        fn get_x2(&self) -> &i64 {
            &self.x2
        }
        fn get_y1(&self) -> &i64 {
            &self.y1
        }
        fn get_y2(&self) -> &i64 {
            &self.y2
        }
        fn get_space(&self) -> &IntSpace {
            &self.space
        }
        fn immutable(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> Self {
            Rect { x1, x2, y1, y2, space: IntSpace }
        }
    }

    /// A second, independent rectangle type used to exercise cross-type `rect_eq`.
    struct OtherRect {
        x1: i64,
        x2: i64,
        y1: i64,
        y2: i64,
        space: IntSpace,
    }

    impl Rectangle2D for OtherRect {
        type X = i64;
        type Y = i64;
        type Space = IntSpace;

        fn get_x1(&self) -> &i64 {
            &self.x1
        }
        fn get_x2(&self) -> &i64 {
            &self.x2
        }
        fn get_y1(&self) -> &i64 {
            &self.y1
        }
        fn get_y2(&self) -> &i64 {
            &self.y2
        }
        fn get_space(&self) -> &IntSpace {
            &self.space
        }
        fn immutable(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> Self {
            OtherRect { x1, x2, y1, y2, space: IntSpace }
        }
    }

    struct Pt {
        x: i64,
        y: i64,
        space: IntSpace,
    }

    impl Point2D for Pt {
        type X = i64;
        type Y = i64;
        type Space = IntSpace;

        fn get_x(&self) -> &i64 {
            &self.x
        }
        fn get_y(&self) -> &i64 {
            &self.y
        }
        fn get_space(&self) -> &IntSpace {
            &self.space
        }
    }

    fn rect(x1: i64, x2: i64, y1: i64, y2: i64) -> Rect {
        Rect { x1, x2, y1, y2, space: IntSpace }
    }

    fn other_rect(x1: i64, x2: i64, y1: i64, y2: i64) -> OtherRect {
        OtherRect { x1, x2, y1, y2, space: IntSpace }
    }

    fn hash_of<R: Rectangle2D<X = i64, Y = i64>>(r: &R) -> u64 {
        let mut h = DefaultHasher::new();
        r.rect_hash(&mut h);
        h.finish()
    }

    // ── contains ──────────────────────────────────────────────────────────────

    #[test]
    fn contains_point_inside() {
        let r = rect(0, 4, 0, 4);
        assert!(r.contains(&2, &2));
    }

    #[test]
    fn contains_boundary_is_inclusive() {
        let r = rect(0, 4, 0, 4);
        assert!(r.contains(&0, &0));
        assert!(r.contains(&4, &4));
    }

    #[test]
    fn contains_outside_x_is_false() {
        let r = rect(0, 4, 0, 4);
        assert!(!r.contains(&5, &2));
        assert!(!r.contains(&-1, &2));
    }

    #[test]
    fn contains_outside_y_is_false() {
        let r = rect(0, 4, 0, 4);
        assert!(!r.contains(&2, &5));
        assert!(!r.contains(&2, &-1));
    }

    #[test]
    fn contains_point_delegates_to_contains() {
        let r = rect(0, 4, 0, 4);
        let p = Pt { x: 2, y: 2, space: IntSpace };
        assert!(r.contains_point(&p));

        let outside = Pt { x: 9, y: 9, space: IntSpace };
        assert!(!r.contains_point(&outside));
    }

    // ── area / margin ─────────────────────────────────────────────────────────

    #[test]
    fn get_area_computes_width_times_height() {
        let r = rect(0, 4, 0, 3);
        // width = dist(4,0)+1 = 5, height = dist(3,0)+1 = 4
        assert_eq!(r.get_area(), 20.0);
    }

    #[test]
    fn get_area_degenerate_point_rect_is_one() {
        let r = rect(3, 3, 7, 7);
        assert_eq!(r.get_area(), 1.0);
    }

    #[test]
    fn get_margin_computes_width_plus_height() {
        let r = rect(0, 4, 0, 3);
        assert_eq!(r.get_margin(), 9.0);
    }

    // ── center ────────────────────────────────────────────────────────────────

    #[test]
    fn get_center_computes_midpoint() {
        let r = rect(0, 4, 0, 3);
        let c = r.get_center();
        assert_eq!(c.get_x(), &2);
        assert_eq!(c.get_y(), &1);
    }

    // ── union / intersection area ────────────────────────────────────────────

    #[test]
    fn compute_area_union_bounds_disjoint_rects() {
        let a = rect(0, 2, 0, 2);
        let b = rect(4, 6, 4, 6);
        // union spans x:[0,6], y:[0,6] -> width = 7, height = 7
        assert_eq!(a.compute_area_union_bounds(&b), 49.0);
    }

    #[test]
    fn compute_area_intersection_overlapping_rects() {
        let a = rect(0, 4, 0, 4);
        let b = rect(2, 6, 2, 6);
        // intersection spans x:[2,4], y:[2,4] -> width = 3, height = 3
        assert_eq!(a.compute_area_intersection(&b), 9.0);
    }

    #[test]
    fn compute_area_intersection_disjoint_is_zero() {
        let a = rect(0, 2, 0, 2);
        let b = rect(5, 7, 5, 7);
        assert_eq!(a.compute_area_intersection(&b), 0.0);
    }

    // ── centroid distance ─────────────────────────────────────────────────────

    #[test]
    fn compute_centroid_distance_3_4_5() {
        let a = rect(0, 2, 0, 2); // center (1,1)
        let b = rect(4, 6, 5, 7); // center (5,6)
        // dist_x=4, dist_y=5 -> squared distance = 16+25=41 (no sqrt, per Point2D::compute_distance)
        assert_eq!(a.compute_centroid_distance(&b), 41.0);
    }

    #[test]
    fn compute_centroid_distance_same_rect_is_zero() {
        let a = rect(1, 5, 2, 6);
        assert_eq!(a.compute_centroid_distance(&a), 0.0);
    }

    // ── union_bounds ──────────────────────────────────────────────────────────

    #[test]
    fn union_bounds_merges_extents() {
        let a = rect(0, 3, 0, 3);
        let b = rect(1, 5, -2, 4);
        let u = a.union_bounds(&b);
        assert_eq!((u.x1, u.x2, u.y1, u.y2), (0, 5, -2, 4));
    }

    // ── intersects ────────────────────────────────────────────────────────────

    #[test]
    fn intersects_overlapping_is_true() {
        let a = rect(0, 4, 0, 4);
        let b = rect(2, 6, 2, 6);
        assert!(a.intersects(&b));
    }

    #[test]
    fn intersects_touching_edges_is_true() {
        let a = rect(0, 4, 0, 4);
        let b = rect(4, 8, 4, 8);
        assert!(a.intersects(&b));
    }

    #[test]
    fn intersects_disjoint_is_false() {
        let a = rect(0, 2, 0, 2);
        let b = rect(5, 7, 5, 7);
        assert!(!a.intersects(&b));
    }

    // ── intersection ──────────────────────────────────────────────────────────

    #[test]
    fn intersection_overlapping_rects() {
        let a = rect(0, 4, 0, 4);
        let b = rect(2, 6, 2, 6);
        let i = a.intersection(&b);
        assert_eq!((i.x1, i.x2, i.y1, i.y2), (2, 4, 2, 4));
    }

    #[test]
    #[should_panic]
    fn intersection_disjoint_rects_panics() {
        let a = rect(0, 2, 0, 2);
        let b = rect(5, 7, 5, 7);
        let _ = a.intersection(&b);
    }

    // ── encloses / enclosed_by ────────────────────────────────────────────────

    #[test]
    fn encloses_inner_rect() {
        let outer = rect(0, 10, 0, 10);
        let inner = rect(2, 8, 2, 8);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn encloses_equal_rects_is_true() {
        let a = rect(1, 5, 2, 6);
        let b = rect(1, 5, 2, 6);
        assert!(a.encloses(&b));
    }

    #[test]
    fn encloses_false_for_partial_overlap() {
        let a = rect(0, 5, 0, 5);
        let b = rect(3, 8, 3, 8);
        assert!(!a.encloses(&b));
    }

    #[test]
    fn enclosed_by_mirrors_encloses() {
        let outer = rect(0, 10, 0, 10);
        let inner = rect(2, 8, 2, 8);
        assert!(inner.enclosed_by(&outer));
        assert!(!outer.enclosed_by(&inner));
    }

    #[test]
    fn free_function_encloses_matches_trait_method() {
        let outer = rect(0, 10, 0, 10);
        let inner = rect(2, 8, 2, 8);
        assert!(encloses(&outer, &inner));
        assert!(!encloses(&inner, &outer));
    }

    // ── rect_eq / rect_hash ───────────────────────────────────────────────────

    #[test]
    fn rect_eq_true_for_matching_coords() {
        let a = rect(1, 5, 2, 6);
        let b = rect(1, 5, 2, 6);
        assert!(a.rect_eq(&b));
    }

    #[test]
    fn rect_eq_false_when_a_coord_differs() {
        let a = rect(1, 5, 2, 6);
        let b = rect(0, 5, 2, 6);
        assert!(!a.rect_eq(&b));
    }

    #[test]
    fn rect_eq_across_distinct_rectangle_types() {
        let a = rect(1, 5, 2, 6);
        let b = other_rect(1, 5, 2, 6);
        assert!(a.rect_eq(&b));

        let c = other_rect(9, 9, 9, 9);
        assert!(!a.rect_eq(&c));
    }

    #[test]
    fn rect_hash_equal_for_matching_coords() {
        let a = rect(1, 5, 2, 6);
        let b = rect(1, 5, 2, 6);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn rect_hash_differs_for_different_coords() {
        let a = rect(1, 5, 2, 6);
        let b = rect(0, 5, 2, 6);
        assert_ne!(hash_of(&a), hash_of(&b));
    }
}
