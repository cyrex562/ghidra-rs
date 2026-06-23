use super::BoundedShape;

/// A shape that acts as its own bounding container.
///
/// Corresponds to `ghidra.util.database.spatial.BoundingShape`.
///
/// The Java declaration uses F-bounded polymorphism:
/// `BoundingShape<S extends BoundingShape<S>> extends BoundedShape<S>`.
/// In Rust this maps to a trait that is its own bound via `BoundedShape<Self>`.
pub trait BoundingShape: BoundedShape<Self> + Sized {
    /// Returns the area of this bounding shape.
    fn get_area(&self) -> f64;

    /// Returns the margin (sum of edge lengths) of this bounding shape.
    fn get_margin(&self) -> f64;

    /// Computes the distance between the centroids of this shape and `other`.
    fn compute_centroid_distance(&self, other: &Self) -> f64;

    /// Computes the area of the smallest bounding box that contains both
    /// this shape and `other`.
    fn compute_area_union_bounds(&self, other: &Self) -> f64;

    /// Returns `true` if this shape fully encloses `other`.
    fn encloses(&self, other: &Self) -> bool;

    /// Computes the area of the intersection of this shape and `other`.
    fn compute_area_intersection(&self, other: &Self) -> f64;

    /// Returns the smallest bounding shape that contains both this shape and `other`.
    fn union_bounds(&self, other: &Self) -> Self;
}

/// Returns the union bounding shape of all `shapes`, or `None` if the iterator
/// is empty.
///
/// Corresponds to `BoundingShape.unionIterable` in the Java source.
pub fn union_iterable<S: BoundingShape>(shapes: impl IntoIterator<Item = S>) -> Option<S> {
    let mut iter = shapes.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |acc, s| acc.union_bounds(&s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Axis-aligned bounding rectangle used in tests.
    #[derive(Debug, Clone, PartialEq)]
    struct Rect {
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
    }

    impl Rect {
        fn new(x1: f64, y1: f64, x2: f64, y2: f64) -> Self {
            Rect { x1, y1, x2, y2 }
        }
    }

    impl BoundedShape<Rect> for Rect {
        fn get_bounds(&self) -> Rect {
            self.clone()
        }

        fn description(&self) -> String {
            format!("[{},{},{},{}]", self.x1, self.y1, self.x2, self.y2)
        }
    }

    impl BoundingShape for Rect {
        fn get_area(&self) -> f64 {
            (self.x2 - self.x1) * (self.y2 - self.y1)
        }

        fn get_margin(&self) -> f64 {
            2.0 * ((self.x2 - self.x1) + (self.y2 - self.y1))
        }

        fn compute_centroid_distance(&self, other: &Self) -> f64 {
            let cx = (self.x1 + self.x2) / 2.0;
            let cy = (self.y1 + self.y2) / 2.0;
            let ox = (other.x1 + other.x2) / 2.0;
            let oy = (other.y1 + other.y2) / 2.0;
            ((cx - ox).powi(2) + (cy - oy).powi(2)).sqrt()
        }

        fn compute_area_union_bounds(&self, other: &Self) -> f64 {
            let ux1 = self.x1.min(other.x1);
            let uy1 = self.y1.min(other.y1);
            let ux2 = self.x2.max(other.x2);
            let uy2 = self.y2.max(other.y2);
            (ux2 - ux1) * (uy2 - uy1)
        }

        fn encloses(&self, other: &Self) -> bool {
            self.x1 <= other.x1
                && self.y1 <= other.y1
                && self.x2 >= other.x2
                && self.y2 >= other.y2
        }

        fn compute_area_intersection(&self, other: &Self) -> f64 {
            let ix1 = self.x1.max(other.x1);
            let iy1 = self.y1.max(other.y1);
            let ix2 = self.x2.min(other.x2);
            let iy2 = self.y2.min(other.y2);
            if ix2 > ix1 && iy2 > iy1 {
                (ix2 - ix1) * (iy2 - iy1)
            } else {
                0.0
            }
        }

        fn union_bounds(&self, other: &Self) -> Self {
            Rect::new(
                self.x1.min(other.x1),
                self.y1.min(other.y1),
                self.x2.max(other.x2),
                self.y2.max(other.y2),
            )
        }
    }

    #[test]
    fn get_area_width_times_height() {
        let r = Rect::new(0.0, 0.0, 4.0, 3.0);
        assert_eq!(r.get_area(), 12.0);
    }

    #[test]
    fn get_margin_twice_perimeter() {
        let r = Rect::new(0.0, 0.0, 4.0, 3.0);
        assert_eq!(r.get_margin(), 14.0);
    }

    #[test]
    fn compute_centroid_distance_3_4_5() {
        // centroids: (1,1) and (4,5) → distance 5
        let a = Rect::new(0.0, 0.0, 2.0, 2.0);
        let b = Rect::new(3.0, 4.0, 5.0, 6.0);
        assert_eq!(a.compute_centroid_distance(&b), 5.0);
    }

    #[test]
    fn compute_centroid_distance_same_shape_is_zero() {
        let r = Rect::new(1.0, 1.0, 3.0, 3.0);
        assert_eq!(r.compute_centroid_distance(&r), 0.0);
    }

    #[test]
    fn compute_area_union_bounds_overlapping() {
        let a = Rect::new(0.0, 0.0, 3.0, 3.0);
        let b = Rect::new(1.0, 1.0, 4.0, 4.0);
        assert_eq!(a.compute_area_union_bounds(&b), 16.0); // 4×4
    }

    #[test]
    fn encloses_inner_rect() {
        let outer = Rect::new(0.0, 0.0, 10.0, 10.0);
        let inner = Rect::new(2.0, 2.0, 8.0, 8.0);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn encloses_false_for_partial_overlap() {
        let a = Rect::new(0.0, 0.0, 5.0, 5.0);
        let b = Rect::new(3.0, 3.0, 8.0, 8.0);
        assert!(!a.encloses(&b));
    }

    #[test]
    fn compute_area_intersection_overlapping() {
        let a = Rect::new(0.0, 0.0, 5.0, 5.0);
        let b = Rect::new(3.0, 3.0, 8.0, 8.0);
        assert_eq!(a.compute_area_intersection(&b), 4.0); // 2×2
    }

    #[test]
    fn compute_area_intersection_disjoint_is_zero() {
        let a = Rect::new(0.0, 0.0, 2.0, 2.0);
        let b = Rect::new(5.0, 5.0, 8.0, 8.0);
        assert_eq!(a.compute_area_intersection(&b), 0.0);
    }

    #[test]
    fn union_bounds_merges_extents() {
        let a = Rect::new(0.0, 0.0, 3.0, 3.0);
        let b = Rect::new(1.0, 1.0, 5.0, 4.0);
        assert_eq!(a.union_bounds(&b), Rect::new(0.0, 0.0, 5.0, 4.0));
    }

    #[test]
    fn union_iterable_empty_returns_none() {
        let shapes: Vec<Rect> = vec![];
        assert!(union_iterable(shapes).is_none());
    }

    #[test]
    fn union_iterable_single_returns_that_shape() {
        let r = Rect::new(1.0, 2.0, 3.0, 4.0);
        assert_eq!(union_iterable(vec![r.clone()]), Some(r));
    }

    #[test]
    fn union_iterable_multiple_returns_enclosing_rect() {
        let shapes = vec![
            Rect::new(0.0, 0.0, 2.0, 2.0),
            Rect::new(3.0, 3.0, 5.0, 5.0),
            Rect::new(1.0, 0.0, 4.0, 3.0),
        ];
        assert_eq!(union_iterable(shapes), Some(Rect::new(0.0, 0.0, 5.0, 5.0)));
    }
}
