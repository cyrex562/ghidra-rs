use super::euclidean_space2d::EuclideanSpace2D;

/// A point in a 2D Euclidean-like space.
///
/// Corresponds to `ghidra.util.database.spatial.rect.Point2D`.
pub trait Point2D {
    /// The type of the X-axis coordinate.
    type X;
    /// The type of the Y-axis coordinate.
    type Y;
    /// The coordinate space this point lives in.
    type Space: EuclideanSpace2D<X = Self::X, Y = Self::Y>;

    fn get_x(&self) -> &Self::X;
    fn get_y(&self) -> &Self::Y;
    fn get_space(&self) -> &Self::Space;

    /// Returns the squared Euclidean distance to `point`.
    ///
    /// The square root is omitted because it is unnecessary for ordering.
    /// Corresponds to `Point2D.computeDistance`.
    fn compute_distance<P>(&self, point: &P) -> f64
    where
        P: Point2D<X = Self::X, Y = Self::Y>,
    {
        let dist_x = self.get_space().dist_x(self.get_x(), point.get_x());
        let dist_y = self.get_space().dist_y(self.get_y(), point.get_y());
        dist_x * dist_x + dist_y * dist_y
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    struct Rect;

    struct IntSpace;

    impl EuclideanSpace2D for IntSpace {
        type X = i64;
        type Y = i64;
        type Rect = Rect;

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
        fn get_full(&self) -> Rect {
            Rect
        }
    }

    struct Pt {
        x: i64,
        y: i64,
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
            &IntSpace
        }
    }

    fn pt(x: i64, y: i64) -> Pt {
        Pt { x, y }
    }

    #[test]
    fn get_x_returns_stored_value() {
        assert_eq!(pt(3, 7).get_x(), &3);
    }

    #[test]
    fn get_y_returns_stored_value() {
        assert_eq!(pt(3, 7).get_y(), &7);
    }

    #[test]
    fn compute_distance_same_point_is_zero() {
        assert_eq!(pt(5, 5).compute_distance(&pt(5, 5)), 0.0);
    }

    #[test]
    fn compute_distance_x_only() {
        // (3-0)^2 + (0-0)^2 = 9
        assert_eq!(pt(0, 0).compute_distance(&pt(3, 0)), 9.0);
    }

    #[test]
    fn compute_distance_y_only() {
        // (0-0)^2 + (4-0)^2 = 16
        assert_eq!(pt(0, 0).compute_distance(&pt(0, 4)), 16.0);
    }

    #[test]
    fn compute_distance_diagonal_3_4_5() {
        // (3-0)^2 + (4-0)^2 = 9 + 16 = 25
        assert_eq!(pt(0, 0).compute_distance(&pt(3, 4)), 25.0);
    }

    #[test]
    fn compute_distance_is_commutative() {
        let a = pt(1, 2);
        let b = pt(4, 6);
        assert_eq!(a.compute_distance(&b), b.compute_distance(&a));
    }

    #[test]
    fn compute_distance_negative_coords() {
        // dist_x = |-3 - 3| = 6, dist_y = |-4 - 4| = 8 → 36 + 64 = 100
        assert_eq!(pt(3, 4).compute_distance(&pt(-3, -4)), 100.0);
    }
}
