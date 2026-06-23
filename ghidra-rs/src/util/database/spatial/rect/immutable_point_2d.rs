use std::fmt;

use super::euclidean_space2d::EuclideanSpace2D;
use super::point2d::Point2D;

/// An immutable 2D point that carries its own coordinate-space reference.
///
/// Corresponds to `ghidra.util.database.spatial.rect.ImmutablePoint2D`.
pub struct ImmutablePoint2D<S: EuclideanSpace2D> {
    x: S::X,
    y: S::Y,
    space: S,
}

impl<S: EuclideanSpace2D> ImmutablePoint2D<S> {
    pub fn new(x: S::X, y: S::Y, space: S) -> Self {
        Self { x, y, space }
    }
}

impl<S> fmt::Display for ImmutablePoint2D<S>
where
    S: EuclideanSpace2D,
    S::X: fmt::Display,
    S::Y: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p({},{})", self.x, self.y)
    }
}

impl<S: EuclideanSpace2D> Point2D for ImmutablePoint2D<S> {
    type X = S::X;
    type Y = S::Y;
    type Space = S;

    fn get_x(&self) -> &Self::X {
        &self.x
    }

    fn get_y(&self) -> &Self::Y {
        &self.y
    }

    fn get_space(&self) -> &Self::Space {
        &self.space
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::*;

    struct FullRect;

    struct IntSpace;

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

    fn make(x: i64, y: i64) -> ImmutablePoint2D<IntSpace> {
        ImmutablePoint2D::new(x, y, IntSpace)
    }

    #[test]
    fn get_x_returns_stored_value() {
        let p = make(3, 7);
        assert_eq!(p.get_x(), &3);
    }

    #[test]
    fn get_y_returns_stored_value() {
        let p = make(3, 7);
        assert_eq!(p.get_y(), &7);
    }

    #[test]
    fn display_formats_as_p_x_y() {
        let p = make(4, 9);
        assert_eq!(p.to_string(), "p(4,9)");
    }

    #[test]
    fn display_negative_coords() {
        let p = make(-1, -2);
        assert_eq!(p.to_string(), "p(-1,-2)");
    }

    #[test]
    fn compute_distance_same_point_is_zero() {
        let p = make(5, 5);
        assert_eq!(p.compute_distance(&make(5, 5)), 0.0);
    }

    #[test]
    fn compute_distance_axis_aligned_x() {
        // dist = (3-0)^2 + (0-0)^2 = 9
        let a = make(0, 0);
        let b = make(3, 0);
        assert_eq!(a.compute_distance(&b), 9.0);
    }

    #[test]
    fn compute_distance_axis_aligned_y() {
        // dist = (0-0)^2 + (4-0)^2 = 16
        let a = make(0, 0);
        let b = make(0, 4);
        assert_eq!(a.compute_distance(&b), 16.0);
    }

    #[test]
    fn compute_distance_diagonal() {
        // dist = (3-0)^2 + (4-0)^2 = 9 + 16 = 25
        let a = make(0, 0);
        let b = make(3, 4);
        assert_eq!(a.compute_distance(&b), 25.0);
    }
}
