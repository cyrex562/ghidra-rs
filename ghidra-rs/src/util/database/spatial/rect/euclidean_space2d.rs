use std::cmp::Ordering;

/// A 2D Euclidean-like metric space over generic X and Y coordinate types.
///
/// Corresponds to `ghidra.util.database.spatial.rect.EuclideanSpace2D`.
///
/// Implementors supply coordinate ordering, distance, and midpoint operations.
/// The default methods for `min_x`, `max_x`, `min_y`, and `max_y` are derived
/// from the ordering operations.
///
/// The associated type `Rect` represents the rectangle type returned by
/// [`get_full`](EuclideanSpace2D::get_full). It corresponds to the Java wildcard
/// `Rectangle2D<X, Y, ?>` and will be constrained to the `Rectangle2D` trait
/// when that type is ported.
pub trait EuclideanSpace2D {
    /// The type of X-axis coordinate values.
    type X;
    /// The type of Y-axis coordinate values.
    type Y;
    /// The rectangle type returned by [`get_full`](EuclideanSpace2D::get_full).
    type Rect;

    /// Compare two X coordinates.
    fn compare_x(&self, x1: &Self::X, x2: &Self::X) -> Ordering;

    /// Compare two Y coordinates.
    fn compare_y(&self, y1: &Self::Y, y2: &Self::Y) -> Ordering;

    /// Compute the distance between two X coordinates.
    fn dist_x(&self, x1: &Self::X, x2: &Self::X) -> f64;

    /// Compute the distance between two Y coordinates.
    fn dist_y(&self, y1: &Self::Y, y2: &Self::Y) -> f64;

    /// Return the midpoint X coordinate between `x1` and `x2`.
    fn mid_x(&self, x1: &Self::X, x2: &Self::X) -> Self::X;

    /// Return the midpoint Y coordinate between `y1` and `y2`.
    fn mid_y(&self, y1: &Self::Y, y2: &Self::Y) -> Self::Y;

    /// Return the lesser of two X coordinates.
    fn min_x<'a>(&self, x1: &'a Self::X, x2: &'a Self::X) -> &'a Self::X {
        if self.compare_x(x1, x2) == Ordering::Less {
            x1
        } else {
            x2
        }
    }

    /// Return the greater of two X coordinates.
    fn max_x<'a>(&self, x1: &'a Self::X, x2: &'a Self::X) -> &'a Self::X {
        if self.compare_x(x1, x2) == Ordering::Greater {
            x1
        } else {
            x2
        }
    }

    /// Return the lesser of two Y coordinates.
    fn min_y<'a>(&self, y1: &'a Self::Y, y2: &'a Self::Y) -> &'a Self::Y {
        if self.compare_y(y1, y2) == Ordering::Less {
            y1
        } else {
            y2
        }
    }

    /// Return the greater of two Y coordinates.
    fn max_y<'a>(&self, y1: &'a Self::Y, y2: &'a Self::Y) -> &'a Self::Y {
        if self.compare_y(y1, y2) == Ordering::Greater {
            y1
        } else {
            y2
        }
    }

    /// Return the rectangle covering the entire space.
    fn get_full(&self) -> Self::Rect;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal rectangle used only in tests: (x1, x2, y1, y2).
    #[derive(Debug, PartialEq)]
    struct FullRect(i32, i32, i32, i32);

    struct IntSpace;

    impl EuclideanSpace2D for IntSpace {
        type X = i32;
        type Y = i32;
        type Rect = FullRect;

        fn compare_x(&self, x1: &i32, x2: &i32) -> Ordering {
            x1.cmp(x2)
        }
        fn compare_y(&self, y1: &i32, y2: &i32) -> Ordering {
            y1.cmp(y2)
        }
        fn dist_x(&self, x1: &i32, x2: &i32) -> f64 {
            (x2 - x1).unsigned_abs() as f64
        }
        fn dist_y(&self, y1: &i32, y2: &i32) -> f64 {
            (y2 - y1).unsigned_abs() as f64
        }
        fn mid_x(&self, x1: &i32, x2: &i32) -> i32 {
            x1 + (x2 - x1) / 2
        }
        fn mid_y(&self, y1: &i32, y2: &i32) -> i32 {
            y1 + (y2 - y1) / 2
        }
        fn get_full(&self) -> FullRect {
            FullRect(i32::MIN, i32::MAX, i32::MIN, i32::MAX)
        }
    }

    // --- compare_x ---

    #[test]
    fn compare_x_less() {
        let s = IntSpace;
        assert_eq!(s.compare_x(&1, &2), Ordering::Less);
    }

    #[test]
    fn compare_x_equal() {
        let s = IntSpace;
        assert_eq!(s.compare_x(&5, &5), Ordering::Equal);
    }

    #[test]
    fn compare_x_greater() {
        let s = IntSpace;
        assert_eq!(s.compare_x(&3, &1), Ordering::Greater);
    }

    // --- compare_y ---

    #[test]
    fn compare_y_less() {
        let s = IntSpace;
        assert_eq!(s.compare_y(&-1, &0), Ordering::Less);
    }

    #[test]
    fn compare_y_greater() {
        let s = IntSpace;
        assert_eq!(s.compare_y(&10, &5), Ordering::Greater);
    }

    // --- dist_x / dist_y ---

    #[test]
    fn dist_x_positive_range() {
        let s = IntSpace;
        assert_eq!(s.dist_x(&3, &10), 7.0);
    }

    #[test]
    fn dist_x_same_point_is_zero() {
        let s = IntSpace;
        assert_eq!(s.dist_x(&5, &5), 0.0);
    }

    #[test]
    fn dist_y_positive_range() {
        let s = IntSpace;
        assert_eq!(s.dist_y(&0, &100), 100.0);
    }

    // --- mid_x / mid_y ---

    #[test]
    fn mid_x_even_range() {
        let s = IntSpace;
        assert_eq!(s.mid_x(&0, &10), 5);
    }

    #[test]
    fn mid_x_odd_range_truncates() {
        let s = IntSpace;
        assert_eq!(s.mid_x(&0, &9), 4);
    }

    #[test]
    fn mid_y_same_value() {
        let s = IntSpace;
        assert_eq!(s.mid_y(&7, &7), 7);
    }

    // --- min_x / max_x ---

    #[test]
    fn min_x_picks_smaller() {
        let s = IntSpace;
        assert_eq!(s.min_x(&3, &7), &3);
    }

    #[test]
    fn min_x_equal_picks_second() {
        let s = IntSpace;
        assert_eq!(s.min_x(&5, &5), &5);
    }

    #[test]
    fn max_x_picks_larger() {
        let s = IntSpace;
        assert_eq!(s.max_x(&3, &7), &7);
    }

    #[test]
    fn max_x_equal_picks_second() {
        let s = IntSpace;
        assert_eq!(s.max_x(&5, &5), &5);
    }

    // --- min_y / max_y ---

    #[test]
    fn min_y_picks_smaller() {
        let s = IntSpace;
        assert_eq!(s.min_y(&-10, &0), &-10);
    }

    #[test]
    fn max_y_picks_larger() {
        let s = IntSpace;
        assert_eq!(s.max_y(&-10, &0), &0);
    }

    // --- get_full ---

    #[test]
    fn get_full_spans_entire_space() {
        let s = IntSpace;
        let full = s.get_full();
        assert_eq!(full, FullRect(i32::MIN, i32::MAX, i32::MIN, i32::MAX));
    }
}
