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
