pub mod euclidean_space2d;
pub mod immutable_point_2d;
pub mod immutable_rectangle2d;
pub mod point2d;
pub mod rectangle2d;

pub use euclidean_space2d::EuclideanSpace2D;
pub use immutable_point_2d::ImmutablePoint2D;
pub use immutable_rectangle2d::ImmutableRectangle2D;
pub use point2d::Point2D;
pub use rectangle2d::{encloses, Rectangle2D};
