pub mod bounded_shape;
pub mod bounding_shape;
pub mod query;

pub use bounded_shape::BoundedShape;
pub use bounding_shape::{union_iterable, BoundingShape};
pub use query::{Query, QueryInclusion};
