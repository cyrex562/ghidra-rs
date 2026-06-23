pub mod bounded_shape;
pub mod bounding_shape;
pub mod query;
pub mod spatial_map;

pub use bounded_shape::BoundedShape;
pub use bounding_shape::{union_iterable, BoundingShape};
pub use query::{Query, QueryInclusion};
pub use spatial_map::{empty_map, EmptySpatialMap, SpatialMap};
