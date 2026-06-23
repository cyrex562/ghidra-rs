pub mod bounded_shape;
pub mod bounding_shape;
pub mod hyper;
pub mod query;
pub mod rect;
pub mod spatial_map;

pub use bounded_shape::BoundedShape;
pub use bounding_shape::{union_iterable, BoundingShape};
pub use hyper::HyperDirection;
pub use query::{Query, QueryInclusion};
pub use spatial_map::{empty_map, EmptySpatialMap, SpatialMap};
