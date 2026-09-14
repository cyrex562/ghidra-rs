pub mod tree_traversal;

pub mod all_paths_visitor;
pub mod ancestors_relative_visitor;
pub mod ancestors_root_visitor;
pub mod canonical_successors_relative_visitor;
pub mod ordered_successors_visitor;
pub mod successors_relative_visitor;

#[cfg(test)]
pub(crate) mod fixtures;

pub use tree_traversal::{SpanIntersectingVisitor, TreeTraversal, VisitResult, Visitor};

pub use all_paths_visitor::AllPathsVisitor;
pub use ancestors_relative_visitor::AncestorsRelativeVisitor;
pub use ancestors_root_visitor::AncestorsRootVisitor;
pub use canonical_successors_relative_visitor::CanonicalSuccessorsRelativeVisitor;
pub use ordered_successors_visitor::OrderedSuccessorsVisitor;
pub use successors_relative_visitor::SuccessorsRelativeVisitor;
