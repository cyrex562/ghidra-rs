pub mod constructor_impl;
pub mod context_commit;
pub mod context_op;

pub use constructor_impl::Constructor;
pub use context_commit::ContextCommit;
pub use context_op::ContextOp;

#[derive(Debug, Clone)]
pub enum ContextChange {
    Op(ContextOp),
    Commit(ContextCommit),
}
