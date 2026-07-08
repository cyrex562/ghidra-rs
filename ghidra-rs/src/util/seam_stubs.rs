//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.util.task.Task`, needed by [`crate::util::TrackedTaskListener`].
pub trait Task: Send + Sync {}
