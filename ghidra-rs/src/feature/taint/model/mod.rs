//! The Taint domain model.
//!
//! This module implements the domain of taint analysis. [`TaintVec`] models an array of bytes,
//! each having a [`TaintSet`]. A [`TaintSet`] is in turn made of several [`TaintMark`]s. Each
//! mark is a symbol with optional tags. Tags handle indirection so that tainted offsets taint
//! values read/written from memory without committing up front — the marks carry tags that can
//! be examined or filtered by the user.
//!
//! Serialization uses `Display`/`FromStr` rather than Java's object serialization.
//!
//! Recommended reading order (bottom-up): [`TaintMark`], [`TaintSet`].

pub mod taint_mark;
pub use taint_mark::TaintMark;

pub mod taint_set;
pub use taint_set::TaintSet;

#[cfg(test)]
mod tests {
    #[test]
    fn module_exists() {
        // Package-info port: verifies the taint model module is wired into the crate.
    }
}
