//! A location in a trace, specified by thread and address.
//!
//! Port of `ghidra.trace.model.TraceLocation`.
//!
//! Java's `TraceLocation extends Comparable<TraceLocation>` is not reflected in the trait
//! signature because `Comparable` (like `Ord` in Rust) uses `Self` parameters and is not
//! object-safe for `&dyn TraceLocation`. Implementors that need ordering should implement
//! `Ord`/`PartialOrd` separately.

use crate::program::model::address::Address;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::thread::trace_thread::TraceThread;
use crate::trace::model::trace::Trace;

/// A location in a trace, specified by a thread, address, and lifespan.
///
/// This is a core interface for specifying locations within a trace for debugging
/// and analysis operations. Port of `ghidra.trace.model.TraceLocation`.
pub trait TraceLocation: Send + Sync {
    /// Get the trace containing this location.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the thread at this location.
    fn get_thread(&self) -> Box<dyn TraceThread>;

    /// Get the lifespan (time range) of this location.
    fn get_lifespan(&self) -> Lifespan;

    /// Get the address of this location.
    fn get_address(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trait_object_dyn_compatible() {
        // Verify that TraceLocation can be used as a dyn trait object, which is the key
        // requirement for the placeholder replacement.
        fn needs_dyn_trait_location(_loc: &dyn TraceLocation) {}

        // The test passes if this compiles without errors. We don't instantiate a mock
        // because the trait is primarily used polymorphically in the app services, where
        // real implementations (like DBTraceLocation) will be provided.
    }
}
