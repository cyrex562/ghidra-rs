//! An exception indicating a proposed static mapping conflicts with existing ones.
//!
//! Port of `ghidra.trace.model.modules.TraceConflictedMappingException`.
//!
//! The Java class is a concrete `RuntimeException`, but it sits at a dependency-cycle
//! cut-point between [`TraceStaticMapping`] consumers (e.g.,
//! [`TraceStaticMappingManager`](crate::trace::model::modules::trace_static_mapping_manager::TraceStaticMappingManager)
//! and `DebuggerStaticMappingService`), so it is mapped to an object-safe trait here instead, with
//! [`TraceConflictedMappingError`] as a constructible implementor mirroring the Java constructor.

use std::fmt;

use crate::trace::model::modules::trace_static_mapping::TraceStaticMapping;

/// Indicates a new trace-to-program mapping conflicts with one or more existing mappings.
///
/// Port of `ghidra.trace.model.modules.TraceConflictedMappingException`. Extends
/// `std::error::Error` (plus `Send + Sync`) so it can stand in for the Java unchecked exception as
/// a boxed `Result` error.
pub trait TraceConflictedMappingException: std::error::Error + Send + Sync {
    /// Get the mappings that conflicted with the prospective mapping.
    ///
    /// Port of `TraceConflictedMappingException.getConflicts()`. The Java method returns the
    /// exception's immutable `Set` field directly rather than a copy; since
    /// [`TraceStaticMapping`] trait objects cannot cheaply be cloned or hashed into a `Set`, this
    /// returns a borrowed slice of the stored conflicts instead.
    fn get_conflicts(&self) -> &[Box<dyn TraceStaticMapping>];
}

/// A constructible implementor of [`TraceConflictedMappingException`].
///
/// Port of the Java class's `TraceConflictedMappingException(String message, Collection<TraceStaticMapping>
/// conflicts)` constructor, which formats the exception message as `message + ": " + conflicts`.
pub struct TraceConflictedMappingError {
    display: String,
    conflicts: Vec<Box<dyn TraceStaticMapping>>,
}

impl TraceConflictedMappingError {
    /// Constructs a new exception from `message` and the mappings that conflicted with the
    /// prospective mapping.
    pub fn new(message: impl Into<String>, conflicts: Vec<Box<dyn TraceStaticMapping>>) -> Self {
        let message = message.into();
        let urls: Vec<String> = conflicts
            .iter()
            .map(|conflict| conflict.get_static_program_url())
            .collect();
        let display = format!("{}: [{}]", message, urls.join(", "));
        Self { display, conflicts }
    }
}

impl fmt::Display for TraceConflictedMappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

impl fmt::Debug for TraceConflictedMappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceConflictedMappingError")
            .field("display", &self.display)
            .field("conflicts_len", &self.conflicts.len())
            .finish()
    }
}

impl std::error::Error for TraceConflictedMappingError {}

impl TraceConflictedMappingException for TraceConflictedMappingError {
    fn get_conflicts(&self) -> &[Box<dyn TraceStaticMapping>] {
        &self.conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Arc;

    struct MockObjectKey;

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some()
        }

        fn hash_code(&self) -> i32 {
            0
        }

        fn compare_to(&self, _that: &dyn ObjectKey) -> i32 {
            0
        }
    }



    struct MockMapping {
        to_program_url: String,
    }

    impl TraceUniqueObject for MockMapping {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey)
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceStaticMapping for MockMapping {
        fn get_trace(&self) -> Arc<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_trace_address_range(&self) -> AddressRange {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_min_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_max_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_length(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_shift(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn get_end_snap(&self) -> i64 {
            i64::MAX
        }

        fn get_static_program_url(&self) -> String {
            self.to_program_url.clone()
        }

        fn get_static_address(&self) -> String {
            "0x0".to_string()
        }

        fn delete(&mut self) {}

        fn conflicts_with(
            &self,
            _range: &AddressRange,
            _lifespan: Lifespan,
            _to_program_url: &str,
            _to_address: &str,
        ) -> bool {
            false
        }
    }

    #[test]
    fn new_formats_message_with_conflicts() {
        let conflicts: Vec<Box<dyn TraceStaticMapping>> = vec![Box::new(MockMapping {
            to_program_url: "ghidra://repo/a".to_string(),
        })];
        let err = TraceConflictedMappingError::new("overlaps existing mapping", conflicts);
        assert_eq!(
            err.to_string(),
            "overlaps existing mapping: [ghidra://repo/a]"
        );
        assert_eq!(err.get_conflicts().len(), 1);
        assert_eq!(err.get_conflicts()[0].get_static_program_url(), "ghidra://repo/a");
    }

    #[test]
    fn new_with_no_conflicts_formats_empty_list() {
        let err = TraceConflictedMappingError::new("no conflicts", Vec::new());
        assert_eq!(err.to_string(), "no conflicts: []");
        assert!(err.get_conflicts().is_empty());
    }

    #[test]
    fn trait_object_is_object_safe_and_is_error() {
        let err: Box<dyn TraceConflictedMappingException> = Box::new(
            TraceConflictedMappingError::new(
                "conflict",
                vec![Box::new(MockMapping {
                    to_program_url: "ghidra://repo/b".to_string(),
                }) as Box<dyn TraceStaticMapping>],
            ),
        );
        let as_error: &dyn std::error::Error = err.as_ref();
        assert_eq!(as_error.to_string(), "conflict: [ghidra://repo/b]");
        assert_eq!(err.get_conflicts().len(), 1);
    }
}
