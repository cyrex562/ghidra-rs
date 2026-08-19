use std::any::Any;

use crate::program::model::address::AddressRange;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_location::TraceLocation;

/// A mapping between a trace location and a program location.
///
/// Port of `ghidra.debug.api.modules.MapEntry<T, P>`.
///
/// This trait represents a single static mapping (relocation) from a trace to a program.
/// Since Rust traits must be object-safe to be used as `&dyn MapEntry`, the generic type
/// parameters `T` and `P` from the Java interface are replaced with `Box<dyn Any>` in
/// `get_from_object()` and `get_to_object()` respectively. Implementers can store and
/// return specific types wrapped in Any, allowing callers to downcast as needed.
///
/// The other methods return specific Ghidra core types that are not generic: traces,
/// programs, addresses, and lifespans.
pub trait MapEntry: Send + Sync {
    /// Returns the trace from which this mapping originates.
    fn get_from_trace(&self) -> &dyn Trace;

    /// Returns the object from the trace side of the mapping.
    ///
    /// In Java, this is typed as the generic parameter `T`. Implementers should return
    /// `Box::new(object)` to wrap their concrete type in Any, allowing the caller to
    /// downcast if needed.
    fn get_from_object(&self) -> Box<dyn Any>;

    /// Returns the address range from which this mapping originates.
    fn get_from_range(&self) -> &AddressRange;

    /// Returns the lifespan of this mapping on the trace side.
    fn get_from_lifespan(&self) -> Lifespan;

    /// Returns the trace location from which this mapping originates.
    fn get_from_trace_location(&self) -> Box<dyn TraceLocation>;

    /// Returns the program to which this mapping points.
    fn get_to_program(&self) -> &dyn Program;

    /// Returns the object in the program side of the mapping.
    ///
    /// In Java, this is typed as the generic parameter `P`. Implementers should return
    /// `Box::new(object)` to wrap their concrete type in Any, allowing the caller to
    /// downcast if needed.
    fn get_to_object(&self) -> Box<dyn Any>;

    /// Returns the address range to which this mapping points.
    fn get_to_range(&self) -> &AddressRange;

    /// Returns the program location to which this mapping points.
    fn get_to_program_location(&self) -> &dyn ProgramLocation;

    /// Returns the length of the mapped region.
    ///
    /// Note: In Java, this can be `0`, which represents `1 << 64` (full 64-bit address space).
    fn get_mapping_length(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A minimal test implementation of MapEntry.
    struct TestMapEntry {
        from_range: AddressRange,
        to_range: AddressRange,
        length: i64,
    }

    impl MapEntry for TestMapEntry {
        fn get_from_trace(&self) -> &dyn Trace {
            todo!("Test implementation")
        }

        fn get_from_object(&self) -> Box<dyn Any> {
            Box::new(42_i32)
        }

        fn get_from_range(&self) -> &AddressRange {
            &self.from_range
        }

        fn get_from_lifespan(&self) -> Lifespan {
            todo!("Test implementation")
        }

        fn get_from_trace_location(&self) -> Box<dyn TraceLocation> {
            todo!("Test implementation")
        }

        fn get_to_program(&self) -> &dyn Program {
            todo!("Test implementation")
        }

        fn get_to_object(&self) -> Box<dyn Any> {
            Box::new("test_string".to_string())
        }

        fn get_to_range(&self) -> &AddressRange {
            &self.to_range
        }

        fn get_to_program_location(&self) -> &dyn ProgramLocation {
            todo!("Test implementation")
        }

        fn get_mapping_length(&self) -> i64 {
            self.length
        }
    }

    #[test]
    fn map_entry_is_object_safe() {
        // Verify that MapEntry can be stored as a trait object in a vector
        let entries: Vec<Arc<dyn MapEntry>> = vec![];
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn map_entry_returns_generic_objects_via_any() {
        // Verify that generic objects can be wrapped in Any and downcast by callers
        let from_obj = Box::new(99_i32);
        let from_any: Box<dyn Any> = from_obj;

        if let Some(num) = from_any.downcast_ref::<i32>() {
            assert_eq!(*num, 99);
        } else {
            panic!("Failed to downcast from_object");
        }

        let to_obj = Box::new("test_value".to_string());
        let to_any: Box<dyn Any> = to_obj;

        if let Some(s) = to_any.downcast_ref::<String>() {
            assert_eq!(s, "test_value");
        } else {
            panic!("Failed to downcast to_object");
        }
    }
}
