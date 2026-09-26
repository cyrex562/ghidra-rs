use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::iface::TraceObjectInterface;

/// The memory model of a target object.
///
/// Mirrors `ghidra.trace.model.memory.TraceMemory`.
///
/// The convention for modeling valid addresses is to have children supporting
/// [`TraceMemoryRegion`](crate::trace::model::memory::trace_memory_region::TraceMemoryRegion). If
/// no such children exist, then the client should assume no address is valid. Thus, for the
/// client to confidently access any memory, at least one child region must exist. It may present
/// the memory's entire address space in a single region.
pub trait TraceMemory: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceMemory`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Memory", "memory", [] as [&str; 0], [] as [&str; 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMemory;

    impl TraceObjectInterface for MockMemory {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }
    impl TraceMemory for MockMemory {}

    fn as_dyn(m: &MockMemory) -> &dyn TraceMemory {
        m
    }

    #[test]
    fn is_object_safe() {
        let memory = MockMemory;
        let _dyn_ref = as_dyn(&memory);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockMemory as TraceMemory>::trace_object_info();
        assert_eq!(info.schema_name, "Memory");
        assert_eq!(info.short_name, "memory");
        assert!(info.attributes.is_empty());
        assert!(info.fixed_keys.is_empty());
    }
}
