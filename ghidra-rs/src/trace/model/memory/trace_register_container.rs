use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::seam_stubs::TraceObjectInterface;

/// A container of registers.
///
/// Mirrors `ghidra.trace.model.memory.TraceRegisterContainer`.
///
/// NOTE: This is a special case of "container", since it need not be the immediate parent of the
/// registers it contains. Thus, this cannot be supplanted by a canonical-container search over
/// the object schema.
pub trait TraceRegisterContainer: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceRegisterContainer`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "RegisterContainer",
            "register container",
            [] as [&str; 0],
            [] as [&str; 0],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRegisterContainer;

    impl TraceObjectInterface for MockRegisterContainer {}
    impl TraceRegisterContainer for MockRegisterContainer {}

    fn as_dyn(c: &MockRegisterContainer) -> &dyn TraceRegisterContainer {
        c
    }

    #[test]
    fn is_object_safe() {
        let container = MockRegisterContainer;
        let _dyn_ref = as_dyn(&container);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = MockRegisterContainer::trace_object_info();
        assert_eq!(info.schema_name, "RegisterContainer");
        assert_eq!(info.short_name, "register container");
        assert!(info.attributes.is_empty());
        assert!(info.fixed_keys.is_empty());
    }
}
