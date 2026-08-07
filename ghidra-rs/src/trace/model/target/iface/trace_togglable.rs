use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::seam_stubs::TraceObjectInterface;

/// The object attribute key holding whether a togglable object is enabled.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceTogglable.KEY_ENABLED`.
pub const KEY_ENABLED: &str = "_enabled";

/// An object which can be toggled.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceTogglable`.
pub trait TraceTogglable: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceTogglable`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Togglable", "togglable", [KEY_ENABLED], [] as [&str; 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTogglable;

    impl TraceObjectInterface for MockTogglable {}
    impl TraceTogglable for MockTogglable {}

    fn as_dyn(t: &MockTogglable) -> &dyn TraceTogglable {
        t
    }

    #[test]
    fn is_object_safe() {
        let togglable = MockTogglable;
        let _dyn_ref = as_dyn(&togglable);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = MockTogglable::trace_object_info();
        assert_eq!(info.schema_name, "Togglable");
        assert_eq!(info.short_name, "togglable");
        assert_eq!(info.attributes, vec![KEY_ENABLED.to_string()]);
        assert!(info.fixed_keys.is_empty());
    }
}
