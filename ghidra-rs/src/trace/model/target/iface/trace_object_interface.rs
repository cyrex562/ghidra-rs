use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::trace_object::TraceObject;

/// The object attribute key for displaying the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_DISPLAY`.
pub const KEY_DISPLAY: &str = "_display";

/// The object attribute key for the short display of the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_SHORT_DISPLAY`.
pub const KEY_SHORT_DISPLAY: &str = "_short_display";

/// The object attribute key for the kind of the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_KIND`.
pub const KEY_KIND: &str = "_kind";

/// The object attribute key for the order of the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_ORDER`.
pub const KEY_ORDER: &str = "_order";

/// The object attribute key indicating the object has been modified.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_MODIFIED`.
pub const KEY_MODIFIED: &str = "_modified";

/// The object attribute key for the type of the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_TYPE`.
pub const KEY_TYPE: &str = "_type";

/// The object attribute key for the value of the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_VALUE`.
pub const KEY_VALUE: &str = "_value";

/// The object attribute key for the comment on the object.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface.KEY_COMMENT`.
pub const KEY_COMMENT: &str = "_comment";

/// A common interface for object-based implementations of other trace manager entries, e.g.,
/// `TraceThread`.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceObjectInterface`.
pub trait TraceObjectInterface: Send + Sync {
    /// Get the object backing this implementation.
    ///
    /// Mirrors `TraceObjectInterface.getObject()`.
    fn get_object(&self) -> Box<dyn TraceObject>;

    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceObjectInterface`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "OBJECT",
            "object",
            [KEY_DISPLAY, KEY_COMMENT],
            [] as [&str; 0],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTraceObjectInterface;

    impl TraceObjectInterface for MockTraceObjectInterface {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("mock")
        }
    }

    fn as_dyn(obj: &MockTraceObjectInterface) -> &dyn TraceObjectInterface {
        obj
    }

    #[test]
    fn is_object_safe() {
        let obj = MockTraceObjectInterface;
        let _dyn_ref = as_dyn(&obj);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = MockTraceObjectInterface::trace_object_info();
        assert_eq!(info.schema_name, "OBJECT");
        assert_eq!(info.short_name, "object");
        assert_eq!(info.attributes, vec![KEY_DISPLAY.to_string(), KEY_COMMENT.to_string()]);
        assert!(info.fixed_keys.is_empty());
    }

    #[test]
    fn constants_match_expected_values() {
        assert_eq!(KEY_DISPLAY, "_display");
        assert_eq!(KEY_SHORT_DISPLAY, "_short_display");
        assert_eq!(KEY_KIND, "_kind");
        assert_eq!(KEY_ORDER, "_order");
        assert_eq!(KEY_MODIFIED, "_modified");
        assert_eq!(KEY_TYPE, "_type");
        assert_eq!(KEY_VALUE, "_value");
        assert_eq!(KEY_COMMENT, "_comment");
    }
}
