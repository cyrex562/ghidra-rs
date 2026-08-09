use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use super::TraceObjectInterface;

/// A marker interface which indicates its attributes represent the object as a whole.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceAggregate`.
///
/// Often applied to processes and sessions, this causes ancestry traversals to include this
/// object's children when visited.
///
/// LATER (GP-5754): This should be an attribute of the schema, not an interface.
pub trait TraceAggregate: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceAggregate`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Aggregate", "aggregate", [] as [&str; 0], [] as [&str; 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAggregate;

    impl TraceObjectInterface for MockAggregate {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }
    impl TraceAggregate for MockAggregate {}

    fn as_dyn(a: &MockAggregate) -> &dyn TraceAggregate {
        a
    }

    #[test]
    fn is_object_safe() {
        let aggregate = MockAggregate;
        let _dyn_ref = as_dyn(&aggregate);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockAggregate as TraceAggregate>::trace_object_info();
        assert_eq!(info.schema_name, "Aggregate");
        assert_eq!(info.short_name, "aggregate");
        assert!(info.attributes.is_empty());
        assert!(info.fixed_keys.is_empty());
    }
}
