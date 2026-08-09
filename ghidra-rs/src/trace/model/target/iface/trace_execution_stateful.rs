use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use super::TraceObjectInterface;

/// The object attribute key holding the execution state.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceExecutionStateful.KEY_STATE`.
pub const KEY_STATE: &str = "_state";

/// An object with an execution state, e.g., a thread or process.
///
/// Mirrors `ghidra.trace.model.target.iface.TraceExecutionStateful`.
pub trait TraceExecutionStateful: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceExecutionStateful`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("ExecutionStateful", "exec stateful", [KEY_STATE], [] as [&str; 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExecutionStateful;

    impl TraceObjectInterface for MockExecutionStateful {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }
    impl TraceExecutionStateful for MockExecutionStateful {}

    fn as_dyn(e: &MockExecutionStateful) -> &dyn TraceExecutionStateful {
        e
    }

    #[test]
    fn is_object_safe() {
        let stateful = MockExecutionStateful;
        let _dyn_ref = as_dyn(&stateful);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockExecutionStateful as TraceExecutionStateful>::trace_object_info();
        assert_eq!(info.schema_name, "ExecutionStateful");
        assert_eq!(info.short_name, "exec stateful");
        assert_eq!(info.attributes, vec![KEY_STATE.to_string()]);
        assert!(info.fixed_keys.is_empty());
    }
}
