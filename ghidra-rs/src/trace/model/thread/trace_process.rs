use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::iface::TraceObjectInterface;

/// The object attribute key holding the process id.
///
/// Mirrors `ghidra.trace.model.thread.TraceProcess.KEY_PID`.
pub const KEY_PID: &str = "_pid";

/// A marker interface which indicates a process, usually on a host operating system.
///
/// Port of `ghidra.trace.model.thread.TraceProcess`.
///
/// If this object does not support
/// [`TraceExecutionStateful`](crate::trace::model::target::iface::trace_execution_stateful::TraceExecutionStateful),
/// then its mere existence in the model implies that it is
/// [`TraceExecutionState::Alive`](crate::trace::model::trace_execution_state::TraceExecutionState).
/// TODO: Should allow association via convention to a different `TraceExecutionStateful`, but
/// that may have to wait until schemas are introduced.
pub trait TraceProcess: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceProcess`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Process", "process", [KEY_PID], [] as [&str; 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProcess;

    impl TraceObjectInterface for MockProcess {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }
    impl TraceProcess for MockProcess {}

    fn as_dyn(p: &MockProcess) -> &dyn TraceProcess {
        p
    }

    #[test]
    fn is_object_safe() {
        let process = MockProcess;
        let _dyn_ref = as_dyn(&process);
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockProcess as TraceProcess>::trace_object_info();
        assert_eq!(info.schema_name, "Process");
        assert_eq!(info.short_name, "process");
        assert_eq!(info.attributes, vec![KEY_PID.to_string()]);
        assert!(info.fixed_keys.is_empty());
    }
}
