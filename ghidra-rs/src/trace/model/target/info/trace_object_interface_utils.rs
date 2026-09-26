//! Partial port of `ghidra.trace.model.target.info.TraceObjectInterfaceUtils`: the by-name
//! lookup of trace object interfaces.
//!
//! Java builds its registry from every `TraceObjectInterfaceFactory` found by `ClassSearcher`,
//! falling back to `BuiltinTraceObjectInterfaceFactory`, the only factory in the tree. It maps
//! each interface's `@TraceObjectInfo.schemaName` to a constructor for the interface's
//! database-backed implementation. The database implementations are not ported, so this module
//! exposes the part schemas need -- schema name to the reified annotation -- over exactly the
//! builtin factory's interface list.
use std::sync::OnceLock;

use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;

const NONE: [&str; 0] = [];

/// The `@TraceObjectInfo` of every interface in `BuiltinTraceObjectInterfaceFactory.BUILTINS`,
/// in that list's order. The annotation values are copied from the Java interfaces.
pub fn builtin_interface_infos() -> &'static [TraceObjectInfo] {
    static INFOS: OnceLock<Vec<TraceObjectInfo>> = OnceLock::new();
    INFOS.get_or_init(|| {
        vec![
            TraceObjectInfo::new("Activatable", "activatable", NONE, NONE),
            TraceObjectInfo::new("Aggregate", "aggregate", NONE, NONE),
            TraceObjectInfo::new(
                "BreakpointLocation",
                "breakpoint location",
                ["_range", "_emu_enabled", "_emu_sleigh"],
                ["_range"],
            ),
            TraceObjectInfo::new(
                "BreakpointSpec",
                "breakpoint specification",
                ["_expression", "_kinds", "_bpt"],
                ["_display", "_expression", "_kinds"],
            ),
            TraceObjectInfo::new(
                "Environment",
                "environment",
                ["_arch", "_debugger", "_endian", "_os"],
                NONE,
            ),
            TraceObjectInfo::new(
                "EventScope",
                "event scope",
                ["_event_thread", "_time_support"],
                NONE,
            ),
            TraceObjectInfo::new("ExecutionStateful", "exec stateful", ["_state"], NONE),
            TraceObjectInfo::new("FocusScope", "focus scope", ["_focus"], NONE),
            TraceObjectInfo::new("Memory", "memory", NONE, NONE),
            TraceObjectInfo::new(
                "MemoryRegion",
                "region",
                ["_range", "_readable", "_writable", "_executable", "_volatile"],
                ["_display", "_range"],
            ),
            TraceObjectInfo::new("Method", "method", NONE, NONE),
            TraceObjectInfo::new(
                "Module",
                "module",
                ["_range", "_module_name"],
                ["_display", "_range"],
            ),
            TraceObjectInfo::new("Process", "process", ["_pid"], NONE),
            TraceObjectInfo::new("Register", "register", ["_length", "_state"], ["_length"]),
            TraceObjectInfo::new("RegisterContainer", "register container", NONE, NONE),
            TraceObjectInfo::new("Section", "section", ["_module", "_range"], ["_display", "_range"]),
            TraceObjectInfo::new("Stack", "stack", NONE, NONE),
            TraceObjectInfo::new("StackFrame", "frame", ["_pc", "_sp"], NONE),
            TraceObjectInfo::new("Thread", "thread", ["_tid"], ["_display", "_comment"]),
            TraceObjectInfo::new("Togglable", "togglable", ["_enabled"], NONE),
        ]
    })
}

/// The interface registered under `schema_name`, if any. Mirrors
/// `getConstructorsByName().get(schemaName)`, yielding the interface's annotation.
pub fn get_info_by_name(schema_name: &str) -> Option<&'static TraceObjectInfo> {
    builtin_interface_infos().iter().find(|i| i.schema_name == schema_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_cover_the_twenty_factory_interfaces() {
        assert_eq!(builtin_interface_infos().len(), 20);
        let mut names: Vec<&str> =
            builtin_interface_infos().iter().map(|i| i.schema_name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 20, "schema names must be unique");
    }

    #[test]
    fn lookup_by_schema_name() {
        let thread = get_info_by_name("Thread").unwrap();
        assert_eq!(thread.short_name, "thread");
        assert_eq!(thread.attributes, vec!["_tid"]);
        assert_eq!(thread.fixed_keys, vec!["_display", "_comment"]);
        // TraceObjectInterface itself is not a registered interface.
        assert!(get_info_by_name("OBJECT").is_none());
        assert!(get_info_by_name("Bogus").is_none());
    }
}
