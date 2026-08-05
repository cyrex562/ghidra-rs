//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::trace::model::program::TraceProgramView;

/// Placeholder for `ghidra.trace.model.property.TraceAddressPropertyManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceAddressPropertyManager {}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBookmarkManager {}

/// Placeholder for `ghidra.trace.model.breakpoint.TraceBreakpointManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBreakpointManager {}

/// Placeholder for `ghidra.trace.model.listing.TraceCodeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceCodeManager {}

/// Placeholder for `ghidra.trace.model.data.TraceBasedDataTypeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends ProgramBasedDataTypeManager` (itself a `DataTypeManager`) so that
/// the placeholder stays substitutable for [`DataTypeManager`].
pub trait TraceBasedDataTypeManager: DataTypeManager {}

/// Placeholder for `ghidra.trace.model.symbol.TraceEquateManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceEquateManager {}

/// Placeholder for `ghidra.trace.model.guest.TracePlatformManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TracePlatformManager {}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceMemoryManager {}

/// Placeholder for `ghidra.trace.model.modules.TraceModuleManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceModuleManager {}

/// Placeholder for `ghidra.trace.model.target.TraceObjectManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceObjectManager {}

/// Placeholder for `ghidra.trace.model.symbol.TraceReferenceManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceReferenceManager {}

/// Placeholder for `ghidra.trace.model.context.TraceRegisterContextManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceRegisterContextManager {}

/// Placeholder for `ghidra.trace.model.stack.TraceStackManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceStackManager {}

/// Placeholder for `ghidra.trace.model.modules.TraceStaticMappingManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceStaticMappingManager {}

/// Placeholder for `ghidra.trace.model.symbol.TraceSymbolManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceSymbolManager {}

/// Placeholder for `ghidra.trace.model.thread.TraceThreadManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceThreadManager {}

/// Placeholder for `ghidra.trace.model.time.TraceTimeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceTimeManager {}

/// Placeholder for `ghidra.trace.model.program.TraceVariableSnapProgramView`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends TraceProgramView`, now that
/// [`TraceProgramView`](crate::trace::model::program::TraceProgramView) has a real port.
pub trait TraceVariableSnapProgramView: TraceProgramView {}

/// Placeholder for `ghidra.trace.model.TraceAddressSnapSpace`, referenced by
/// [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range::ImmutableTraceAddressSnapRange)
/// before the real (concrete, cached-singleton) implementation is ported. Only the method that
/// type needs: obtaining the canonical space for a given address space.
pub trait TraceAddressSnapSpace: Send + Sync {
    fn for_address_space(space: &std::sync::Arc<crate::program::model::address::AddressSpace>) -> Box<dyn TraceAddressSnapSpace>
    where
        Self: Sized;
}

/// Placeholder for `ghidra.util.database.ObjectKey`, referenced by
/// [`TraceUniqueObject`](crate::trace::model::trace_unique_object::TraceUniqueObject) before the
/// real port is available. Mirrors the Java type's identity contract: an immutable-hash opaque id
/// that is equatable and orderable against other keys.
pub trait ObjectKey: Send + Sync {
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
    fn hash_code(&self) -> i32;
    fn compare_to(&self, that: &dyn ObjectKey) -> i32;
}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkType`, referenced by
/// [`TraceBookmark`](crate::trace::model::bookmark::trace_bookmark::TraceBookmark) before the
/// real port is available. No members are parsed from the Java source yet.
pub trait TraceBookmarkType: Send + Sync {}

/// Placeholder for `ghidra.trace.model.target.iface.TraceObjectInterface`, referenced by
/// [`TraceRegisterContainer`](crate::trace::model::memory::trace_register_container::TraceRegisterContainer)
/// (and other `Trace*` marker interfaces) before the real port is available. No members are
/// parsed from the Java source yet.
pub trait TraceObjectInterface: Send + Sync {}
