//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use crate::program::model::data::data_type_manager::DataTypeManager;

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

/// Placeholder for `ghidra.trace.model.program.TraceProgramView`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceProgramView {}

/// Placeholder for `ghidra.trace.model.program.TraceVariableSnapProgramView`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends TraceProgramView`.
pub trait TraceVariableSnapProgramView: TraceProgramView {}

/// Placeholder for `ghidra.trace.model.TraceTimeViewport`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceTimeViewport {}
