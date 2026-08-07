//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use std::sync::Arc;

use crate::debug::api::tracermi::SchemaName;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::symbol::Symbol;
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::trace::Trace;

/// Placeholder for `ghidra.trace.model.property.TraceAddressPropertyManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceAddressPropertyManager {}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBookmarkManager {}

/// Placeholder for `ghidra.trace.model.breakpoint.TraceBreakpointManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBreakpointManager {}

/// Placeholder for `ghidra.trace.model.data.TraceBasedDataTypeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends ProgramBasedDataTypeManager` (itself a `DataTypeManager`) so that
/// the placeholder stays substitutable for [`DataTypeManager`].
pub trait TraceBasedDataTypeManager: DataTypeManager {}

/// Placeholder for `ghidra.trace.model.symbol.TraceEquateManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceEquateManager {}

/// Placeholder for `ghidra.trace.model.guest.TracePlatformManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Grown to add
/// the lookup
/// [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView)'s
/// default `getForRegister(long, Register)`/`getContaining(long, Register)`/`get(long, Register,
/// boolean)` methods need: the host platform, used when no explicit platform is given.
pub trait TracePlatformManager {
    /// Returns the trace's host (base) platform. Mirrors `TracePlatformManager.getHostPlatform()`.
    fn get_host_platform(&self) -> Box<dyn TracePlatform>;
}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceMemoryManager {}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryOperations`, referenced by
/// [`TraceMemorySpace`](crate::trace::model::memory::trace_memory_space::TraceMemorySpace) before
/// the real interface is ported. `TraceMemorySpace` only extends this interface as a supertrait
/// and does not itself call any of its (large) surface of byte/state/register operations, so no
/// members are ported here yet.
pub trait TraceMemoryOperations: Send + Sync {}

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

/// Placeholder for `ghidra.trace.model.symbol.TraceSymbolManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Grown to add
/// the lookup
/// [`TraceReference`](crate::trace::model::symbol::trace_reference::TraceReference)'s default
/// `get_associated_symbol()` needs. The real Java default resolves this via the manager's full
/// symbol table (`SymbolTable.getSymbolByID(long)`), not yet ported, so this placeholder always
/// reports no symbol found until that machinery exists.
pub trait TraceSymbolManager {
    /// Looks up a symbol by its ID. Mirrors `SymbolTable.getSymbolByID(long)`.
    fn get_symbol_by_id(&self, _id: i64) -> Option<Arc<dyn Symbol>> {
        None
    }
}

/// Placeholder for `ghidra.trace.model.thread.TraceThreadManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceThreadManager {}

/// Placeholder for `ghidra.trace.model.time.TraceSnapshot`, referenced by
/// [`TraceTimeManager`](crate::trace::model::time::trace_time_manager::TraceTimeManager) before
/// the real port is available. Mirrors the one member referenced in that interface's javadoc:
/// whether a snapshot is a fork point.
pub trait TraceSnapshot: Send + Sync {
    /// Mirrors `TraceSnapshot.isFork()`.
    fn is_fork(&self) -> bool;
}

/// Placeholder for `ghidra.trace.model.time.schedule.TraceSchedule`, referenced by
/// [`TraceTimeManager`](crate::trace::model::time::trace_time_manager::TraceTimeManager) before
/// the real port is available. `TraceTimeManager` only ever passes these around opaquely (as a
/// lookup/creation key), never inspecting them, so this is a marker trait.
pub trait TraceSchedule: Send + Sync {}

/// Placeholder for the nested enum `ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix`,
/// referenced by
/// [`TraceTimeManager`](crate::trace::model::time::trace_time_manager::TraceTimeManager) before
/// the real port is available. Mirrors the one member needed to make a round-trip
/// `set_time_radix`/`get_time_radix` observable: the radix's numeric value (Java's
/// `TimeRadix.getRadix()`).
pub trait TimeRadix: Send + Sync {
    /// Mirrors `TimeRadix.getRadix()`.
    fn radix(&self) -> i32;
}

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

/// Placeholder for `ghidra.trace.model.memory.TraceOverlappedRegionException`, referenced by
/// [`TraceMemoryRegion`](crate::trace::model::memory::trace_memory_region::TraceMemoryRegion)
/// before the real port is available. Mirrors the two members
/// [`TraceMemoryRegion`]'s setters need: the detail message (inherited from Java's
/// `UsrException.getMessage()`) and the conflicting regions.
pub trait TraceOverlappedRegionException: Send + Sync {
    /// Mirrors `UsrException.getMessage()`, as inherited by `TraceOverlappedRegionException`.
    fn message(&self) -> &str;

    /// Mirrors `TraceOverlappedRegionException.getConflicts()`.
    fn get_conflicts(
        &self,
    ) -> Vec<Box<dyn crate::trace::model::memory::trace_memory_region::TraceMemoryRegion>>;
}

/// Placeholder for `ghidra.trace.model.target.schema.TraceObjectSchema`, referenced by
/// [`SchemaContext`](crate::trace::model::target::schema::schema_context::SchemaContext) and
/// [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
/// before the real port is available. Grown beyond an opaque marker to add the two members
/// `DefaultSchemaContext` needs: the name a schema is keyed by in a context, and its
/// `toString()` representation.
pub trait TraceObjectSchema: Send + Sync {
    /// The name this schema is registered under. Mirrors `TraceObjectSchema.getName()`.
    fn get_name(&self) -> SchemaName;

    /// Mirrors `TraceObjectSchema.toString()`.
    fn to_string(&self) -> String;

    /// Checks whether the given attribute key is hidden by this schema. Mirrors
    /// `TraceObjectSchema.isHidden(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `isHidden()`.
    ///
    /// The real Java default resolves this via a per-schema `Hidden` predicate not yet ported, so
    /// this placeholder defaults to "never hidden" until that machinery exists.
    fn is_hidden(&self, _name: &str) -> bool {
        false
    }

    /// Resolves an attribute name (or one of its aliases) to its canonical key. Mirrors
    /// `TraceObjectSchema.checkAliasedAttribute(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `hasEntryKey()`.
    ///
    /// The real Java default resolves this via an attribute-alias map not yet ported, so this
    /// placeholder defaults to identity (no aliasing).
    fn check_aliased_attribute(&self, name: &str) -> String {
        name.to_string()
    }

    /// Resolves the schema for a given child key (attribute or element). Mirrors
    /// `TraceObjectSchema.getChildSchema(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `getTargetSchema()`.
    ///
    /// The real Java default resolves this via the element/attribute schema maps not yet ported,
    /// so this placeholder defaults to the "ANY" primitive schema, mirroring
    /// `SchemaContext::get_schema`'s documented fallback for unresolved names.
    fn get_child_schema(&self, _key: &str) -> Box<dyn TraceObjectSchema> {
        struct FallbackAnySchema;
        impl TraceObjectSchema for FallbackAnySchema {
            fn get_name(&self) -> SchemaName {
                SchemaName::new("ANY")
            }

            fn to_string(&self) -> String {
                "ANY".to_string()
            }
        }
        Box::new(FallbackAnySchema)
    }
}

/// Placeholder for the nested `ghidra.trace.model.Lifespan.LifeSet`, referenced by
/// [`TraceObject`] before the real port is available. Mirrors the one member
/// `DBTraceObjectInterface`'s default `isDeleted()` needs: whether the set of lifespans is empty.
pub trait LifeSet: Send + Sync {
    /// Mirrors `Span.SpanSet.isEmpty()`, as inherited by `LifeSet`.
    fn is_empty(&self) -> bool;
}

/// Placeholder for `ghidra.trace.model.target.TraceObject`, referenced by
/// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue) and
/// [`DBTraceObjectInterface`](crate::trace::database::target::db_trace_object_interface::DBTraceObjectInterface)
/// before the real port is available. Grown beyond the schema lookup `TraceObjectValue`'s
/// defaults need to add the two members `DBTraceObjectInterface`'s defaults need: the object's
/// key and life. In the real Java hierarchy both are inherited from `TraceUniqueObject` (which
/// `TraceObject` extends); they're declared directly here instead of via that supertrait to avoid
/// requiring every existing placeholder implementor of this trait to also implement
/// `TraceUniqueObject`.
pub trait TraceObject: Send + Sync {
    /// Mirrors `TraceObject.getSchema()`.
    fn get_schema(&self) -> Box<dyn TraceObjectSchema>;

    /// Mirrors `TraceUniqueObject.getObjectKey()`, as inherited by `TraceObject`.
    fn get_object_key(&self) -> Box<dyn ObjectKey>;

    /// Mirrors `TraceObject.getLife()`.
    fn get_life(&self) -> Box<dyn LifeSet>;
}

/// Placeholder for the nested enum `ghidra.trace.model.target.TraceObject.ConflictResolution`,
/// referenced by
/// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue) before
/// the real `TraceObject` port is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Truncate, split, or delete conflicting entries to make way for the specified lifespan.
    Truncate,
    /// Fail with [`crate::trace::model::target::duplicate_key_exception::DuplicateKeyException`]
    /// if the specified lifespan would result in conflicting entries.
    Deny,
    /// Adjust the new entry to fit into the span available, possibly ignoring it altogether.
    Adjust,
}

/// Placeholder for `ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema`,
/// referenced by
/// [`PrimitiveTraceObjectSchema`](crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema)
/// before the real port is available. `PrimitiveTraceObjectSchema` only ever hands these back as
/// opaque values (`AttributeSchema.DEFAULT_ANY`/`DEFAULT_VOID`), never inspecting them, so this is
/// a marker trait rather than reproducing `getName`/`getSchema`/`isRequired`/`isFixed`/`getHidden`.
pub trait AttributeSchema: Send + Sync {}

/// Placeholder for `ghidra.trace.model.target.schema.SchemaBuilder`, referenced by
/// [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
/// before the real port is available. `DefaultSchemaContext` only invokes `buildAndAdd()` on
/// builders it constructs, so that is the only member ported here.
pub trait SchemaBuilder: Send + Sync {
    /// Builds the schema and adds it to the context the builder was created from. Mirrors
    /// `SchemaBuilder.buildAndAdd()`.
    fn build_and_add(&self) -> Box<dyn TraceObjectSchema>;
}

/// Placeholder for `ghidra.trace.model.guest.TracePlatform`, referenced by
/// [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit) before the real
/// port is available. Grown to add the two members
/// [`InstructionAdapterFromPrototype`](crate::trace::util::instruction_adapter_from_prototype::InstructionAdapterFromPrototype)
/// needs to remap guest-language operand addresses into the trace's host address space. Both
/// default to identity/host behavior so existing marker (`impl TracePlatform for T {}`)
/// implementors keep compiling unchanged.
pub trait TracePlatform: Send + Sync {
    /// Whether this is the trace's host (native) platform, as opposed to a guest platform.
    /// Mirrors `TracePlatform.isHost()`.
    fn is_host(&self) -> bool {
        true
    }

    /// Maps an address in this platform's language into the trace's host address space, or
    /// `None` if it cannot be mapped. Mirrors `TracePlatform.mapGuestToHost(Address)`. Defaults
    /// to the identity mapping, matching the host platform's behavior.
    fn map_guest_to_host(&self, address: Address) -> Option<Address> {
        Some(address)
    }
}

/// Placeholder for `ghidra.trace.model.thread.TraceThread`, referenced by
/// [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit) before the real
/// port is available. No members are parsed from the Java source yet.
pub trait TraceThread: Send + Sync {}

/// Placeholder for `ghidra.trace.model.stack.TraceStackFrame`, referenced by
/// [`TraceCodeManager`](crate::trace::model::listing::trace_code_manager::TraceCodeManager)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceStackFrame: Send + Sync {}

/// Placeholder for `ghidra.trace.database.target.DBTraceObject`, referenced by
/// [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage)
/// before the real port is available. `TraceObjectValueStorage` is a bare abstract interface (no
/// default methods), so it only ever passes this type around opaquely (as `getParent`'s return
/// and `getChildOrNull`'s return); no members are needed yet.
pub trait DBTraceObject: Send + Sync {}

/// Placeholder for `ghidra.trace.database.target.DBTraceObjectManager`, referenced by
/// [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage)
/// before the real port is available. `TraceObjectValueStorage` only ever passes this type around
/// opaquely (as `getManager`'s return); no members are needed yet.
pub trait DBTraceObjectManager: Send + Sync {}

/// Placeholder for `ghidra.trace.database.target.DBTraceObjectValue`, referenced by
/// [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage)
/// before the real port is available. `TraceObjectValueStorage` only ever passes this type around
/// opaquely (as `getWrapper`'s return); no members are needed yet.
pub trait DBTraceObjectValue: Send + Sync {}

/// Placeholder for `ghidra.trace.util.TraceChangeRecord`, referenced by
/// [`TraceChangeManager`](crate::trace::util::trace_change_manager::TraceChangeManager) before
/// the real port is available. The Java interface only ever receives this type as an opaque,
/// wildcard-typed (`TraceChangeRecord<?, ?>`) event parameter -- it never calls any of the
/// type's own getters -- so this is a marker trait rather than reproducing
/// `getAddressSpace`/`getAffectedObject`/`isOldKnown`/`getOldValue`/`getNewValue`.
pub trait TraceChangeRecord: Send + Sync {}

/// Placeholder for `ghidra.trace.util.TraceRegisterUtils`, referenced by
/// [`TraceSpaceMixin`](crate::trace::util::trace_space_mixin::TraceSpaceMixin) before the real
/// port is available. Mirrors the Java class's static-method-only shape (see
/// [`ExtensionUtils`](crate::util::extensions::extension_utils::ExtensionUtils) for the same
/// static-class-to-`&self`-trait convention) as an object-safe trait, restricted to the two
/// static methods `TraceSpaceMixin`'s defaults call: `getThread(Trace, AddressSpace)` and
/// `getFrameLevel(Trace, AddressSpace)`.
pub trait TraceRegisterUtils: Send + Sync {
    /// Mirrors `TraceRegisterUtils.getThread(Trace, AddressSpace)`.
    fn get_thread(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> Box<dyn TraceThread>;

    /// Mirrors `TraceRegisterUtils.getFrameLevel(Trace, AddressSpace)`.
    fn get_frame_level(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> i32;
}

