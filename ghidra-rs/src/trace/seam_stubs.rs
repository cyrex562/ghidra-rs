//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use std::sync::Arc;

use crate::debug::api::tracermi::SchemaName;
use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressSet, AddressSetView, AddressSpace,
};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::{Language, Register};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::util::trace_change_manager::TraceChangeManager;
use crate::util::lock_hold::Lock;

/// Placeholder for `ghidra.trace.model.property.TraceAddressPropertyManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceAddressPropertyManager {}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBookmarkManager {}

/// Placeholder for `ghidra.trace.model.breakpoint.TraceBreakpointCommon`, referenced by
/// [`TraceBreakpointSpec`](crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceBreakpointCommon: Send + Sync {}

/// Placeholder for `ghidra.trace.model.breakpoint.TraceBreakpointLocation`, referenced by
/// [`TraceBreakpointSpec`](crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceBreakpointLocation: Send + Sync {}

/// Placeholder for `ghidra.trace.model.data.TraceBasedDataTypeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends ProgramBasedDataTypeManager` (itself a `DataTypeManager`) so that
/// the placeholder stays substitutable for [`DataTypeManager`].
pub trait TraceBasedDataTypeManager: DataTypeManager {}

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

/// Placeholder for `ghidra.trace.model.context.TraceRegisterContextManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceRegisterContextManager {}

/// Placeholder for `ghidra.trace.model.stack.TraceStackManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceStackManager {}

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

    /// Resolves the schema of the (possibly indirect) successor object at the given path from
    /// this schema. Mirrors `TraceObjectSchema.getSuccessorSchema(KeyPath)`, used by
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)'s
    /// `getConventionalRegisterPath(AddressSpace, Register)` default.
    ///
    /// The real Java method walks the element/attribute schema maps (not yet ported) to resolve
    /// each path component, so this placeholder defaults to "unresolved" until that machinery
    /// exists.
    fn get_successor_schema(&self, _path: &KeyPath) -> Option<Box<dyn TraceObjectSchema>> {
        None
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

    /// The path from the trace's root object to this object. Mirrors
    /// `TraceObject.getCanonicalPath()`, used by
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)'s
    /// `getConventionalRegisterPath(TraceObject, Register)` default.
    ///
    /// Defaults to the root path so existing implementors are unaffected; concrete
    /// implementations should override once this placeholder is replaced by the real port.
    fn get_canonical_path(&self) -> KeyPath {
        KeyPath::root()
    }
}

/// Placeholder for `ghidra.trace.model.target.TraceObjectValPath`, referenced by
/// [`TraceObjectManager`](crate::trace::model::target::trace_object_manager::TraceObjectManager)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceObjectValPath: Send + Sync {}

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

    /// Get the trace this platform belongs to. Mirrors `TracePlatform.getTrace()`.
    ///
    /// Real Java method, abstract (no default), so every platform must supply it. This
    /// placeholder instead defaults to panicking, matching this crate's other
    /// grown-but-not-yet-implemented placeholder members (see
    /// [`TraceRegisterUtils::require_byte_bound`]'s panic for the same reasoning): that keeps the
    /// several existing marker (`impl TracePlatform for T {}`) implementors compiling unchanged,
    /// since none of them are exercised through a path that calls this method.
    ///
    /// Grown for
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform),
    /// whose defaults need it to reach the owning trace's symbol/object managers.
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("TracePlatform::get_trace placeholder not overridden")
    }

    /// Maps an address in this platform's language into the trace's host address space, or
    /// `None` if it cannot be mapped. Mirrors `TracePlatform.mapGuestToHost(Address)`. Defaults
    /// to the identity mapping, matching the host platform's behavior.
    fn map_guest_to_host(&self, address: Address) -> Option<Address> {
        Some(address)
    }

    /// Maps a range in this platform's language into the trace's host address space, or `None`
    /// if it cannot be mapped (the Java method requires the entire range map to a single range).
    /// Mirrors `TracePlatform.mapGuestToHost(AddressRange)`. Defaults to the identity mapping,
    /// matching the host platform's behavior.
    ///
    /// Grown for
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform),
    /// whose `getConventionalRegisterRange` default needs the range-taking overload.
    fn map_guest_to_host_range(&self, range: &AddressRange) -> Option<AddressRange> {
        Some(range.clone())
    }

    /// Get the conventional (register-space-overlay) address range for the given platform
    /// register, within the given overlay address space. Mirrors
    /// `TracePlatform.getConventionalRegisterRange(AddressSpace, Register)`, used by
    /// [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)'s
    /// register-taking defaults.
    ///
    /// The Java method is abstract with no default (its mapping depends on platform-specific
    /// guest/host register layout, not yet ported). This placeholder defaults to re-basing the
    /// register's own offset and byte length into the given overlay space, matching a host
    /// platform's identity mapping (see [`Self::map_guest_to_host`]'s default for the same
    /// convention).
    fn get_conventional_register_range(
        &self,
        overlay: &Arc<AddressSpace>,
        register: &Register,
    ) -> AddressRange {
        let start = overlay.address(register.address().offset());
        AddressRange::from_start_len(start.clone(), register.num_bytes() as u64)
            .unwrap_or_else(|_| AddressRange::new(start.clone(), start))
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

/// Placeholder for `ghidra.trace.model.property.TracePropertyMapSpace`, referenced by
/// [`TracePropertyMap`](crate::trace::model::property::trace_property_map::TracePropertyMap)
/// before the real port is available. `TracePropertyMap` only ever passes this type around
/// opaquely (as the return of its map-space lookups); no members are needed yet.
pub trait TracePropertyMapSpace<T>: Send + Sync {}

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

/// Placeholder for `ghidra.trace.database.target.TraceObjectValueQuery`, referenced by
/// [`DBTraceObjectValueRStarTree`](crate::trace::database::target::db_trace_object_value_r_star_tree::DBTraceObjectValueRStarTree)
/// before the real port is available. That trait's `DBTraceObjectValueMap::reduce` only ever
/// passes this type around opaquely (as the query to combine with any existing constraint); no
/// members are needed yet.
pub trait TraceObjectValueQuery: Send + Sync {}

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
///
/// Grown to add
/// [`TraceLabelSymbolView`](crate::trace::model::symbol::trace_label_symbol_view::TraceLabelSymbolView)'s
/// `requireByteBound(Register)` static check, used by its register-taking `add` default.
pub trait TraceRegisterUtils: Send + Sync {
    /// Mirrors `TraceRegisterUtils.getThread(Trace, AddressSpace)`.
    fn get_thread(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> Box<dyn TraceThread>;

    /// Mirrors `TraceRegisterUtils.getFrameLevel(Trace, AddressSpace)`.
    fn get_frame_level(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> i32;

    /// Get the register address space for the given thread and frame level, or `None` if it
    /// does not exist (and `create_if_absent` is false). Mirrors
    /// `TraceRegisterUtils.getRegisterAddressSpace(TraceThread, int, boolean)`, used by
    /// [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)'s
    /// register-taking defaults.
    fn get_register_address_space(
        &self,
        thread: &dyn TraceThread,
        frame_level: i32,
        create_if_absent: bool,
    ) -> Option<Arc<AddressSpace>>;

    /// Mirrors `TraceRegisterUtils.requireByteBound(Register)`, which rejects a register that
    /// does not start and end on a byte boundary. Implemented directly against the ported
    /// [`Register`], since the check depends only on the register itself, not on any manager
    /// state.
    ///
    /// # Panics
    /// Panics if `register` is not byte-bound, mirroring the Java method's
    /// `IllegalArgumentException`.
    fn require_byte_bound(&self, register: &Register) {
        if register.least_significant_bit() % 8 != 0 || register.bit_length() % 8 != 0 {
            panic!("register {} is not byte-bound", register.name());
        }
    }

    /// Get the (byte-addressed) range a register occupies in its own address space. Mirrors the
    /// static `TraceRegisterUtils.rangeForRegister(Register)`, used by
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)'s
    /// `getConventionalRegisterRange` default.
    ///
    /// Unlike this trait's other members, this one is implemented directly against the ported
    /// [`Register`] (its address and byte length), since the computation depends only on the
    /// register itself, not on any manager state.
    fn range_for_register(&self, register: &Register) -> AddressRange {
        let start = register.address().clone();
        let end = start.add_wrap((register.num_bytes() as i64) - 1);
        AddressRange::new(start, end)
    }
}

/// Placeholder for the nested `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery`,
/// referenced by
/// [`TraceAddressSnapRangePropertyMapOperations`](crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations)
/// before the real port is available. That trait only ever passes this type around opaquely (as
/// the `Q` type parameter of the `SpatialMap` supertrait it extends); no members are needed yet.
pub trait TraceAddressSnapRangeQuery: Send + Sync {}

/// Placeholder for `ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage`,
/// referenced by
/// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
/// before the real port is available. `InternalTracePlatform` only ever passes this type around
/// opaquely (as `getLanguageEntry()`'s return); no members are needed yet.
pub trait DBTraceGuestLanguage: Send + Sync {}

/// Placeholder for the nested
/// `ghidra.trace.database.data.DBTraceDataSettingsAdapter.DBTraceSettingsEntry`, referenced by
/// [`DBTraceDataSettingsOperations`](crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations)
/// before the real (DB-record-backed) type is ported. Mirrors the subset of members that
/// interface's default methods call: the lifespan and name accessors, plus the
/// `setLong`/`getLong`/`setString`/`getString`/`setValue`/`getValue` value accessors. The Java
/// class's `setBytes`/`getBytes` pair is not referenced by that interface (only reachable through
/// `setValue`/`getValue`, which already cover the `byte[]` case via
/// [`SettingsValue::Bytes`](crate::trace::database::data::db_trace_data_settings_operations::SettingsValue::Bytes)),
/// so it is omitted here.
pub trait DBTraceSettingsEntry: Send + Sync {
    /// Mirrors the record's `getLifespan()` (inherited from
    /// `AbstractDBTraceAddressSnapRangePropertyMapData`).
    fn get_lifespan(&self) -> Box<dyn crate::trace::model::lifespan::Lifespan>;

    /// Mirrors the `name` field's getter.
    fn name(&self) -> Option<String>;

    /// Mirrors `setName(String)`.
    fn set_name(&mut self, name: String);

    /// Mirrors `getLong()`.
    fn get_long(&self) -> Option<i64>;

    /// Mirrors `setLong(long)`.
    fn set_long(&mut self, value: i64);

    /// Mirrors `getString()`.
    fn get_string(&self) -> Option<String>;

    /// Mirrors `setString(String)`.
    fn set_string(&mut self, value: String);

    /// Mirrors `getValue()`.
    fn get_value(&self) -> crate::trace::database::data::db_trace_data_settings_operations::SettingsValue;

    /// Mirrors `setValue(Object)`.
    fn set_value(
        &mut self,
        value: crate::trace::database::data::db_trace_data_settings_operations::SettingsValue,
    );
}

/// Placeholder for the nested
/// `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData`,
/// referenced by
/// [`DBTraceAddressSnapRangePropertyMap`](crate::trace::database::map::db_trace_address_snap_range_property_map::DBTraceAddressSnapRangePropertyMap)
/// before the real port is available. That trait's `deleteData(DR)` only ever reads one field off
/// the record: the address space its backing range belongs to (`data.range.getAddressSpace()`),
/// used to pick which per-space delegate owns it.
pub trait AbstractDBTraceAddressSnapRangePropertyMapData: Send + Sync {
    /// The address space that this record's range belongs to. Mirrors
    /// `data.range.getAddressSpace()`.
    fn address_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeUnitAdapter`, referenced (as a
/// supertrait) by
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)
/// before the real port is available. In Java this interface overrides `TraceCodeUnit.getTrace()`
/// to covariantly narrow its return type from `Trace` to `DBTrace` (which implements
/// `ghidra.trace.util.TraceChangeManager`), letting `DBTraceDataAdapter`'s settings-change
/// defaults call `getTrace().setChanged(...)` directly. Rust has no covariant trait-method
/// override (see `TraceData`'s docs for the same issue), so this placeholder instead exposes the
/// change-notification sink those defaults need as its own accessor, rather than reproducing the
/// covariant `getTrace()`.
pub trait DBTraceCodeUnitAdapter: Send + Sync {
    /// Mirrors reaching the owning trace's `TraceChangeManager` through the covariant
    /// `getTrace()` override.
    fn trace_change_manager(&mut self) -> &mut dyn TraceChangeManager;
}

/// Placeholder for `ghidra.trace.util.DataAdapterFromDataType`, referenced (as a supertrait) by
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait DataAdapterFromDataType: Send + Sync {}

/// Placeholder for `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace`,
/// referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `getMapSpace()` returns this type opaquely to
/// callers; the one accessor it (and the tree's own node/data records) reach into is the backing
/// address space. Mirrors `DBTraceAddressSnapRangePropertyMapSpace.getAddressSpace()`.
pub trait DBTraceAddressSnapRangePropertyMapSpace<T>: Send + Sync {
    /// Mirrors `DBTraceAddressSnapRangePropertyMapSpace.getAddressSpace()`.
    fn address_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.util.database.spatial.DBTreeNodeRecord`, referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `internalGetChildrenOf(DBTreeNodeRecord<?>)`
/// only ever type-tests and passes this type around opaquely; no members are needed yet.
pub trait DBTreeNodeRecord: Send + Sync {}

/// Placeholder for `ghidra.util.database.spatial.DBTreeRecord`, referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `internalGetChildrenOf(DBTreeNodeRecord<?>)`
/// only ever returns this type opaquely to callers; no members are needed yet.
pub trait DBTreeRecord: Send + Sync {}

/// Placeholder for `ghidra.util.database.spatial.rect.Rectangle2DDirection`, referenced by
/// [`TraceReferenceOperations`](crate::trace::model::symbol::trace_reference_operations::TraceReferenceOperations)
/// before the real port is available. The Java type is an enum (`LEFTMOST`, `RIGHTMOST`,
/// `BOTTOMMOST`, `TOPMOST`) whose only public member is `isReversed()`; only that member is
/// stubbed here.
pub trait Rectangle2DDirection: Send + Sync {
    fn is_reversed(&self) -> bool;
}

/// Placeholder for `ghidra.trace.database.listing.AbstractBaseDBTraceCodeUnitsView<T>`,
/// referenced (as a supertrait) by
/// [`AbstractSingleDBTraceCodeUnitsView`](crate::trace::database::listing::abstract_single_db_trace_code_units_view::AbstractSingleDBTraceCodeUnitsView)
/// and (as the composed-view bound `M`) by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. Grown from a non-generic marker (just `getSpace()`) to
/// carry the Java class's `T extends DBTraceCodeUnitAdapter` type parameter, since
/// `AbstractBaseDBTraceCodeUnitsMemoryView`'s defaults call straight through to this view's own
/// per-space query methods (`getFloor`, `getAt`, the `get(...)` overloads, etc.) -- named here
/// to match the sibling overload-disambiguated names already established on
/// [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView)
/// (`get_in_range`, `get_address_set_view_within`, `covers_snap_range`, ...). Methods this stub's
/// original (narrower) consumer, [`AbstractSingleDBTraceCodeUnitsView`], doesn't need are still
/// included, since the real Java interface declares them regardless of which subtrait uses them.
pub trait AbstractBaseDBTraceCodeUnitsView<T> {
    /// The address space this view is bound to. Mirrors
    /// `AbstractBaseDBTraceCodeUnitsView.getSpace()` (equivalently, `getAddressSpace()`).
    fn get_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.size()`.
    fn size(&self) -> i32;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getFloor(long, Address)`.
    fn get_floor(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getContaining(long, Address)`.
    fn get_containing(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAt(long, Address)`.
    fn get_at(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getCeiling(long, Address)`.
    fn get_ceiling(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.get(long, AddressRange, boolean)`. Named to
    /// match [`TraceBaseCodeUnitsView::get_in_range`].
    fn get_in_range(&self, snap: i64, range: &AddressRange, forward: bool) -> Vec<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getIntersecting(TraceAddressSnapRange)`.
    fn get_intersecting(&self, tasr: &dyn TraceAddressSnapRange) -> Vec<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAddressSetView(long, AddressRange)`. Named to
    /// match [`TraceBaseCodeUnitsView::get_address_set_view_within`].
    fn get_address_set_view_within(&self, snap: i64, within: &AddressRange) -> Box<dyn AddressSetView>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAddressSetView(long)`.
    fn get_address_set_view(&self, snap: i64) -> Box<dyn AddressSetView>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.containsAddress(long, Address)`.
    fn contains_address(&self, snap: i64, address: &Address) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: &dyn Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.coversRange(TraceAddressSnapRange)`. Named to
    /// match [`TraceBaseCodeUnitsView::covers_snap_range`].
    fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: &dyn Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(TraceAddressSnapRange)`. Named
    /// to match [`TraceBaseCodeUnitsView::intersects_snap_range`].
    fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeManager`, referenced by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. That trait's `manager` field accessor only ever reaches
/// these members (all inherited, in the real Java class, from
/// `AbstractDBTraceSpaceBasedManager<DBTraceCodeSpace>`): the owning trace, the base language
/// (used to walk address spaces when stepping past a space boundary), the read/write locks, the
/// per-space lookup, and the active-space listing `size()` sums over.
pub trait DBTraceCodeManager: Send + Sync {
    /// Mirrors `AbstractDBTraceSpaceBasedManager.getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getBaseLanguage()`.
    fn get_base_language(&self) -> Box<dyn Language>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.lock.readLock()`.
    fn read_lock(&self) -> &dyn Lock;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.lock.writeLock()`.
    fn write_lock(&self) -> &dyn Lock;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getForSpace(AddressSpace, boolean)`.
    fn get_for_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceCodeSpace>>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`.
    fn get_active_spaces(&self) -> Vec<Arc<dyn DBTraceCodeSpace>>;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeSpace`, referenced by
/// [`DBTraceCodeManager`] and
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. The memory view mostly passes this type opaquely (received
/// from [`DBTraceCodeManager::get_for_space`]/[`DBTraceCodeManager::get_active_spaces`] and handed
/// to its own abstract `getView(DBTraceCodeSpace)`); the one accessor stubbed here mirrors the
/// real class's package-visible `space` field (read via `AbstractBaseDBTraceCodeUnitsView`'s
/// `getAddressSpace() { return space.space; }`), which any real `getView` implementation needs to
/// pick the right per-space storage.
pub trait DBTraceCodeSpace: Send + Sync {
    /// Mirrors the `DBTraceCodeSpace.space` field.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.trace.database.DBTraceUtils`, referenced by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. That (large, static-method-only) utility class is mirrored
/// here, like [`AddressCollectors`](crate::program::model::address::address_collectors::AddressCollectors),
/// as a unit struct with associated functions rather than a `&self`-taking trait, since none of
/// its methods are instance methods in the original. Only the one static method the memory view
/// needs is ported, with a real (not stubbed-out) body: both `AddressFactory::get_address_set`
/// and `AddressFactory::get_address_set_range` it composes are already-ported real APIs.
pub struct DBTraceUtils;

impl DBTraceUtils {
    /// Mirrors `DBTraceUtils.getAddressSet(AddressFactory, Address, boolean)`: the sub-range of
    /// `factory`'s full address set from `start` to the end of its space (`forward`) or from the
    /// beginning of its space to `start` (`!forward`).
    pub fn get_address_set(factory: &dyn AddressFactory, start: &Address, forward: bool) -> AddressSet {
        let all = factory.get_address_set();
        if forward {
            match all.max_address() {
                Some(max) => factory.get_address_set_range(start, &max),
                None => AddressSet::new(),
            }
        } else {
            match all.min_address() {
                Some(min) => factory.get_address_set_range(&min, start),
                None => AddressSet::new(),
            }
        }
    }
}

/// Placeholder for `ghidra.trace.database.listing.InternalBaseCodeUnitsView`, referenced (as a
/// supertrait) by
/// [`InternalTraceBaseDefinedUnitsView`](crate::trace::database::listing::internal_trace_base_defined_units_view::InternalTraceBaseDefinedUnitsView)
/// before the real port is available. The real Java interface's other members (the
/// `getForRegister`/`getContaining`/`get` overloads taking a `TracePlatform`) are generic in its
/// `T extends TraceCodeUnit` type parameter and are not needed by any currently-ported subtrait;
/// only its abstract `getSpace()` accessor is stubbed here, since that's the one member
/// `InternalTraceBaseDefinedUnitsView`'s `clear(TracePlatform, ...)` default needs.
pub trait InternalBaseCodeUnitsView: TraceBaseCodeUnitsView {
    /// The address space this view is bound to. Mirrors
    /// `InternalBaseCodeUnitsView.getSpace()`.
    fn get_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.trace.database.listing.AbstractBaseDBTraceDefinedUnitsView`,
/// referenced by
/// [`DBTraceDefinedUnitsView`](crate::trace::database::listing::db_trace_defined_units_view::DBTraceDefinedUnitsView)
/// before the real port is available. The real Java class is a large abstract base (caching,
/// spatial-map queries, generic in `T extends AbstractDBTraceCodeUnit<T>`) that backs one "part"
/// (e.g. instructions, or defined data) of a composed view; `DBTraceDefinedUnitsView` only ever
/// calls three of its members -- on each part, to aggregate across all parts -- so only those are
/// stubbed here, with the same signatures as the overridden
/// [`TraceBaseCodeUnitsView`]/[`TraceBaseDefinedUnitsView`](crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView)
/// methods they implement.
pub trait AbstractBaseDBTraceDefinedUnitsView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceDefinedUnitsView.coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: &dyn crate::trace::model::lifespan::Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceDefinedUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: &dyn crate::trace::model::lifespan::Lifespan, range: &AddressRange) -> bool;

    /// Mirrors the abstract `clear(Lifespan, AddressRange, boolean, TaskMonitor)` this part
    /// implements (declared on `TraceBaseDefinedUnitsView`).
    fn clear(
        &mut self,
        span: &dyn crate::trace::model::lifespan::Lifespan,
        range: &AddressRange,
        clear_context: bool,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Result<(), crate::util::exception::CancelledException>;
}

/// Placeholder for `ghidra.trace.database.listing.AbstractDBTraceDataComponent`, referenced by
/// [`DBTraceDefinedDataAdapter`] before the real port is available. That trait's
/// `doGetComponentCache()` only ever passes this type around opaquely (as the element type of the
/// per-instance component cache it returns); no members are needed yet.
pub trait AbstractDBTraceDataComponent: Send + Sync {}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDefinedDataAdapter`, referenced (as a
/// supertrait) by
/// [`DBTraceData`](crate::trace::database::listing::db_trace_data::DBTraceData) before the real
/// port is available. Mirrors the Java interface's `extends DBTraceDataAdapter` (already ported)
/// plus the two members it adds beyond that supertrait's abstract surface: the abstract
/// `doGetComponentCache()` (a lazily-populated per-instance cache of
/// [`AbstractDBTraceDataComponent`]s that has no natural default body without access to instance
/// storage) and the `StringBuilder`-taking `getPathName(StringBuilder, boolean)` overload
/// (ported as `append_path_name`, taking the builder by mutable reference; distinct from the
/// no-arg `Data::get_path_name` this interface also inherits). The interface's remaining default
/// methods (`isDefined`, `getNumComponents`, `getComponent`, `getComponentAt`,
/// `getComponentContaining`, `getComponentsContaining`, `getPrimitiveAt`, `getComponent(int[])`,
/// and the covariantly-narrowed abstract `getRoot()`/`getParent()`) are either pure covariant
/// narrowings of already-inherited `Data` members or business logic layered over them (see
/// [`TraceData`](crate::trace::model::listing::trace_data::TraceData)'s docs for why Rust cannot
/// re-declare covariant overrides), so none are reproduced here.
pub trait DBTraceDefinedDataAdapter:
    crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter
{
    /// Mirrors the abstract `doGetComponentCache()`.
    fn do_get_component_cache(&self) -> Vec<Box<dyn AbstractDBTraceDataComponent>>;

    /// Mirrors the abstract `getPathName(StringBuilder, boolean)`, appending to `builder` in
    /// place of returning a new `StringBuilder`.
    fn append_path_name(&self, builder: &mut String, include_root_symbol: bool);
}

/// Placeholder for `ghidra.trace.database.symbol.AbstractDBTraceSymbol`, referenced (as a
/// supertrait) by
/// [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
/// before the real port is available. The Java class has ~30 members covering identity,
/// DB-record access, references, and program-location lookups; only the five members
/// `DBTraceNamespaceSymbol` actually calls through `super.*()` are modeled here
/// (`getLifespan`, `getAddressSet`, `setNamespace`, `delete`, `isGlobal`); the rest are omitted
/// until a consumer needs them.
pub trait AbstractDBTraceSymbol: Send + Sync {
    /// Mirrors `getLifespan()`.
    fn get_lifespan(&self) -> Box<dyn crate::trace::model::lifespan::Lifespan>;

    /// Mirrors `getAddressSet()`.
    fn get_address_set(&self) -> crate::program::model::address::AddressSet;

    /// Mirrors `setNamespace(Namespace)`.
    fn set_namespace(
        &self,
        new_namespace: &dyn crate::program::model::symbol::Namespace,
    ) -> std::io::Result<()>;

    /// Mirrors `delete()`.
    fn delete(&self) -> bool;

    /// Mirrors `isGlobal()`.
    fn is_global(&self) -> bool;
}

/// Placeholder for `ghidra.trace.database.symbol.DBTraceSymbolManager`, referenced by
/// [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
/// before the real port is available. The Java class has ~20 members; only
/// `getGlobalNamespace()`, the one method `DBTraceNamespaceSymbol::checkCircular` needs, is
/// modeled here.
pub trait DBTraceSymbolManager: Send + Sync {
    /// Mirrors `getGlobalNamespace()`.
    fn get_global_namespace(
        &self,
    ) -> std::sync::Arc<
        dyn crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol,
    >;
}

