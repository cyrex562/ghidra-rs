//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use crate::debug::api::tracermi::SchemaName;
use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressSet, AddressSetView, AddressSpace,
};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::{Language, Register};
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::RegisterValue as ProgramRegisterValue;
use crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::util::trace_change_manager::TraceChangeManager;
use crate::util::exception::DuplicateNameException;
use crate::util::lock_hold::Lock;
use crate::util::task::TaskMonitor;

/// Placeholder for `ghidra.trace.database.map.AbstractDBTracePropertyMap`, referenced by
/// [`TraceAddressPropertyManager`] (grown below) and
/// [`DBTraceAddressPropertyManager`](crate::trace::database::property::db_trace_address_property_manager::DBTraceAddressPropertyManager)
/// before the real (generic, DB-record-backed) type is ported. Java's `Class<T> valueClass` /
/// `AbstractDBTracePropertyMap<T, ?>` erasure is represented the same way
/// [`TraceObjectValue::get_value`](crate::trace::model::target::trace_object_value::TraceObjectValue::get_value)'s
/// docs establish for an unconstrained type parameter on an object-safe trait: the map's value
/// type is carried at runtime as a [`TypeId`] rather than at the Rust type level, so a single
/// manager can hold differently-typed property maps simultaneously (mirroring
/// `propertyMapsByName: Map<String, AbstractDBTracePropertyMap<?, ?>>`). Only the one accessor
/// [`TraceAddressPropertyManager`]'s type-checking members need is stubbed here.
pub trait AbstractDBTracePropertyMap: Send + Sync {
    /// Mirrors `AbstractDBTracePropertyMap.getValueClass()`.
    fn get_value_class(&self) -> TypeId;
}

/// Placeholder for `ghidra.trace.model.property.TraceAddressPropertyManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
///
/// Grown to add the manager's full method surface, needed by
/// [`DBTraceAddressPropertyManager`](crate::trace::database::property::db_trace_address_property_manager::DBTraceAddressPropertyManager)
/// (a cycle cut-point ported directly against this interface, mirroring Java's
/// `DBTraceAddressPropertyManager implements TraceAddressPropertyManager, DBTraceManager`). Java's
/// `<T> ... Class<T> valueClass` generic methods are not object-safe as written (a `dyn Trait`
/// cannot dispatch a generic method); `Class<T>` becomes [`TypeId`] and the returned
/// `TracePropertyMap<T>` becomes the type-erased [`AbstractDBTracePropertyMap`], matching this
/// crate's established convention for an unconstrained type parameter on an object-safe trait
/// (see
/// [`TraceObjectValue::get_value`](crate::trace::model::target::trace_object_value::TraceObjectValue::get_value)'s
/// docs). Java's unchecked `TypeMismatchException` (no `throws` clause) is mirrored as a possible
/// panic, matching this crate's existing convention for that exception (see
/// [`PropertyMapManager`](crate::program::model::util::property_map_manager::PropertyMapManager)'s
/// "May panic" docs); only the checked `DuplicateNameException` on `createPropertyMap` becomes a
/// `Result`. All new members default to panicking, matching this module's other
/// grown-but-not-yet-implemented placeholders (see [`TracePlatform::get_trace`]'s docs for the
/// same reasoning), so the existing marker (`impl TraceAddressPropertyManager for T {}`)
/// implementor keeps compiling unchanged.
pub trait TraceAddressPropertyManager: Send + Sync {
    /// Create a property map with the given name and value type. Mirrors
    /// `createPropertyMap(String, Class<T>)`.
    fn create_property_map(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Result<Box<dyn AbstractDBTracePropertyMap>, DuplicateNameException> {
        unimplemented!("TraceAddressPropertyManager::create_property_map placeholder not overridden")
    }

    /// Get the property map with the given name, if it has the given type. Mirrors
    /// `getPropertyMap(String, Class<T>)`. Returns `None` if no such map exists (Java's `null`).
    fn get_property_map(
        &self,
        _name: &str,
        _value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!("TraceAddressPropertyManager::get_property_map placeholder not overridden")
    }

    /// Get the property map with the given name, if its values extend the given type. Mirrors
    /// `getPropertyMapExtends(String, Class<T>)`.
    fn get_property_map_extends(
        &self,
        _name: &str,
        _value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!(
            "TraceAddressPropertyManager::get_property_map_extends placeholder not overridden"
        )
    }

    /// Get the property map with the given name, creating it if necessary. Mirrors
    /// `getOrCreatePropertyMap(String, Class<T>)`.
    fn get_or_create_property_map(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        unimplemented!(
            "TraceAddressPropertyManager::get_or_create_property_map placeholder not overridden"
        )
    }

    /// Get the property map with the given name, creating it if necessary; if it already exists,
    /// its values' type must be a supertype of the given type. Mirrors
    /// `getOrCreatePropertyMapSuper(String, Class<T>)`.
    fn get_or_create_property_map_super(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        unimplemented!(
            "TraceAddressPropertyManager::get_or_create_property_map_super placeholder not overridden"
        )
    }

    /// Get the property map with the given name, without type-checking. Mirrors the overload
    /// `getPropertyMap(String)`.
    fn get_property_map_untyped(&self, _name: &str) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!(
            "TraceAddressPropertyManager::get_property_map_untyped placeholder not overridden"
        )
    }

    /// Get a copy of all the defined properties. Mirrors `getAllProperties()`.
    fn get_all_properties(&self) -> HashMap<String, Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!("TraceAddressPropertyManager::get_all_properties placeholder not overridden")
    }
}

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

/// Placeholder for `ghidra.trace.model.guest.TraceGuestPlatform`, referenced by
/// [`TracePlatformManager`](crate::trace::model::guest::trace_platform_manager::TracePlatformManager)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceGuestPlatform: Send + Sync {}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceMemoryManager {}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryOperations`, referenced by
/// [`TraceMemorySpace`](crate::trace::model::memory::trace_memory_space::TraceMemorySpace) before
/// the real interface is ported. `TraceMemorySpace` only extends this interface as a supertrait
/// and does not itself call any of its (large) surface of byte/state/register operations, so no
/// members were needed there.
///
/// Grown to add the six abstract (non-register) primitives
/// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
/// register-taking defaults reduce to: setting/querying state and reading/writing/removing bytes
/// over a plain address range. Java's `ByteBuffer` position/limit-bounded parameters become `&mut
/// [u8]` slices, the convention already established by
/// [`MemBuffer`](crate::program::model::mem::MemBuffer) and
/// [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit).
/// The `Collection<Entry<TraceAddressSnapRange, TraceMemoryState>>` returned by `getStates` becomes
/// a `Vec` of pairs.
pub trait TraceMemoryOperations: Send + Sync {
    /// Set the state of memory over a given time and address range. Mirrors
    /// `setState(long, AddressRange, TraceMemoryState)`.
    fn set_state(&mut self, snap: i64, range: &AddressRange, state: TraceMemoryState);

    /// Get all the entries covering the given range effective at the given snap. Mirrors
    /// `getStates(long, AddressRange)`.
    fn get_states(
        &self,
        snap: i64,
        range: &AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Write bytes at the given snap and address, returning the number of bytes written. Mirrors
    /// `putBytes(long, Address, ByteBuffer)`.
    fn put_bytes(&mut self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Read the most recent bytes from the given snap and address, returning the number of bytes
    /// read. Mirrors `getBytes(long, Address, ByteBuffer)`.
    fn get_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Read the most recent bytes from the given snap and address, following schedule forks.
    /// Mirrors `getViewBytes(long, Address, ByteBuffer)`.
    fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Remove bytes from the given time and location. Mirrors `removeBytes(long, Address, int)`.
    fn remove_bytes(&mut self, snap: i64, start: &Address, len: i32);
}

/// Placeholder for `ghidra.trace.model.context.TraceRegisterContextManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceRegisterContextManager {}

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

    /// Get the language this platform disassembles/decodes with. Mirrors
    /// `TracePlatform.getLanguage()`.
    ///
    /// Named `platform_language` rather than `get_language` to avoid an inherent-method-style
    /// ambiguity: [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
    /// already implements the unrelated [`ProgramArchitecture`](crate::program::model::lang::program_architecture::ProgramArchitecture)`::get_language`,
    /// and Rust rejects a bare `self.get_language()` call when both are in scope on the same
    /// concrete type.
    ///
    /// Real Java method, abstract (no default). Defaults to panicking, matching
    /// [`Self::get_trace`]'s established growth convention, so existing marker
    /// (`impl TracePlatform for T {}`) implementors keep compiling unchanged.
    ///
    /// Grown for
    /// [`DBTraceRegisterContextManager`](crate::trace::database::context::db_trace_register_context_manager::DBTraceRegisterContextManager)'s
    /// `get_value_with_default` default, which needs the platform's language to resolve both the
    /// per-space delegate call and the language-defined default fallback.
    fn platform_language(&self) -> Box<dyn Language> {
        unimplemented!("TracePlatform::platform_language placeholder not overridden")
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
/// [`TraceCodeManager`](crate::trace::model::listing::trace_code_manager::TraceCodeManager) and
/// [`TraceStackManager`](crate::trace::model::stack::trace_stack_manager::TraceStackManager)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceStackFrame: Send + Sync {}

/// Placeholder for `ghidra.trace.model.stack.TraceStack`, referenced by
/// [`TraceStackManager`](crate::trace::model::stack::trace_stack_manager::TraceStackManager)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait TraceStack: Send + Sync {}

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
///
/// Grown to add the region-storage methods
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// region-management defaults need. The real Java methods are generic in a `Class<I extends
/// TraceObjectInterface>` reflection token (`getAllObjects(Class<I>)`, etc); every call site this
/// placeholder's consumer makes passes `TraceMemoryRegion.class`, so each is specialized directly
/// to [`TraceMemoryRegion`] rather than reproducing the generic/reflective shape. All default to
/// panicking, like [`DBTrace`]'s grown `get_object_manager`, so the existing marker
/// (`impl DBTraceObjectManager for T {}`) implementors keep compiling unchanged.
pub trait DBTraceObjectManager: Send + Sync {
    /// Mirrors `addMemoryRegion(String, Lifespan, AddressRange, Collection<TraceMemoryFlag>)`.
    fn add_memory_region(
        &self,
        _path: &str,
        _lifespan: Lifespan,
        _range: AddressRange,
        _flags: &[TraceMemoryFlag],
    ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
        unimplemented!("DBTraceObjectManager::add_memory_region placeholder not overridden")
    }

    /// Mirrors `getAllObjects(TraceMemoryRegion.class)`.
    fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_all_regions placeholder not overridden")
    }

    /// Mirrors `getObjectByPath(long, String, TraceMemoryRegion.class)`.
    fn get_region_by_path(&self, _snap: i64, _path: &str) -> Option<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_region_by_path placeholder not overridden")
    }

    /// Mirrors `getObjectContaining(long, Address, TraceMemoryRegion.KEY_RANGE,
    /// TraceMemoryRegion.class)`.
    fn get_region_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_region_containing placeholder not overridden")
    }

    /// Mirrors `getObjectsIntersecting(Lifespan, AddressRange, TraceMemoryRegion.KEY_RANGE,
    /// TraceMemoryRegion.class)`.
    fn get_regions_intersecting(
        &self,
        _lifespan: Lifespan,
        _range: &AddressRange,
    ) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_regions_intersecting placeholder not overridden")
    }

    /// Mirrors `getObjectsAtSnap(long, TraceMemoryRegion.class)`.
    fn get_regions_at_snap(&self, _snap: i64) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_regions_at_snap placeholder not overridden")
    }

    /// Mirrors `getObjectsAddressSet(long, TraceMemoryRegion.KEY_RANGE, TraceMemoryRegion.class,
    /// Predicate<TraceMemoryRegion>)`.
    fn get_regions_address_set(
        &self,
        _snap: i64,
        _predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
    ) -> Box<dyn AddressSetView> {
        unimplemented!("DBTraceObjectManager::get_regions_address_set placeholder not overridden")
    }
}

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

    /// Whether `register` starts and ends on a byte boundary. Mirrors the static
    /// `TraceRegisterUtils.isByteBound(Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `setValue` default.
    ///
    /// Like [`Self::range_for_register`], this is implemented directly against the ported
    /// [`Register`]: the same check [`Self::require_byte_bound`] already makes, but as a predicate
    /// rather than a panic.
    fn is_byte_bound(&self, register: &Register) -> bool {
        register.least_significant_bit() % 8 == 0 && register.bit_length() % 8 == 0
    }

    /// Allocate a zeroed buffer sized to receive `register`'s bytes. Mirrors the static
    /// `TraceRegisterUtils.prepareBuffer(Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `getValue`/`getViewValue` defaults, which fill it via `TraceMemoryOperations::get_bytes`/
    /// `get_view_bytes` before handing it to [`Self::finish_buffer`].
    ///
    /// The real Java method over-allocates to the base register's mask width and slices a
    /// byte-order-dependent window into it (see [`Self::finish_buffer`]'s docs for why that
    /// endianness handling has no home here yet); since callers only ever observe the buffer's
    /// length (`register.getNumBytes()`), a buffer of exactly that length is a faithful
    /// placeholder.
    fn prepare_buffer(&self, register: &Register) -> Vec<u8> {
        vec![0u8; register.num_bytes() as usize]
    }

    /// Extract the byte-ordered, mask-offset window of `value`'s bytes that corresponds to
    /// `register`. Mirrors the static `TraceRegisterUtils.bufferForValue(Register,
    /// RegisterValue)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `setValue` default.
    ///
    /// Required rather than defaulted: the real computation reads `value`'s raw mask/value byte
    /// array (`RegisterValue.toBytes()`), which the
    /// [`RegisterValue`](crate::program::seam_stubs::RegisterValue) placeholder does not yet
    /// expose.
    fn buffer_for_value(&self, register: &Register, value: &dyn ProgramRegisterValue) -> Vec<u8>;

    /// Reconstruct a register value from a buffer previously filled via [`Self::prepare_buffer`].
    /// Mirrors the static `TraceRegisterUtils.finishBuffer(ByteBuffer, Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `getValue`/`getViewValue` defaults.
    ///
    /// Required rather than defaulted: constructing a `RegisterValue` from raw bytes has no
    /// implementation to call through to on the
    /// [`RegisterValue`](crate::program::seam_stubs::RegisterValue) placeholder trait (it can only
    /// be built by a concrete type).
    fn finish_buffer(&self, buf: &[u8], register: &Register) -> Box<dyn ProgramRegisterValue>;
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
    fn get_lifespan(&self) -> Lifespan;

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
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.coversRange(TraceAddressSnapRange)`. Named to
    /// match [`TraceBaseCodeUnitsView::covers_snap_range`].
    fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(TraceAddressSnapRange)`. Named
    /// to match [`TraceBaseCodeUnitsView::intersects_snap_range`].
    fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeManager`, referenced by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. That trait's `manager` field accessor only ever reaches
/// these members (all inherited, in the real Java class, from
/// `AbstractDBTraceSpaceBasedManager<`[`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)`>`): the owning trace, the base language
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

/// Placeholder for `ghidra.trace.database.DBTrace`, referenced by
/// [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit)
/// before the real port is available. `AbstractDBTraceCodeUnit.getTrace()` only ever passes this
/// type around opaquely (returning `space.trace`, covariantly narrowed from the base `Trace`
/// interface -- see
/// [`DBTraceCodeSpace::get_trace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace::get_trace)'s
/// docs for that same narrowing); no members are needed yet. Not declared `: Trace`, since nothing
/// currently reachable through this placeholder needs any of `Trace`'s ~20 members, and requiring
/// them would force every implementor (including this module's own tests) to stub out that whole
/// surface for no benefit; the real port should implement both `Trace` and this trait, matching
/// Java's `DBTrace implements Trace`.
///
/// Grown to add the one member
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// region-management defaults need: reaching the trace's object manager, where regions are
/// actually stored (`trace.getObjectManager().addMemoryRegion(...)`, etc). Defaults to
/// panicking, like [`DBTraceOverlaySpaceAdapter`]'s grown members, so the existing marker
/// (`impl DBTrace for T {}`) implementors keep compiling unchanged.
pub trait DBTrace: Send + Sync {
    /// Mirrors `DBTrace.getObjectManager()`.
    fn get_object_manager(&self) -> Box<dyn DBTraceObjectManager> {
        unimplemented!("DBTrace::get_object_manager placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeUnitsView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace` only ever stores and returns this type
/// opaquely (via its own `codeUnits()` accessor); no members are called on it, so this is a bare
/// marker.
pub trait DBTraceCodeUnitsView: Send + Sync {}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceCodeUnitsView`]: only ever
/// stored and returned opaquely (via `data()`), so this is a bare marker.
pub trait DBTraceDataView: Send + Sync {}

/// Placeholder for `ghidra.trace.database.listing.DBTraceInstructionsView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace.invalidateCache()` is the only place that
/// calls a member on this field (`instructions.invalidateCache()`), so only that member is
/// stubbed.
pub trait DBTraceInstructionsView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDefinedDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceInstructionsView`]: only
/// `definedData.invalidateCache()` is called from `DBTraceCodeSpace.invalidateCache()`.
pub trait DBTraceDefinedDataView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceUndefinedDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceInstructionsView`]: only
/// `undefinedData.invalidateCache()` is called from `DBTraceCodeSpace.invalidateCache()`.
pub trait DBTraceUndefinedDataView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.guest.DBTraceGuestPlatform`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace.clearPlatform(...)` only ever compares
/// this type for reference equality (`instruction.platform != guest`) and passes it through
/// opaquely; no members are needed yet.
pub trait DBTraceGuestPlatform: Send + Sync {}

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
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceDefinedUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors the abstract `clear(Lifespan, AddressRange, boolean, TaskMonitor)` this part
    /// implements (declared on `TraceBaseDefinedUnitsView`).
    fn clear(
        &mut self,
        span: Lifespan,
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

/// Placeholder for `ghidra.trace.database.address.DBTraceOverlaySpaceAdapter`, referenced by
/// [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)
/// before the real port is available. That trait's `getOverlaySpaceAdapter()` (mirroring the
/// single-method `DecodesAddresses` interface it implements) only ever passes this type around
/// opaquely; no members are needed yet.
///
/// Grown to add the three overlay-address-space management methods
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// `create_overlay_address_space`/`get_or_create_overlay_address_space`/
/// `delete_overlay_address_space` defaults delegate straight through to (the `overlayAdapter`
/// field DBTraceMemoryManager's Java constructor is handed). All three default to panicking,
/// matching this module's other grown-but-not-yet-implemented placeholders (see
/// [`TracePlatform::get_trace`]'s docs for the same reasoning), so the existing marker
/// (`impl DBTraceOverlaySpaceAdapter for T {}`) implementor keeps compiling unchanged.
pub trait DBTraceOverlaySpaceAdapter: Send + Sync {
    /// Create a new address space with the given name based on `base`. Mirrors
    /// `createOverlayAddressSpace(String, AddressSpace)`.
    fn create_overlay_address_space(
        &self,
        _name: &str,
        _base: &Arc<AddressSpace>,
    ) -> Result<Arc<AddressSpace>, DuplicateNameException> {
        unimplemented!("DBTraceOverlaySpaceAdapter::create_overlay_address_space placeholder not overridden")
    }

    /// Get or create an overlay address space over `base`. Mirrors
    /// `getOrCreateOverlayAddressSpace(String, AddressSpace)`.
    fn get_or_create_overlay_address_space(
        &self,
        _name: &str,
        _base: &Arc<AddressSpace>,
    ) -> Option<Arc<AddressSpace>> {
        unimplemented!("DBTraceOverlaySpaceAdapter::get_or_create_overlay_address_space placeholder not overridden")
    }

    /// Delete the named overlay address space. Mirrors `deleteOverlayAddressSpace(String)`.
    fn delete_overlay_address_space(&self, _name: &str) {
        unimplemented!("DBTraceOverlaySpaceAdapter::delete_overlay_address_space placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.program.DBTraceProgramView`, referenced by
/// [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)
/// before the real port is available. That trait's `getProgram()` only ever passes this type
/// around opaquely; no members are needed yet.
pub trait DBTraceProgramView: Send + Sync {}

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

/// Placeholder for `ghidra.trace.database.memory.DBTraceMemorySpace`, referenced (as the
/// per-address-space delegate `M` of its
/// [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager))
/// by
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)
/// before the real port is available.
///
/// The real Java class implements the full `InternalTraceMemoryOperations` surface (register
/// overloads and all) plus DB-tree bookkeeping (`checkStateMapIntegrity`, `paint`, `getDepth`,
/// ...). `DBTraceMemoryManager` only ever calls this trimmed set of members on it -- the
/// non-register `TraceMemoryOperations` primitives it delegates each per-space, plain-address
/// call to -- so only those are stubbed here, `&self`-receiver throughout since the manager's
/// `delegateXxx` helpers hand out this type by value (`Arc<dyn DBTraceMemorySpace>`), not by
/// exclusive reference.
pub trait DBTraceMemorySpace: Send + Sync {
    /// Mirrors `setState(long, AddressRange, TraceMemoryState)`.
    fn set_state(&self, snap: i64, range: &AddressRange, state: TraceMemoryState);

    /// Mirrors `getState(long, Address)`.
    fn get_state(&self, snap: i64, address: &Address) -> TraceMemoryState;

    /// Mirrors `getViewState(long, Address)`.
    fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState);

    /// Mirrors `getMostRecentStateEntry(long, Address)`.
    fn get_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getViewMostRecentStateEntry(long, Address)`.
    fn get_view_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getViewMostRecentStateEntry(long, AddressRange, Predicate<TraceMemoryState>)`.
    fn get_view_most_recent_state_entry_where(
        &self,
        snap: i64,
        range: &AddressRange,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors the two-argument `getAddressesWithState(long, Predicate<TraceMemoryState>)`.
    /// (The three-argument `getAddressesWithState(Lifespan, AddressSetView,
    /// Predicate<TraceMemoryState>)` and the lifespan-only two-argument overload are not modeled
    /// here; see
    /// [`DBTraceMemoryManager::get_addresses_with_state_in`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager::get_addresses_with_state_in)'s
    /// docs.)
    fn get_addresses_with_state(
        &self,
        snap: i64,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors `getStates(long, AddressRange)`.
    fn get_states(
        &self,
        snap: i64,
        range: &AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getMostRecentStates(TraceAddressSnapRange)`.
    fn get_most_recent_states(
        &self,
        within: &dyn TraceAddressSnapRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `putBytes(long, Address, ByteBuffer)`.
    fn put_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `getBytes(long, Address, ByteBuffer)`.
    fn get_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `getViewBytes(long, Address, ByteBuffer)`.
    fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `removeBytes(long, Address, int)`.
    fn remove_bytes(&self, snap: i64, start: &Address, len: i32);

    /// Mirrors `findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)`.
    /// `mask` is `None` for Java's `null` ("match all bytes exactly").
    fn find_bytes(
        &self,
        snap: i64,
        range: &AddressRange,
        data: &[u8],
        mask: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>;

    /// Mirrors `getBufferAt(long, Address, ByteOrder)`. `big_endian` stands in for the Java
    /// `ByteOrder`, the same simplification
    /// [`MemBuffer::is_big_endian`](crate::program::model::mem::MemBuffer::is_big_endian) already
    /// established for byte-order parameters.
    fn get_buffer_at(&self, snap: i64, start: &Address, big_endian: bool) -> Box<dyn MemBuffer>;

    /// Mirrors `getSnapOfMostRecentChangeToBlock(long, Address)`.
    fn get_snap_of_most_recent_change_to_block(&self, snap: i64, address: &Address) -> Option<i64>;

    /// Mirrors `pack()`.
    fn pack(&self);
}

/// Placeholder for `ghidra.trace.database.context.DBTraceRegisterContextSpace`, referenced (as the
/// per-address-space delegate `M` of its
/// [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager))
/// by
/// [`DBTraceRegisterContextManager`](crate::trace::database::context::db_trace_register_context_manager::DBTraceRegisterContextManager)
/// before the real port is available.
///
/// The real Java class implements the model-level `TraceRegisterContextSpace` interface (already
/// ported as [`TraceRegisterContextSpace`](crate::trace::model::context::trace_register_context_space::TraceRegisterContextSpace),
/// whose mutating members take `&mut self`) plus DB-record-backed bookkeeping. This manager hands
/// the delegate out by value as `Arc<dyn DBTraceRegisterContextSpace>` (matching
/// [`DBTraceMemorySpace`]'s established convention for `Arc`-shared, lock-synchronized DB
/// delegates), so its members are `&self`-receiver throughout rather than reusing the `&mut self`
/// model trait. `get_value_with_default` is modeled on the concrete class's package-private
/// `getValueWithDefault(Language, Register, long, Address hostAddress, Address langAddress)`
/// helper (already resolved to a host address), which is what
/// `DBTraceRegisterContextManager.getValueWithDefault` actually calls -- not the model-level,
/// platform-taking overload -- since the manager itself is the one that maps guest to host and
/// resolves the language via `TracePlatform`.
pub trait DBTraceRegisterContextSpace: Send + Sync {
    /// The address space this register-context space is bound to. Mirrors
    /// `DBTraceRegisterContextSpace.getAddressSpace()`.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `setValue(Language, RegisterValue, Lifespan, AddressRange)`.
    fn set_value(
        &self,
        language: &dyn Language,
        value: &dyn ProgramRegisterValue,
        lifespan: Lifespan,
        range: &AddressRange,
    );

    /// Mirrors `removeValue(Language, Register, Lifespan, AddressRange)`.
    fn remove_value(
        &self,
        language: &dyn Language,
        register: &Register,
        span: Lifespan,
        range: &AddressRange,
    );

    /// Mirrors `getValue(Language, Register, long, Address)`.
    fn get_value(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn ProgramRegisterValue>>;

    /// Mirrors `getEntry(Language, Register, long, Address)`.
    fn get_entry(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn ProgramRegisterValue>)>;

    /// Mirrors the package-private `getValueWithDefault(Language, Register, long, Address
    /// hostAddress, Address langAddress)` helper, called by
    /// `DBTraceRegisterContextManager.getValueWithDefault(TracePlatform, Register, long, Address)`
    /// after it has already mapped the guest address to `host_address` and resolved `language`
    /// from the platform.
    fn get_value_with_default(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        host_address: &Address,
        guest_address: &Address,
    ) -> Option<Box<dyn ProgramRegisterValue>>;

    /// Mirrors `getRegisterValueAddressRanges(Language, Register, long, AddressRange)`.
    fn get_register_value_address_ranges_within(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors the all-space overload `getRegisterValueAddressRanges(Language, Register, long)`.
    fn get_register_value_address_ranges(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors `hasRegisterValueInAddressRange(Language, Register, long, AddressRange)`.
    fn has_register_value_in_address_range(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> bool;

    /// Mirrors the all-space overload `hasRegisterValue(Language, Register, long)`.
    fn has_register_value(&self, language: &dyn Language, register: &Register, snap: i64) -> bool;

    /// Mirrors `clear(Lifespan, AddressRange)`.
    fn clear(&self, span: Lifespan, range: &AddressRange);
}

