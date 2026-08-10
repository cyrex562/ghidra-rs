//! Port of `ghidra.trace.database.listing.DBTraceDataAdapter`.
//!
//! A base interface for implementations of
//! [`TraceData`](crate::trace::model::listing::trace_data::TraceData): a mixin usable on both
//! whole data units and data components (e.g. fields of a struct data unit).
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! Two adaptations from a literal translation, both forced by Rust's object-safety rules (the
//! task requires `Box<dyn DBTraceDataAdapter>` to be constructible):
//!
//! - The Java interface also extends `DataAdapterFromSettings`. That trait's
//!   `getSettingsDefinition(Class<T>)` was ported as a generic method
//!   (`get_settings_definition<F>`) with no `Self: Sized` bound, which makes
//!   [`DataAdapterFromSettings`](crate::trace::util::data_adapter_from_settings::DataAdapterFromSettings)
//!   itself not dyn-compatible (confirmed by attempting to compile `&dyn DataAdapterFromSettings`).
//!   Since any supertrait's dyn-incompatibility propagates to the whole hierarchy, that trait is
//!   *not* declared as a Rust supertrait here. Implementors that need its
//!   `get_settings_definition`/`has_mutability`/`is_constant`/`is_writable`/`is_volatile` helpers
//!   should implement `DataAdapterFromSettings` separately, mirroring Java's multiple interface
//!   inheritance; this trait does not re-declare `getSettingsDefinition(Class<T>)` or
//!   `hasMutability(int)` (both wrapped a trace read lock around the `DataAdapterFromSettings`
//!   default in Java), since neither has an object-safe counterpart to wrap.
//! - `getRoot()` and `getPrimitiveAt(int)` are declared abstract in Java purely to covariantly
//!   narrow the inherited `Data.getRoot()`/`Data.getPrimitiveAt(int)` return type from `Data` to
//!   `DBTraceDataAdapter`. Rust has no covariant trait-method override (the same issue documented
//!   on [`TraceData`]/[`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit)),
//!   so they are not re-declared here either: implementations of the inherited `Data::get_root`
//!   and `Data::get_primitive_at` (via the `TraceData` supertrait) must return a
//!   `DBTraceDataAdapter`, boxed as `Box<dyn Data>`.
//!
//! Several remaining default methods override a supertrait method of the exact same name (Java's
//! `@Override default ...` on an inherited abstract method): `get_value_references` (overrides
//! [`DataAdapterMinimal`]'s default), `add_value_reference`/`remove_value_reference`/`is_change_allowed`
//! (override [`Data`]/[`Settings`]'s abstract members), and `set_long`/`get_long`/`set_string`/
//! `get_string`/`set_value`/`get_value`/`clear_setting`/`clear_all_settings`/`get_names`/`is_empty`
//! (override [`Settings`]'s members). Rust does not support re-overriding an inherited trait
//! method: declaring a method of the same name in this trait instead adds a *second*, separately
//! dispatched method reachable under the same name, exactly as
//! [`DBTraceDefinedUnitsView`](crate::trace::database::listing::db_trace_defined_units_view::DBTraceDefinedUnitsView)
//! already established for `clear`. A type implementing both the overridden supertrait and this
//! trait must disambiguate calls with UFCS (e.g. `DBTraceDataAdapter::set_long(&mut x, ..)`); a
//! `Settings`/`Data`/`DataAdapterMinimal` impl should simply delegate its body to the
//! `DBTraceDataAdapter` version.

use std::any::Any;
use std::sync::Arc;

use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::address::Address;
use crate::program::model::mem::MemBuffer;
use crate::program::model::symbol::{RefType, Reference, SourceType};
use crate::trace::database::data::db_trace_data_settings_operations::{
    DBTraceDataSettingsOperations, SettingsValue,
};
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
use crate::trace::model::listing::trace_data::TraceData;
use crate::trace::seam_stubs::{DBTraceCodeUnitAdapter, DataAdapterFromDataType, TraceChangeRecord};
use crate::trace::util::data_adapter_minimal::{DataAdapterMinimal, DATA_OP_INDEX};

// `Settings::get_default_settings` and `TraceChangeManager::set_changed` are called below via
// `self`/a `&mut dyn TraceChangeManager` receiver whose concrete trait is already fixed by the
// call site (a transitively-implied supertrait bound, and a `dyn` value, respectively), so no
// `use` of those traits is needed in this module -- only in the `tests` module below, which names
// them directly in `impl Settings for ..`/`impl TraceChangeManager for ..` blocks.

/// Opaque event fired via [`TraceChangeManager::set_changed`] to mirror
/// `TraceEvents.CODE_DATA_SETTINGS_CHANGED`.
///
/// `TraceChangeRecord` is (per its own placeholder docs) a bare marker never inspected by its own
/// getters, so the event kind and payload (`TraceEvents.CODE_DATA_SETTINGS_CHANGED`, the affected
/// address space, and this unit's bounds in the Java source) carry no representable information
/// yet; this unit struct simply stands in for "a settings-changed notification occurred."
struct SettingsChangedRecord;
impl TraceChangeRecord for SettingsChangedRecord {}

/// Converts a `Settings::set_value`-style `Box<dyn Any>` into a [`SettingsValue`], mirroring the
/// Java static `DBTraceDataSettingsOperations.assertKnownType(Object)` check that validates the
/// value is a `Long`, `String`, or `byte[]`. Returns `None` for any other type, where Java would
/// have thrown `IllegalArgumentException`.
fn any_to_settings_value(value: Box<dyn Any>) -> Option<SettingsValue> {
    let value = match value.downcast::<i64>() {
        Ok(v) => return Some(SettingsValue::Long(*v)),
        Err(v) => v,
    };
    let value = match value.downcast::<String>() {
        Ok(v) => return Some(SettingsValue::Str(*v)),
        Err(v) => v,
    };
    match value.downcast::<Vec<u8>>() {
        Ok(v) => Some(SettingsValue::Bytes(*v)),
        Err(_) => None,
    }
}

/// Converts a [`SettingsValue`] back into a `Settings::get_value`-style `Box<dyn Any>`.
fn settings_value_to_any(value: SettingsValue) -> Box<dyn Any> {
    match value {
        SettingsValue::Long(v) => Box::new(v),
        SettingsValue::Str(v) => Box::new(v),
        SettingsValue::Bytes(v) => Box::new(v),
    }
}

/// A base interface for implementations of [`TraceData`].
///
/// Port of `ghidra.trace.database.listing.DBTraceDataAdapter`.
///
/// This behaves somewhat like a mixin, allowing it to be used on data units as well as data
/// components, e.g., fields of a struct data unit.
///
/// See the module documentation for the object-safety-driven deviations from a literal
/// translation.
pub trait DBTraceDataAdapter:
    DBTraceCodeUnitAdapter + DataAdapterMinimal + DataAdapterFromDataType + TraceData
{
    /// Get the same space from the internal settings adapter.
    ///
    /// Mirrors `DBTraceDataAdapter.getSettingsSpace(boolean)`. Returns `None` if the space does
    /// not exist (and `create_if_absent` is `false`).
    fn get_settings_space(&self, create_if_absent: bool) -> Option<Box<dyn DBTraceDataSettingsOperations>>;

    /// Fires the `TraceEvents.CODE_DATA_SETTINGS_CHANGED` notification through the owning
    /// trace's change manager.
    ///
    /// Reached via [`DBTraceCodeUnitAdapter::trace_change_manager`] rather than
    /// `getTrace().setChanged(...)`; see that placeholder's docs for why.
    fn notify_settings_changed(&mut self) {
        DBTraceCodeUnitAdapter::trace_change_manager(self).set_changed(Box::new(SettingsChangedRecord));
    }

    /// Overrides [`DataAdapterMinimal`]'s default to acquire the trace's read lock first.
    ///
    /// Mirrors `DBTraceDataAdapter.getValueReferences()`. The Java override additionally casts
    /// the result to `TraceReference[]`; that cast is not reproduced (see the module
    /// documentation on [`TraceData`] for why trace-specific reference types cannot be recovered
    /// from a `Reference` trait object), so implementations of the underlying
    /// `get_operand_references` this delegates to are expected to already return
    /// `TraceReference`s boxed as the base `Reference` type.
    fn get_value_references(&self) -> Vec<Arc<dyn Reference>> {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        DataAdapterMinimal::get_value_references(self)
    }

    /// Adds a memory reference from this unit's address to `ref_addr`, mirroring
    /// `DBTraceDataAdapter.addValueReference(Address, RefType)`.
    fn add_value_reference(&mut self, ref_addr: Address, ref_type: RefType) {
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_write();
        let mut reference_manager = trace.get_reference_manager();
        reference_manager.add_memory_reference_to_address(
            lifespan,
            &address,
            &ref_addr,
            ref_type,
            SourceType::UserDefined,
            DATA_OP_INDEX,
        );
    }

    /// Removes the memory reference from this unit's address to `ref_addr`, if any. Mirrors
    /// `DBTraceDataAdapter.removeValueReference(Address)`.
    fn remove_value_reference(&mut self, ref_addr: Address) {
        let snap = TraceCodeUnit::get_start_snap(self);
        let address = MemBuffer::get_address(self);
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_write();
        let reference_manager = trace.get_reference_manager();
        if let Some(mut reference) =
            reference_manager.get_reference_to_address(snap, &address, &ref_addr, DATA_OP_INDEX)
        {
            reference.delete();
        }
    }

    /// Determines whether a settings change is allowed: never for a type-def settings
    /// definition, otherwise whatever the default settings permit. Mirrors
    /// `DBTraceDataAdapter.isChangeAllowed(SettingsDefinition)`.
    ///
    /// `settings_definition.is_type_def_settings_definition()` stands in for Java's `instanceof
    /// TypeDefSettingsDefinition` check (see
    /// [`SettingsDefinition`]'s own docs for that substitution). Java's
    /// `getDefaultSettings().isChangeAllowed(...)` has no null guard (an NPE if there are no
    /// default settings); this instead defaults to permitting the change when there are none.
    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        if settings_definition.is_type_def_settings_definition() {
            return false;
        }
        match self.get_default_settings() {
            Some(defaults) => defaults.is_change_allowed(settings_definition),
            None => true,
        }
    }

    /// Sets a long-valued setting, notifying the trace's change manager. Mirrors
    /// `DBTraceDataAdapter.setLong(String, long)`.
    fn set_long(&mut self, name: &str, value: i64) {
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        {
            let trace = TraceCodeUnit::get_trace(self);
            let _hold = trace.lock_write();
            if let Some(mut space) = self.get_settings_space(true) {
                space.set_long(lifespan, address, name, value);
            }
        }
        self.notify_settings_changed();
    }

    /// Gets a long-valued setting, falling back to the default settings. Mirrors
    /// `DBTraceDataAdapter.getLong(String)`.
    fn get_long(&self, name: &str) -> Option<i64> {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        if let Some(space) = self.get_settings_space(false) {
            if let Some(value) = space.get_long(TraceCodeUnit::get_start_snap(self), MemBuffer::get_address(self), name) {
                return Some(value);
            }
        }
        self.get_default_settings().and_then(|defaults| defaults.get_long(name))
    }

    /// Sets a string-valued setting, notifying the trace's change manager. Mirrors
    /// `DBTraceDataAdapter.setString(String, String)`.
    fn set_string(&mut self, name: &str, value: &str) {
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        {
            let trace = TraceCodeUnit::get_trace(self);
            let _hold = trace.lock_write();
            if let Some(mut space) = self.get_settings_space(true) {
                space.set_string(lifespan, address, name, value.to_string());
            }
        }
        self.notify_settings_changed();
    }

    /// Gets a string-valued setting, falling back to the default settings. Mirrors
    /// `DBTraceDataAdapter.getString(String)`.
    fn get_string(&self, name: &str) -> Option<String> {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        if let Some(space) = self.get_settings_space(false) {
            if let Some(value) = space.get_string(TraceCodeUnit::get_start_snap(self), MemBuffer::get_address(self), name) {
                return Some(value);
            }
        }
        self.get_default_settings().and_then(|defaults| defaults.get_string(name))
    }

    /// Sets an arbitrary-valued setting, notifying the trace's change manager. Mirrors
    /// `DBTraceDataAdapter.setValue(String, Object)`.
    ///
    /// Values outside [`SettingsValue`]'s domain (not a `Long`, `String`, or `byte[]`) are
    /// silently ignored; see [`any_to_settings_value`].
    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        let Some(settings_value) = any_to_settings_value(value) else {
            return;
        };
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        {
            let trace = TraceCodeUnit::get_trace(self);
            let _hold = trace.lock_write();
            if let Some(mut space) = self.get_settings_space(true) {
                space.set_value(lifespan, address, name, settings_value);
            }
        }
        self.notify_settings_changed();
    }

    /// Gets an arbitrary-valued setting, falling back to the default settings. Mirrors
    /// `DBTraceDataAdapter.getValue(String)`.
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        if let Some(space) = self.get_settings_space(false) {
            if let Some(value) = space.get_value(TraceCodeUnit::get_start_snap(self), MemBuffer::get_address(self), name) {
                return Some(settings_value_to_any(value));
            }
        }
        self.get_default_settings().and_then(|defaults| defaults.get_value(name))
    }

    /// Clears a single setting, notifying the trace's change manager if a settings space
    /// existed. Mirrors `DBTraceDataAdapter.clearSetting(String)`.
    fn clear_setting(&mut self, name: &str) {
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        let cleared = {
            let trace = TraceCodeUnit::get_trace(self);
            let _hold = trace.lock_write();
            match self.get_settings_space(false) {
                Some(mut space) => {
                    space.clear_setting(lifespan, address, Some(name));
                    true
                }
                None => false,
            }
        };
        if cleared {
            self.notify_settings_changed();
        }
    }

    /// Clears every setting, notifying the trace's change manager if a settings space existed.
    /// Mirrors `DBTraceDataAdapter.clearAllSettings()`.
    fn clear_all_settings(&mut self) {
        let lifespan = TraceCodeUnit::get_lifespan(self);
        let address = MemBuffer::get_address(self);
        let cleared = {
            let trace = TraceCodeUnit::get_trace(self);
            let _hold = trace.lock_write();
            match self.get_settings_space(false) {
                Some(mut space) => {
                    space.clear_setting(lifespan, address, None);
                    true
                }
                None => false,
            }
        };
        if cleared {
            self.notify_settings_changed();
        }
    }

    /// Lists the names of all stored settings. Mirrors `DBTraceDataAdapter.getNames()`.
    fn get_names(&self) -> Vec<String> {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        match self.get_settings_space(false) {
            Some(space) => space.get_setting_names(TraceCodeUnit::get_lifespan(self), MemBuffer::get_address(self)),
            None => Vec::new(),
        }
    }

    /// Returns whether no settings are stored (ignoring default settings). Mirrors
    /// `DBTraceDataAdapter.isEmpty()`.
    fn is_empty(&self) -> bool {
        let trace = TraceCodeUnit::get_trace(self);
        let _hold = trace.lock_read();
        match self.get_settings_space(false) {
            Some(space) => space.is_empty_at(TraceCodeUnit::get_lifespan(self), MemBuffer::get_address(self)),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::Language;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, ReferenceIterator, SourceType as SymSourceType, Symbol,
    };
    use crate::docking::settings::settings::Settings;
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType as StubRefType, Reference as StubReference};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TracePlatform, TraceThread};
    use crate::trace::util::trace_change_manager::TraceChangeManager;
    use crate::util::lock_hold::Lock;
    use std::any::TypeId;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockStubReference;
    impl StubReference for MockStubReference {}

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockReferenceIterator;
    impl Iterator for MockReferenceIterator {
        type Item = Arc<dyn Reference>;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    impl ReferenceIterator for MockReferenceIterator {}

    /// A reference standing in for a `TraceReference` boxed as the base `Reference` type, since
    /// (per this trait's module docs) trace-specific reference types cannot be recovered from a
    /// `Reference` trait object.
    struct MockValueReference {
        from: Address,
        to: Address,
    }

    impl Reference for MockValueReference {
        fn from_address(&self) -> Address {
            self.from.clone()
        }
        fn to_address(&self) -> Address {
            self.to.clone()
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            -1
        }
        fn reference_type(&self) -> SymRefType {
            SymRefType::Data
        }
        fn operand_index(&self) -> i32 {
            DATA_OP_INDEX
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SymSourceType {
            SymSourceType::UserDefined
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A `Lock` that counts how many times it is held, so tests can prove the trace's read/write
    /// lock was actually acquired around a default method's body (not just that the body ran).
    /// Uses `AtomicI32` rather than `Cell<i32>` since `Lock` (transitively, via `MemBuffer`, a
    /// `Reference` supertrait) requires `Send + Sync`.
    #[derive(Default)]
    struct RecordingLock {
        depth: std::sync::atomic::AtomicI32,
        max_depth: std::sync::atomic::AtomicI32,
    }

    impl Lock for RecordingLock {
        fn lock(&self) {
            use std::sync::atomic::Ordering;
            let depth = self.depth.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_depth.fetch_max(depth, Ordering::SeqCst);
        }
        fn unlock(&self) {
            self.depth.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct MockChangeManager {
        notifications: i32,
    }

    impl TraceChangeManager for MockChangeManager {
        fn set_changed(&mut self, _event: Box<dyn TraceChangeRecord>) {
            self.notifications += 1;
        }
    }

    #[derive(Clone)]
    struct MockTrace {
        lock: Arc<RecordingLock>,
    }

    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(&self) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(&self) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(&mut self, _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(&mut self, _listener: &dyn crate::trace::model::trace::TraceProgramViewListener) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn Lock> {
            crate::util::lock_hold::LockHold::lock(&*self.lock)
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn Lock> {
            crate::util::lock_hold::LockHold::lock(&*self.lock)
        }
    }

    struct DefaultSettingsMock {
        allow: bool,
    }

    impl Settings for DefaultSettingsMock {
        fn is_change_allowed(&self, _settings_definition: &dyn SettingsDefinition) -> bool {
            self.allow
        }
    }

    struct MockTypeDefCheckSettingsDefinition {
        is_typedef: bool,
    }

    impl SettingsDefinition for MockTypeDefCheckSettingsDefinition {
        fn is_type_def_settings_definition(&self) -> bool {
            self.is_typedef
        }
    }

    struct MockData {
        address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
        deleted: bool,
        operand_references: Vec<Arc<dyn Reference>>,
        default_settings_allow: bool,
        change_manager: MockChangeManager,
        trace: MockTrace,
    }

    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl PropertySet for MockData {}

    impl Settings for MockData {
        fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
            Some(Box::new(DefaultSettingsMock { allow: self.default_settings_allow }))
        }
    }

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "db".to_string()
        }
        fn get_comment(&self, _comment_type: crate::program::model::listing::CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: crate::program::model::listing::CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x00; self.length as usize])
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x00);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>> {
            if index == DATA_OP_INDEX {
                self.operand_references.clone()
            } else {
                Vec::new()
            }
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SymSourceType, _ref_type: SymRefType) {}
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SymSourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn StubReference>> {
            vec![Box::new(MockStubReference)]
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn StubRefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "mock".to_string()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            unimplemented!("not exercised by these tests")
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    impl TraceCodeUnit for MockData {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(self.trace.clone())
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by these tests")
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by these tests")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), addr(self.address.offset() + self.length as i64 - 1))
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }
        fn set_end_snap(&mut self, end_snap: i64) {
            self.end_snap = end_snap;
        }
        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }
        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    impl TraceData for MockData {}
    impl DataAdapterMinimal for MockData {}
    impl DataAdapterFromDataType for MockData {}

    impl DBTraceCodeUnitAdapter for MockData {
        fn trace_change_manager(&mut self) -> &mut dyn TraceChangeManager {
            &mut self.change_manager
        }
    }

    impl DBTraceDataAdapter for MockData {
        fn get_settings_space(&self, _create_if_absent: bool) -> Option<Box<dyn DBTraceDataSettingsOperations>> {
            unimplemented!("not exercised by these tests")
        }
    }


    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_data(default_settings_allow: bool) -> MockData {
        MockData {
            address: addr(0x400),
            length: 4,
            start_snap: 0,
            end_snap: 10,
            deleted: false,
            operand_references: Vec::new(),
            default_settings_allow,
            change_manager: MockChangeManager { notifications: 0 },
            trace: MockTrace { lock: Arc::new(RecordingLock::default()) },
        }
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn DBTraceDataAdapter) {}
        assert_object_safe(&make_data(true));
    }

    #[test]
    fn typedef_setting_change_is_never_allowed_even_if_defaults_would_allow_it() {
        let data = make_data(true);
        let def = MockTypeDefCheckSettingsDefinition { is_typedef: true };
        assert!(!DBTraceDataAdapter::is_change_allowed(&data, &def));
    }

    #[test]
    fn non_typedef_setting_change_delegates_to_default_settings() {
        let def = MockTypeDefCheckSettingsDefinition { is_typedef: false };

        let disallowing = make_data(false);
        assert!(!DBTraceDataAdapter::is_change_allowed(&disallowing, &def));

        let allowing = make_data(true);
        assert!(DBTraceDataAdapter::is_change_allowed(&allowing, &def));
    }

    #[test]
    fn get_value_references_acquires_the_trace_read_lock_and_delegates() {
        let mut data = make_data(true);
        data.operand_references = vec![Arc::new(MockValueReference { from: addr(0x400), to: addr(0x800) })];
        let lock = Arc::clone(&data.trace.lock);

        let refs = DBTraceDataAdapter::get_value_references(&data);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_address(), addr(0x800));
        // The lock was acquired (and released) exactly once around the call.
        assert_eq!(lock.max_depth.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(lock.depth.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
