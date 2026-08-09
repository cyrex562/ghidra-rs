//! Port of `ghidra.trace.database.listing.AbstractDBTraceDataComponent`.
//!
//! An abstract implementation of a [`TraceData`](crate::trace::model::listing::trace_data::TraceData)
//! for a data component, i.e. a field of a struct or an element of an array.
//!
//! These are not backed directly by a table: the root data unit, along with its type, is stored
//! in the table, and components are generated (possibly recursively) from it.
//!
//! The Java class carries 12 instance fields and has two in-repo subclasses
//! (`DBTraceDataArrayElementComponent`, `DBTraceDataCompositeFieldComponent`, both not yet
//! ported), so per this crate's abstract-base shape rule it is split in two:
//! [`AbstractDBTraceDataComponentBase`] holds the fields and every method the Java class actually
//! gives a body to; [`AbstractDBTraceDataComponent`] declares only `getFieldSyntax()`, the one
//! method the Java source marks `abstract`. A future concrete subclass is expected to embed a
//! `AbstractDBTraceDataComponentBase`, implement `AbstractDBTraceDataComponent` for its own field
//! syntax, and implement the various `Data`/`CodeUnit`/`MemBuffer`/`Settings`/`TraceCodeUnit`
//! surface by delegating to this base's inherent methods (mirroring how the Java class leaves the
//! rest of `DBTraceDefinedDataAdapter` abstract).
//!
//! Several adaptations, all forced by the same object-safety/covariance limits already documented
//! on sibling files in this package:
//! - `root`/`parent`/`data_type`/`base_data_type`/`default_settings` are `Arc`, not `Box`, so this
//!   base's own accessors (`get_root`/`get_parent`/`get_data_type`/`get_base_data_type`/
//!   `get_default_settings`) can return an owned handle from a `&self` receiver the way the Java
//!   getters return the (aliased, GC'd) field directly. `data_type`/`base_data_type` in particular
//!   mirror `DBTraceData.getBaseDataType(DataType)`'s aliasing: when `data_type` is not a typedef,
//!   Java's `baseDataType` field is `dataType` itself (the very same object); this port reproduces
//!   that by `Arc::clone`-ing rather than only "equal" data.
//! - `getTrace()` is declared to return the narrower `DBTrace`, and `root`'s Java static type
//!   (`DBTraceData`) has its own covariant override returning `DBTrace` too. Neither narrowing
//!   survives the port (see [`DBTraceData`]'s and
//!   [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit)'s
//!   docs for the same issue), so [`AbstractDBTraceDataComponentBase::get_trace`] returns the
//!   already-available `Box<dyn Trace>` (via `root`'s `TraceCodeUnit::get_trace`) instead of
//!   inventing a `DBTrace`-returning path this crate cannot currently supply.
//! - `getComponentPath()` locks `root.space.lock.writeLock()` directly, reaching into a
//!   package-private field of the concrete `DBTraceData` implementation that this port's
//!   `DBTraceData` trait does not expose. [`AbstractDBTraceDataComponentBase::get_component_path`]
//!   instead locks through `root.getTrace().lockWrite()`, the same trace-wide read/write lock
//!   [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)'s
//!   own default methods already use for equivalent synchronization.
//! - `doGetComponentCache()` sizes its lazy cache from `getNumComponents()`, itself a
//!   `DBTraceDefinedDataAdapter` default this crate does not reproduce (see that trait's own
//!   docs): it depends on `getBaseDataType()` `instanceof` checks against `Composite`/`Array`/
//!   `DynamicDataType`, none of which are downcastable from a `dyn DataType` without extra
//!   machinery. [`AbstractDBTraceDataComponentBase::do_get_component_cache`] therefore takes the
//!   component count as a parameter, to be supplied by whatever concrete `Data` impl eventually
//!   computes it.
//! - `toString()` delegates to `DataAdapterFromDataType.doToString()`, a default method this crate
//!   has not grown (see that placeholder trait's docs) since it needs `this` to already be a full
//!   `MemBuffer` + `Settings` -- which this abstract base, on its own, is not (`getByte`/
//!   `isBigEndian` are among the members the Java class leaves for its concrete subclasses).
//!   [`AbstractDBTraceDataComponentBase::to_string`] reproduces `doToString`'s formula directly
//!   (mnemonic, then default value representation) against a private `ComponentMemBuffer` adapter
//!   built from the members this base *does* own (`address`, and the `getBytes` override it
//!   reproduces below).

use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::Language;
use crate::program::model::listing::data::Data;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};
use crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations;
use crate::trace::database::listing::db_trace_data::DBTraceData;
use crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{DBTraceDefinedDataAdapter, TracePlatform, TraceThread};

/// The one abstract member of `AbstractDBTraceDataComponent`: the syntax (e.g. `.fieldName` or
/// `[index]`) this component contributes to its parent's path name.
///
/// Port of `ghidra.trace.database.listing.AbstractDBTraceDataComponent`'s abstract surface.
///
/// See the module documentation for why the class's state and concrete methods live on
/// [`AbstractDBTraceDataComponentBase`] instead of here.
pub trait AbstractDBTraceDataComponent {
    /// Mirrors the abstract `AbstractDBTraceDataComponent.getFieldSyntax()`.
    fn get_field_syntax(&self) -> String;
}

/// If `data_type` is a typedef, its base data type; otherwise `data_type` itself (`Arc::clone`d,
/// reproducing the Java field aliasing described in the module documentation).
///
/// Mirrors `DBTraceData.getBaseDataType(DataType)`, called from the constructor.
fn base_data_type_of(data_type: &Arc<dyn DataType>) -> Arc<dyn DataType> {
    if data_type.is_typedef() {
        if let Some(base) = data_type.typedef_base_data_type() {
            return Arc::from(base);
        }
    }
    Arc::clone(data_type)
}

/// A `MemBuffer` over a data component's own bytes, used only to compute
/// [`AbstractDBTraceDataComponentBase::to_string`]'s default value representation.
///
/// Owns its bytes (read once, up front) rather than borrowing the base and reading lazily: unlike
/// [`Data`]/[`Settings`], [`MemBuffer`] itself requires `Send + Sync`, which the base's `Arc<dyn
/// DataType>`/`Arc<dyn Settings>` fields do not guarantee. An owned snapshot sidesteps that
/// without imposing a `Send + Sync` bound on every `DataType`/`Settings` implementor this crate
/// has.
struct ComponentMemBuffer {
    address: Address,
    bytes: Vec<u8>,
    big_endian: bool,
}

impl MemBuffer for ComponentMemBuffer {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.bytes
            .get(offset as usize)
            .copied()
            .ok_or_else(|| MemoryAccessException::new("could not read component byte"))
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        let start = offset as usize;
        let n = buf.len().min(self.bytes.len().saturating_sub(start));
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        n
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

/// The shared state and concrete behavior of `AbstractDBTraceDataComponent`.
///
/// Port of `ghidra.trace.database.listing.AbstractDBTraceDataComponent`'s fields and
/// non-abstract methods.
///
/// See the module documentation for the shape split and its object-safety-driven deviations from
/// a literal translation.
pub struct AbstractDBTraceDataComponentBase {
    /// The root data unit. Mirrors the constructor-injected `root` field.
    pub root: Arc<dyn DBTraceData>,
    /// The parent component, possibly the root itself. Mirrors the constructor-injected `parent`
    /// field.
    pub parent: Arc<dyn DBTraceDefinedDataAdapter>,
    /// The index of this component in its parent. Mirrors the constructor-injected `index` field.
    pub index: i32,
    /// The minimum address of this component. Mirrors the constructor-injected `address` field.
    pub address: Address,
    /// The data type of this component. Mirrors the constructor-injected `dataType` field.
    pub data_type: Arc<dyn DataType>,
    /// The length of this component, in bytes. Mirrors the constructor-injected `length` field.
    pub length: i32,
    /// This component's depth below the root (the root itself is level 0). Mirrors the
    /// `level` field, computed as `parent.getComponentLevel() + 1`.
    pub level: i32,
    /// `data_type`, with typedefs unwrapped. Mirrors the `baseDataType` field.
    pub base_data_type: Arc<dyn DataType>,
    /// The maximum (inclusive) address of this component. Mirrors the `maxAddress` field.
    pub max_address: Address,
    /// `data_type`'s default settings. Mirrors the `defaultSettings` field.
    pub default_settings: Arc<dyn Settings>,

    /// Lazily-computed, then cached, root-to-self path of component indices. Mirrors the `path`
    /// field; `Mutex`-wrapped since Java populates it under a lock from a `&self` (non-`&mut
    /// self`) method.
    path: Mutex<Option<Vec<i32>>>,
    /// Lazily-sized, then cached, per-instance component cache. Mirrors the `componentCache`
    /// field; empty means "not yet sized" (Java's `null`), matching how
    /// [`Self::do_get_component_cache`] tells the two apart.
    component_cache: Mutex<Vec<Option<Box<dyn AbstractDBTraceDataComponent>>>>,
}

impl AbstractDBTraceDataComponentBase {
    /// Creates a data component.
    ///
    /// Mirrors the constructor
    /// `AbstractDBTraceDataComponent(DBTraceData, DBTraceDefinedDataAdapter, int, Address,
    /// DataType, int)`.
    pub fn new(
        root: Arc<dyn DBTraceData>,
        parent: Arc<dyn DBTraceDefinedDataAdapter>,
        index: i32,
        address: Address,
        data_type: Arc<dyn DataType>,
        length: i32,
    ) -> Self {
        let level = parent.get_component_level() + 1;
        let base_data_type = base_data_type_of(&data_type);
        // NOTE: max address of root will have already overflowed if that were a concern here.
        let max_address = address
            .add(length as i64 - 1)
            .expect("component address should not overflow its address space");
        let default_settings: Arc<dyn Settings> = Arc::from(data_type.get_default_settings());

        AbstractDBTraceDataComponentBase {
            root,
            parent,
            index,
            address,
            data_type,
            length,
            level,
            base_data_type,
            max_address,
            default_settings,
            path: Mutex::new(None),
            component_cache: Mutex::new(Vec::new()),
        }
    }

    /// Mirrors `AbstractDBTraceDataComponent.toString()` (`doToString()`). See the module
    /// documentation for why this reproduces `DataAdapterFromDataType.doToString()`'s formula
    /// directly rather than delegating to it.
    pub fn to_string(&self) -> String {
        let mut bytes = vec![0u8; self.length.max(0) as usize];
        self.get_bytes(&mut bytes, 0);
        let buf = ComponentMemBuffer {
            address: self.address.clone(),
            bytes,
            big_endian: MemBuffer::is_big_endian(self.root.as_ref()),
        };
        let mut result = self.data_type.get_mnemonic(self.default_settings.as_ref());
        let representation =
            self.data_type
                .get_representation(&buf, self.default_settings.as_ref(), self.length);
        if !representation.is_empty() {
            result.push(' ');
            result.push_str(&representation);
        }
        result
    }

    /// Mirrors `AbstractDBTraceDataComponent.delete()`, which always refuses: a component cannot
    /// be deleted on its own.
    pub fn delete(&self) {
        panic!("Either delete the root, or modify the type");
    }

    /// Mirrors `AbstractDBTraceDataComponent.getTrace()`. See the module documentation for why
    /// this returns the generic `Trace` rather than the narrower `DBTrace`.
    pub fn get_trace(&self) -> Box<dyn Trace> {
        self.root.get_trace()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getThread()`.
    pub fn get_thread(&self) -> Box<dyn TraceThread> {
        self.root.get_thread()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getPlatform()`.
    pub fn get_platform(&self) -> Box<dyn TracePlatform> {
        self.root.get_platform()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getLanguage()`.
    pub fn get_language(&self) -> Box<dyn Language> {
        self.root.get_language()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getLifespan()`.
    pub fn get_lifespan(&self) -> Lifespan {
        self.root.get_lifespan()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getStartSnap()`.
    pub fn get_start_snap(&self) -> i64 {
        self.root.get_start_snap()
    }

    /// Mirrors `AbstractDBTraceDataComponent.setEndSnap(long)`, which always refuses: only the
    /// root unit's end-snap can be set.
    pub fn set_end_snap(&self, _end_snap: i64) {
        panic!("Set end-snap of root unit");
    }

    /// Mirrors `AbstractDBTraceDataComponent.getEndSnap()`.
    pub fn get_end_snap(&self) -> i64 {
        self.root.get_end_snap()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getAddress()`.
    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getMaxAddress()`.
    pub fn get_max_address(&self) -> Address {
        self.max_address.clone()
    }

    /// Mirrors `AbstractDBTraceDataComponent.getLength()`.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Mirrors `AbstractDBTraceDataComponent.getBytes(ByteBuffer, int)`: reads from the root,
    /// offset by this component's position within it.
    pub fn get_bytes(&self, buf: &mut [u8], address_offset: i32) -> usize {
        let root_address = MemBuffer::get_address(self.root.as_ref());
        let component_offset = self.address.subtract(&root_address) as i32;
        MemBuffer::get_bytes(self.root.as_ref(), buf, address_offset + component_offset)
    }

    /// Mirrors `AbstractDBTraceDataComponent.doGetComponentCache()`: lazily sizes and returns
    /// this component's cache of its own children. See the module documentation for why
    /// `num_components` -- `getNumComponents()` in Java -- is a parameter here rather than
    /// computed internally.
    pub fn do_get_component_cache(
        &self,
        num_components: i32,
    ) -> std::sync::MutexGuard<'_, Vec<Option<Box<dyn AbstractDBTraceDataComponent>>>> {
        let mut cache = self.component_cache.lock().unwrap();
        if cache.is_empty() && num_components > 0 {
            *cache = (0..num_components).map(|_| None).collect();
        }
        cache
    }

    /// Mirrors `AbstractDBTraceDataComponent.getDataType()`.
    pub fn get_data_type(&self) -> Arc<dyn DataType> {
        Arc::clone(&self.data_type)
    }

    /// Mirrors `AbstractDBTraceDataComponent.getBaseDataType()`.
    pub fn get_base_data_type(&self) -> Arc<dyn DataType> {
        Arc::clone(&self.base_data_type)
    }

    /// Mirrors `AbstractDBTraceDataComponent.getComponentPath()`: the root-to-self path of
    /// component indices, computed once and cached. See the module documentation for why this
    /// locks through `getTrace().lockWrite()` rather than `root.space.lock.writeLock()`.
    pub fn get_component_path(&self) -> Vec<i32> {
        let trace = self.root.get_trace();
        let _hold = trace.lock_write();

        {
            let cached = self.path.lock().unwrap();
            if let Some(existing) = cached.as_ref() {
                return existing.clone();
            }
        }

        let n = self.level as usize;
        let mut path = vec![0i32; n];
        if n >= 1 {
            path[n - 1] = self.index;
        }
        if n >= 2 {
            path[n - 2] = self.parent.get_component_index();
            let mut current: Option<Box<dyn Data>> = self.parent.get_parent();
            for i in (0..n - 2).rev() {
                let data = current.expect("component chain must reach the root");
                path[i] = data.get_component_index();
                current = data.get_parent();
            }
        }

        *self.path.lock().unwrap() = Some(path.clone());
        path
    }

    /// Mirrors `AbstractDBTraceDataComponent.getPathName()`: the full path name, including the
    /// root's symbol name.
    pub fn get_path_name(&self, field_syntax: &str) -> String {
        let mut builder = String::new();
        self.append_path_name(&mut builder, true, field_syntax);
        builder
    }

    /// Mirrors `AbstractDBTraceDataComponent.getComponentPathName()`: the path name relative to
    /// the root, omitting its symbol name.
    pub fn get_component_path_name(&self, field_syntax: &str) -> String {
        let mut builder = String::new();
        self.append_path_name(&mut builder, false, field_syntax);
        builder
    }

    /// Mirrors `AbstractDBTraceDataComponent.getPathName(StringBuilder, boolean)`: this
    /// component's parent path, followed by `field_syntax` (`getFieldSyntax()` in Java --
    /// supplied by the caller here since it lives on the [`AbstractDBTraceDataComponent`] trait,
    /// not on this base).
    pub fn append_path_name(&self, builder: &mut String, include_root_symbol: bool, field_syntax: &str) {
        self.parent.append_path_name(builder, include_root_symbol);
        builder.push_str(field_syntax);
    }

    /// Mirrors `AbstractDBTraceDataComponent.getParent()`.
    pub fn get_parent(&self) -> Arc<dyn DBTraceDefinedDataAdapter> {
        Arc::clone(&self.parent)
    }

    /// Mirrors `AbstractDBTraceDataComponent.getRoot()`.
    pub fn get_root(&self) -> Arc<dyn DBTraceData> {
        Arc::clone(&self.root)
    }

    /// Mirrors `AbstractDBTraceDataComponent.getRootOffset()`.
    pub fn get_root_offset(&self) -> i32 {
        self.address.subtract(&MemBuffer::get_address(self.root.as_ref())) as i32
    }

    /// Mirrors `AbstractDBTraceDataComponent.getParentOffset()`.
    pub fn get_parent_offset(&self) -> i32 {
        self.address.subtract(&MemBuffer::get_address(self.parent.as_ref())) as i32
    }

    /// Mirrors `AbstractDBTraceDataComponent.getComponentIndex()`.
    pub fn get_component_index(&self) -> i32 {
        self.index
    }

    /// Mirrors `AbstractDBTraceDataComponent.getComponentLevel()`.
    pub fn get_component_level(&self) -> i32 {
        self.level
    }

    /// Mirrors `AbstractDBTraceDataComponent.getSettingsSpace(boolean)`.
    pub fn get_settings_space(&self, create_if_absent: bool) -> Option<Box<dyn DBTraceDataSettingsOperations>> {
        self.root.get_settings_space(create_if_absent)
    }

    /// Mirrors `AbstractDBTraceDataComponent.getDefaultSettings()`.
    pub fn get_default_settings(&self) -> Arc<dyn Settings> {
        Arc::clone(&self.default_settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, ReferenceIterator, SourceType as SymSourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType as StubRefType, Reference as StubReference};
    use crate::trace::seam_stubs::{DBTraceCodeUnitAdapter, DataAdapterFromDataType, TraceChangeRecord};
    use crate::trace::util::data_adapter_minimal::DataAdapterMinimal;
    use crate::trace::util::trace_change_manager::TraceChangeManager;
    use std::any::{Any, TypeId};

    /// A byte-mnemonic data type whose representation is the hex byte read from its buffer, so
    /// [`AbstractDBTraceDataComponentBase::to_string`] can be checked against a concrete value.
    struct ByteDataType;

    impl DataType for ByteDataType {
        fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
            "byte".to_string()
        }
        fn get_representation(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
            format!("{:#04x}", buf.get_byte(0).unwrap())
        }
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct MockChangeManager;
    impl TraceChangeManager for MockChangeManager {
        fn set_changed(&mut self, _event: Box<dyn TraceChangeRecord>) {}
    }

    #[derive(Default)]
    struct RecordingLock {
        depth: std::sync::atomic::AtomicI32,
        max_depth: std::sync::atomic::AtomicI32,
    }

    impl crate::util::lock_hold::Lock for RecordingLock {
        fn lock(&self) {
            use std::sync::atomic::Ordering;
            let depth = self.depth.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_depth.fetch_max(depth, Ordering::SeqCst);
        }
        fn unlock(&self) {
            self.depth.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
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
        fn get_address_property_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
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
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
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
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            crate::util::lock_hold::LockHold::lock(&*self.lock)
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            crate::util::lock_hold::LockHold::lock(&*self.lock)
        }
    }

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
        type Item = Arc<dyn crate::program::model::symbol::Reference>;
        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }
    impl ReferenceIterator for MockReferenceIterator {}

    struct MockStubReference;
    impl StubReference for MockStubReference {}

    /// The root data unit that a test component sits under: an 8-byte buffer at `0x400`, whose
    /// bytes equal their own offset, so [`AbstractDBTraceDataComponentBase::get_bytes`] and
    /// [`AbstractDBTraceDataComponentBase::to_string`] can be checked against known values.
    ///
    /// Also stands in as its own component's `parent` in the tests below (a level-1 component's
    /// parent, per `AbstractDBTraceDataComponent`'s own contract, is the root).
    struct MockRootUnit {
        address: Address,
        bytes: Vec<u8>,
        start_snap: i64,
        end_snap: i64,
        trace: MockTrace,
    }

    impl MemBuffer for MockRootUnit {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl PropertySet for MockRootUnit {}

    impl Settings for MockRootUnit {
        fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
            None
        }
    }

    impl CodeUnit for MockRootUnit {
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
            self.bytes.len() as i32
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(self.bytes.clone())
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x00);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.bytes.len() as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
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
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}
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

    impl Data for MockRootUnit {
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
            Box::new(ByteDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(ByteDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn StubReference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn StubRefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "ROOT".to_string()
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

    impl TraceCodeUnit for MockRootUnit {
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
        fn get_bounds(&self) -> Box<dyn crate::trace::model::trace_address_snap_range::TraceAddressSnapRange> {
            unimplemented!("not exercised by these tests")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), addr(self.address.offset() + self.bytes.len() as i64 - 1))
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.start_snap, self.end_snap)
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
        fn delete(&mut self) {}
    }

    impl crate::trace::model::listing::trace_data::TraceData for MockRootUnit {}
    impl DataAdapterMinimal for MockRootUnit {}
    impl DataAdapterFromDataType for MockRootUnit {}

    impl DBTraceCodeUnitAdapter for MockRootUnit {
        fn trace_change_manager(&mut self) -> &mut dyn TraceChangeManager {
            unimplemented!("not exercised by these tests")
        }
    }

    impl DBTraceDataAdapter for MockRootUnit {
        fn get_settings_space(&self, _create_if_absent: bool) -> Option<Box<dyn DBTraceDataSettingsOperations>> {
            None
        }
    }

    impl DBTraceDefinedDataAdapter for MockRootUnit {
        fn do_get_component_cache(&self) -> Vec<Box<dyn AbstractDBTraceDataComponent>> {
            Vec::new()
        }
        fn append_path_name(&self, builder: &mut String, include_root_symbol: bool) {
            if include_root_symbol {
                builder.push_str("ROOT");
            }
        }
    }

    impl DBTraceData for MockRootUnit {
        fn to_string(&self) -> String {
            Data::get_path_name(self)
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_root() -> Arc<MockRootUnit> {
        Arc::new(MockRootUnit {
            address: addr(0x400),
            bytes: (0u8..8).collect(),
            start_snap: 0,
            end_snap: 10,
            trace: MockTrace { lock: Arc::new(RecordingLock::default()) },
        })
    }

    /// A level-1 component at root offset 4, one byte long, directly under the root (so the
    /// root also plays the role of `parent`).
    fn make_component(index: i32) -> AbstractDBTraceDataComponentBase {
        let root = make_root();
        AbstractDBTraceDataComponentBase::new(
            root.clone(),
            root,
            index,
            addr(0x404),
            Arc::new(ByteDataType),
            1,
        )
    }

    #[test]
    fn constructor_derives_level_max_address_and_base_data_type() {
        let component = make_component(2);
        assert_eq!(component.get_component_level(), 1);
        assert_eq!(component.get_component_index(), 2);
        assert_eq!(component.get_address(), addr(0x404));
        assert_eq!(component.get_max_address(), addr(0x404));
        assert_eq!(component.get_length(), 1);
        // Not a typedef, so base_data_type aliases data_type (same allocation).
        assert!(Arc::ptr_eq(&component.data_type, &component.base_data_type));
    }

    #[test]
    fn offsets_are_computed_from_root_and_parent_addresses() {
        let component = make_component(2);
        assert_eq!(component.get_root_offset(), 4);
        // The root is also this component's parent here, so both offsets agree.
        assert_eq!(component.get_parent_offset(), 4);
    }

    #[test]
    fn get_bytes_reads_through_the_root_at_the_component_offset() {
        let component = make_component(2);
        let mut buf = [0u8; 1];
        let n = component.get_bytes(&mut buf, 0);
        assert_eq!(n, 1);
        // Root byte at offset 4 (this component's root offset) is 4, by construction.
        assert_eq!(buf[0], 4);
    }

    #[test]
    fn to_string_combines_mnemonic_and_byte_representation() {
        let component = make_component(2);
        assert_eq!(component.to_string(), "byte 0x04");
    }

    #[test]
    fn component_path_for_a_direct_child_of_the_root_is_its_own_index() {
        let component = make_component(5);
        assert_eq!(component.get_component_path(), vec![5]);
        // A second call must hit the cache and return the same answer.
        assert_eq!(component.get_component_path(), vec![5]);
    }

    #[test]
    fn component_path_acquires_the_trace_write_lock() {
        let recording = Arc::new(RecordingLock::default());
        let root = Arc::new(MockRootUnit {
            address: addr(0x400),
            bytes: vec![0; 4],
            start_snap: 0,
            end_snap: 10,
            trace: MockTrace { lock: Arc::clone(&recording) },
        });
        let component = AbstractDBTraceDataComponentBase::new(
            root.clone(),
            root,
            0,
            addr(0x400),
            Arc::new(ByteDataType),
            1,
        );
        component.get_component_path();
        assert_eq!(recording.max_depth.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(recording.depth.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn path_names_include_or_omit_the_root_symbol() {
        let component = make_component(2);
        assert_eq!(component.get_path_name(".field"), "ROOT.field");
        assert_eq!(component.get_component_path_name(".field"), ".field");
    }

    #[test]
    fn do_get_component_cache_lazily_sizes_and_persists() {
        let component = make_component(0);
        {
            let cache = component.do_get_component_cache(3);
            assert_eq!(cache.len(), 3);
        }
        {
            // A second call, even with a different count, must not resize an already-sized cache.
            let cache = component.do_get_component_cache(7);
            assert_eq!(cache.len(), 3);
        }
    }

    #[test]
    #[should_panic(expected = "Either delete the root, or modify the type")]
    fn delete_is_unsupported() {
        make_component(0).delete();
    }

    #[test]
    #[should_panic(expected = "Set end-snap of root unit")]
    fn set_end_snap_is_unsupported() {
        make_component(0).set_end_snap(20);
    }

    #[test]
    fn delegates_lifespan_and_snap_accessors_to_the_root() {
        let component = make_component(0);
        assert_eq!(component.get_lifespan(), Lifespan::span(0, 10));
        assert_eq!(component.get_start_snap(), 0);
        assert_eq!(component.get_end_snap(), 10);
    }
}
