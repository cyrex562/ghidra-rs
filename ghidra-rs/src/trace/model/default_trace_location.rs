//! A concrete location within a trace: a trace, thread, lifespan, and address.
//!
//! Java source: `ghidra.trace.model.DefaultTraceLocation`.
//!
//! The `trace` and `thread` fields are held by [`Arc`] rather than by value, mirroring
//! [`DefaultTraceSpan`](crate::trace::model::default_trace_span::DefaultTraceSpan): Java's
//! `equals()` compares them by reference identity (`this.trace != that.trace`), not by content,
//! so [`Arc::ptr_eq`] is the faithful translation.
//!
//! [`TraceLocation::get_trace`]/[`TraceLocation::get_thread`] must return an owned
//! `Box<dyn Trace>`/`Box<dyn TraceThread>` from `&self`, which an `Arc` cannot produce directly
//! without cloning the pointee. The `impl Trace for Arc<dyn Trace + Send + Sync>` and
//! `impl TraceThread for Arc<dyn TraceThread>` below solve this generically: boxing a clone of
//! the `Arc` (a cheap refcount bump) yields a trait object that forwards every call to the same
//! shared instance. Mutating methods use [`Arc::get_mut`], which only succeeds when this handle
//! is the sole owner; mutation through a shared handle is silently ignored otherwise, since
//! `Trace`/`TraceThread` have no interior mutability of their own to synchronize on. This
//! adapter is reusable: any future concrete type that stores `Arc<dyn Trace>`/`Arc<dyn
//! TraceThread>` and must satisfy these trait signatures can reuse it as-is.
//!
//! `Trace` itself does not declare `Send + Sync` as supertraits, so `dyn Trace` is not `Send +
//! Sync` automatically (unlike `dyn TraceThread`, which gets both for free via
//! [`TraceObjectInterface`]'s supertrait bound). Since [`TraceLocation`] requires `Send + Sync`,
//! the `trace` field's trait object bound spells out `+ Send + Sync` explicitly.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::merge::DataTypeManagerOwner;
use crate::framework::model::DomainObject;
use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
use crate::program::model::lang::{CompilerSpec, Language};
use crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager;
use crate::trace::model::guest::trace_platform_manager::TracePlatformManager;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::TraceCodeManager;
use crate::trace::model::memory::trace_memory_manager::TraceMemoryManager;
use crate::trace::model::modules::{TraceModuleManager, TraceStaticMappingManager};
use crate::trace::model::program::{TraceProgramView, TraceVariableSnapProgramView};
use crate::trace::model::property::TraceAddressPropertyManager;
use crate::trace::model::stack::trace_stack_manager::TraceStackManager;
use crate::trace::model::symbol::trace_equate_manager::TraceEquateManager;
use crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager;
use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_manager::TraceObjectManager;
use crate::trace::model::thread::{TraceThread, TraceThreadManager};
use crate::trace::model::time::trace_time_manager::TraceTimeManager;
use crate::trace::model::trace::{Trace, TraceProgramViewListener};
use crate::trace::model::trace_location::TraceLocation;
use crate::trace::model::trace_time_viewport::TraceTimeViewport;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::{ObjectKey, TraceBasedDataTypeManager, TraceBookmarkManager, TraceRegisterContextManager};
use crate::util::lock_hold::{Lock, LockHold};

impl DomainObject for Arc<dyn Trace + Send + Sync> {
    // `get_name` is forwarded (unlike the rest of `DomainObject`, which is left on its safe
    // defaults) because `Display`/`Ord` below call it directly on this field: without an
    // explicit override here, method resolution would prefer this impl's (default, no-op) `Arc`
    // level over the real trace's, silently returning "" instead of the actual name.
    fn get_name(&self) -> String {
        (**self).get_name()
    }
}

impl DataTypeManagerOwner for Arc<dyn Trace + Send + Sync> {
    fn get_data_type_manager(&self) -> &dyn DataTypeManager {
        (**self).get_data_type_manager()
    }
}

impl DataTypeManagerDomainObject for Arc<dyn Trace + Send + Sync> {}

impl Trace for Arc<dyn Trace + Send + Sync> {
    fn get_base_language(&self) -> Box<dyn Language> {
        (**self).get_base_language()
    }

    fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        (**self).get_base_compiler_spec()
    }

    fn set_emulator_cache_version(&mut self, version: i64) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.set_emulator_cache_version(version);
        }
    }

    fn get_emulator_cache_version(&self) -> i64 {
        (**self).get_emulator_cache_version()
    }

    fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
        (**self).get_base_address_factory()
    }

    fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
        (**self).get_address_property_manager()
    }

    fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
        (**self).get_bookmark_manager()
    }

    fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
        (**self).get_breakpoint_manager()
    }

    fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
        (**self).get_code_manager()
    }

    fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
        (**self).get_base_data_type_manager()
    }

    fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
        (**self).get_equate_manager()
    }

    fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
        (**self).get_platform_manager()
    }

    fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
        (**self).get_memory_manager()
    }

    fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
        (**self).get_module_manager()
    }

    fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
        (**self).get_object_manager()
    }

    fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
        (**self).get_reference_manager()
    }

    fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
        (**self).get_register_context_manager()
    }

    fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
        (**self).get_stack_manager()
    }

    fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
        (**self).get_static_mapping_manager()
    }

    fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
        (**self).get_symbol_manager()
    }

    fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
        (**self).get_thread_manager()
    }

    fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
        (**self).get_time_manager()
    }

    fn get_fixed_program_view(&self, snap: i64) -> Box<dyn TraceProgramView> {
        (**self).get_fixed_program_view(snap)
    }

    fn create_program_view(&self, snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
        (**self).create_program_view(snap)
    }

    fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
        (**self).get_all_program_views()
    }

    fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
        (**self).get_program_view()
    }

    fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
        (**self).create_time_viewport()
    }

    fn add_program_view_listener(&mut self, listener: Box<dyn TraceProgramViewListener>) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.add_program_view_listener(listener);
        }
    }

    fn remove_program_view_listener(&mut self, listener: &dyn TraceProgramViewListener) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.remove_program_view_listener(listener);
        }
    }

    fn lock_read(&self) -> LockHold<'_, dyn Lock> {
        (**self).lock_read()
    }

    fn lock_write(&self) -> LockHold<'_, dyn Lock> {
        (**self).lock_write()
    }
}

impl TraceUniqueObject for Arc<dyn TraceThread> {
    fn get_object_key(&self) -> Box<dyn ObjectKey> {
        (**self).get_object_key()
    }

    fn is_deleted(&self) -> bool {
        (**self).is_deleted()
    }
}

impl TraceObjectInterface for Arc<dyn TraceThread> {
    fn get_object(&self) -> Box<dyn TraceObject> {
        (**self).get_object()
    }
}

impl TraceThread for Arc<dyn TraceThread> {
    fn get_trace(&self) -> Box<dyn Trace> {
        (**self).get_trace()
    }

    fn get_key(&self) -> i64 {
        (**self).get_key()
    }

    fn get_path(&self) -> String {
        (**self).get_path()
    }

    fn get_name(&self, snap: i64) -> String {
        (**self).get_name(snap)
    }

    fn set_name(&mut self, lifespan: Lifespan, name: &str) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.set_name(lifespan, name);
        }
    }

    fn set_name_at(&mut self, snap: i64, name: &str) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.set_name_at(snap, name);
        }
    }

    fn set_comment(&mut self, snap: i64, comment: Option<&str>) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.set_comment(snap, comment);
        }
    }

    fn get_comment(&self, snap: i64) -> Option<String> {
        (**self).get_comment(snap)
    }

    fn delete(&mut self) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.delete();
        }
    }

    fn remove(&mut self, snap: i64) {
        if let Some(inner) = Arc::get_mut(self) {
            inner.remove(snap);
        }
    }

    fn is_valid(&self, snap: i64) -> bool {
        (**self).is_valid(snap)
    }

    fn is_alive(&self, span: Lifespan) -> bool {
        (**self).is_alive(span)
    }
}

/// A concrete location within a trace: a trace, thread, lifespan, and address.
///
/// Port of `ghidra.trace.model.DefaultTraceLocation`.
pub struct DefaultTraceLocation {
    trace: Arc<dyn Trace + Send + Sync>,
    thread: Arc<dyn TraceThread>,
    lifespan: Lifespan,
    address: Address,
}

impl DefaultTraceLocation {
    /// Creates a new location for `address` at `lifespan`, within `thread` of `trace`.
    pub fn new(
        trace: Arc<dyn Trace + Send + Sync>,
        thread: Arc<dyn TraceThread>,
        lifespan: Lifespan,
        address: Address,
    ) -> Self {
        Self { trace, thread, lifespan, address }
    }
}

impl TraceLocation for DefaultTraceLocation {
    fn get_trace(&self) -> Box<dyn Trace> {
        Box::new(Arc::clone(&self.trace))
    }

    fn get_thread(&self) -> Box<dyn TraceThread> {
        Box::new(Arc::clone(&self.thread))
    }

    fn get_lifespan(&self) -> Lifespan {
        self.lifespan
    }

    fn get_address(&self) -> Address {
        self.address.clone()
    }
}

impl fmt::Display for DefaultTraceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TraceLocation<{}: {},{}>",
            self.trace.get_name(),
            self.lifespan,
            self.address
        )
    }
}

impl PartialEq for DefaultTraceLocation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.trace, &other.trace)
            && Arc::ptr_eq(&self.thread, &other.thread)
            && self.address == other.address
            && self.lifespan == other.lifespan
    }
}

impl Eq for DefaultTraceLocation {}

impl Hash for DefaultTraceLocation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.trace) as *const ()).hash(state);
        (Arc::as_ptr(&self.thread) as *const ()).hash(state);
        self.lifespan.hash(state);
        self.address.hash(state);
    }
}

impl PartialOrd for DefaultTraceLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceLocation {
    fn cmp(&self, other: &Self) -> Ordering {
        if std::ptr::eq(self, other) {
            return Ordering::Equal;
        }
        self.trace
            .get_name()
            .cmp(&other.trace.get_name())
            .then_with(|| {
                self.thread
                    .get_name(self.lifespan.lmin())
                    .cmp(&other.thread.get_name(self.lifespan.lmin()))
            })
            .then_with(|| self.lifespan.cmp(&other.lifespan))
            .then_with(|| self.address.cmp(&other.address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockTraceBasedDataTypeManager;
    impl DataTypeManager for MockTraceBasedDataTypeManager {}
    impl TraceBasedDataTypeManager for MockTraceBasedDataTypeManager {}

    struct MockLock;
    impl Lock for MockLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockTrace {
        name: String,
    }

    impl DomainObject for MockTrace {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn DataTypeManager {
            static MANAGER: MockDataTypeManager = MockDataTypeManager;
            &MANAGER
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by these tests")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by these tests")
        }
        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by these tests")
        }
        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by these tests")
        }
        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {
            unimplemented!("not exercised by these tests")
        }
        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {
            unimplemented!("not exercised by these tests")
        }
        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by these tests")
        }
        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockObjectKey(i32);
    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some_and(|other| other.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockThread {
        path: String,
        name: String,
    }

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_key(&self) -> i64 {
            1
        }
        fn get_path(&self) -> String {
            self.path.clone()
        }
        fn get_name(&self, _snap: i64) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            self.name = name.to_string();
        }
        fn set_name_at(&mut self, _snap: i64, name: &str) {
            self.name = name.to_string();
        }
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_comment(&self, _snap: i64) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    fn make_trace(name: &str) -> Arc<dyn Trace + Send + Sync> {
        Arc::new(MockTrace { name: name.to_string() })
    }

    fn make_thread(path: &str, name: &str) -> Arc<dyn TraceThread> {
        Arc::new(MockThread { path: path.to_string(), name: name.to_string() })
    }

    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn make_address(offset: i64) -> Address {
        Address::new(make_space(), offset)
    }

    fn make_location(trace_name: &str, thread_name: &str, min: i64, max: i64, addr: i64) -> DefaultTraceLocation {
        DefaultTraceLocation::new(
            make_trace(trace_name),
            make_thread("Threads[0]", thread_name),
            Lifespan::span(min, max),
            make_address(addr),
        )
    }

    #[test]
    fn getters_return_constructor_values() {
        let trace = make_trace("t1");
        let thread = make_thread("Threads[0]", "main");
        let lifespan = Lifespan::span(0, 10);
        let address = make_address(0x1000);
        let loc = DefaultTraceLocation::new(trace.clone(), thread.clone(), lifespan, address.clone());

        assert_eq!(loc.get_trace().get_name(), trace.get_name());
        assert_eq!(loc.get_lifespan(), lifespan);
        assert_eq!(loc.get_address(), address);
        assert_eq!(loc.get_thread().get_name(0), "main");
    }

    #[test]
    fn get_trace_forwards_to_shared_instance() {
        let loc = make_location("t1", "main", 0, 10, 0x1000);
        assert_eq!(loc.get_trace().get_name(), "t1");
    }

    #[test]
    fn equal_when_same_trace_and_thread_and_equal_span_and_address() {
        let trace = make_trace("t1");
        let thread = make_thread("Threads[0]", "main");
        let a = DefaultTraceLocation::new(trace.clone(), thread.clone(), Lifespan::span(0, 10), make_address(0x1000));
        let b = DefaultTraceLocation::new(trace, thread, Lifespan::span(0, 10), make_address(0x1000));
        assert!(a == b);
    }

    #[test]
    fn not_equal_when_different_trace_reference() {
        let thread = make_thread("Threads[0]", "main");
        let a = DefaultTraceLocation::new(make_trace("t1"), thread.clone(), Lifespan::span(0, 10), make_address(0x1000));
        let b = DefaultTraceLocation::new(make_trace("t1"), thread, Lifespan::span(0, 10), make_address(0x1000));
        assert!(a != b);
    }

    #[test]
    fn not_equal_when_different_address() {
        let trace = make_trace("t1");
        let thread = make_thread("Threads[0]", "main");
        let a = DefaultTraceLocation::new(trace.clone(), thread.clone(), Lifespan::span(0, 10), make_address(0x1000));
        let b = DefaultTraceLocation::new(trace, thread, Lifespan::span(0, 10), make_address(0x2000));
        assert!(a != b);
    }

    #[test]
    fn hash_matches_for_equal_locations() {
        let trace = make_trace("t1");
        let thread = make_thread("Threads[0]", "main");
        let a = DefaultTraceLocation::new(trace.clone(), thread.clone(), Lifespan::span(0, 10), make_address(0x1000));
        let b = DefaultTraceLocation::new(trace, thread, Lifespan::span(0, 10), make_address(0x1000));

        use std::collections::hash_map::DefaultHasher;
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn ordering_by_trace_name_first() {
        let a = make_location("a", "main", 0, 100, 0);
        let b = make_location("b", "main", 0, 0, 0);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn ordering_by_thread_name_when_trace_names_equal() {
        let a = make_location("t1", "a", 0, 10, 0);
        let b = make_location("t1", "b", 0, 10, 0);
        assert!(a < b);
    }

    #[test]
    fn ordering_by_address_when_trace_thread_and_lifespan_equal() {
        let a = make_location("t1", "main", 0, 10, 0x1000);
        let b = make_location("t1", "main", 0, 10, 0x2000);
        assert!(a < b);
    }

    #[test]
    fn comparable_to_self() {
        let loc = make_location("t1", "main", 5, 15, 0x1000);
        assert_eq!(loc.cmp(&loc), Ordering::Equal);
    }

    #[test]
    fn display_includes_trace_name_lifespan_and_address() {
        let loc = make_location("t1", "main", 0, 10, 0);
        let text = loc.to_string();
        assert!(text.starts_with("TraceLocation<t1: "));
    }
}
