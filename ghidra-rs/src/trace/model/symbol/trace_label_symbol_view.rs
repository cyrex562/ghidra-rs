//! A view over a trace's label symbols.
//!
//! Port of `ghidra.trace.model.symbol.TraceLabelSymbolView`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! Java's default `create(long, Address, ...)`, `create(long, TraceThread, Register, ...)`, and
//! `create(TracePlatform, long, TraceThread, Register, ...)` overloads build a `Lifespan.nowOn(
//! snap)` and delegate to the corresponding `Lifespan`-taking `add` overload. This crate's
//! [`Lifespan`] is a trait with no concrete, generically-constructible implementor yet, so there
//! is no way to build that span from just a `snap` inside a default method body. Those three
//! snap-taking overloads are therefore required methods here rather than defaults, following the
//! precedent set by
//! [`TraceBreakpointManager::place_breakpoint`](crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager::place_breakpoint).
//! The register-taking overloads that already receive a [`Lifespan`] (`add(TracePlatform,
//! Lifespan, TraceThread, Register, ...)` and `add(Lifespan, TraceThread, Register, ...)`) remain
//! defaults, since they need no `Lifespan.nowOn` construction.
//!
//! The Java overloads of `add`/`create` cannot be represented as same-named Rust methods (Rust
//! has no overloading), so each overload is given a distinct, descriptive name below.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::Register;
use crate::program::model::symbol::SourceType;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_label_symbol::TraceLabelSymbol;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView;
use crate::trace::model::thread::TraceThread;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::util::exception::InvalidInputException;

/// A view over a trace's label symbols.
pub trait TraceLabelSymbolView: TraceSymbolWithLocationView {
    /// Add a new label symbol.
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn add(
        &self,
        lifespan: Lifespan,
        address: &Address,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException>;

    /// A shorthand for [`Self::add`] where lifespan is from the given snap on.
    ///
    /// Mirrors Java's default `create(long, Address, String, TraceNamespaceSymbol, SourceType)`.
    /// See the module-level docs for why this is a required rather than default method in this
    /// port.
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn create(
        &self,
        snap: i64,
        address: &Address,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException>;

    /// Add a new label symbol on a register for the given thread.
    ///
    /// Mirrors Java's default `add(TracePlatform, Lifespan, TraceThread, Register, String,
    /// TraceNamespaceSymbol, SourceType)`.
    ///
    /// # Panics
    /// Panics if `register` is not byte-bound (see
    /// [`TraceRegisterUtils::require_byte_bound`](crate::trace::seam_stubs::TraceRegisterUtils::require_byte_bound)),
    /// or if the thread has no register address space (which should not happen, since this
    /// requests one be created if absent).
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn add_register(
        &self,
        platform: &dyn TracePlatform,
        lifespan: Lifespan,
        thread: &dyn TraceThread,
        register: &Register,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
        self.trace_register_utils().require_byte_bound(register);
        let space = self
            .trace_register_utils()
            .get_register_address_space(thread, 0, true)
            .expect("register address space must exist when create_if_absent is true");
        let range = platform.get_conventional_register_range(&space, register);
        self.add(lifespan, range.min_address(), name, parent, source)
    }

    /// Add a new label symbol on a register for the given thread, using the trace's host
    /// platform.
    ///
    /// Mirrors Java's default `add(Lifespan, TraceThread, Register, String, TraceNamespaceSymbol,
    /// SourceType)`.
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn add_thread(
        &self,
        lifespan: Lifespan,
        thread: &dyn TraceThread,
        register: &Register,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.add_register(platform.as_ref(), lifespan, thread, register, name, parent, source)
    }

    /// A shorthand for [`Self::add_thread`] where lifespan is from the given snap on.
    ///
    /// Mirrors Java's default `create(long, TraceThread, Register, String, TraceNamespaceSymbol,
    /// SourceType)`. See the module-level docs for why this is a required rather than default
    /// method in this port.
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn create_thread(
        &self,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException>;

    /// A shorthand for [`Self::add_register`] where lifespan is from the given snap on.
    ///
    /// Mirrors Java's default `create(TracePlatform, long, TraceThread, Register, String,
    /// TraceNamespaceSymbol, SourceType)`. See the module-level docs for why this is a required
    /// rather than default method in this port.
    ///
    /// # Errors
    /// Returns an error if `name` is not a valid symbol name.
    fn create_platform_thread(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        thread: &dyn TraceThread,
        register: &Register,
        name: &str,
        parent: &dyn TraceNamespaceSymbol,
        source: SourceType,
    ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, Namespace, NamespaceType, RefType, Reference, ReferenceIterator, Symbol,
        SymbolType,
    };
    use crate::program::model::util::PropertySet;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::symbol::trace_symbol_with_lifespan::TraceSymbolWithLifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager;
    use crate::trace::model::symbol::trace_symbol_view::TraceSymbolView;
    use crate::trace::seam_stubs::TraceRegisterUtils;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }



    fn now_on(snap: i64) -> Lifespan {
        Lifespan::span(snap, i64::MAX)
    }

    struct MockNamespaceSymbol {
        id: i64,
        name: String,
    }

    impl Namespace for MockNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }
        fn is_global(&self) -> bool {
            self.id == crate::program::model::symbol::GLOBAL_NAMESPACE_ID
        }
    }

    impl Symbol for MockNamespaceSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockNamespaceSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }

    impl TraceNamespaceSymbol for MockNamespaceSymbol {
        fn get_parent_trace_namespace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }
        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }
        fn get_path(&self) -> Vec<String> {
            vec![self.name.clone()]
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

    struct MockCodeUnit {
        min_address: Address,
    }

    impl MemBuffer for MockCodeUnit {
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            0
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }
        fn get_label(&self) -> Option<String> {
            Some("LAB".to_string())
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90])
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            *test_addr == self.min_address
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: RefType) {}
        fn set_register_reference(&mut self, _op_index: i32, _reg: &Register, _source_type: SourceType, _ref_type: RefType) {}
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

    impl TraceCodeUnit for MockCodeUnit {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.min_address.clone(), self.min_address.clone())
        }
        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            0
        }
        fn set_end_snap(&mut self, _end_snap: i64) {}
        fn get_end_snap(&self) -> i64 {
            10
        }
        fn delete(&mut self) {}
    }

    struct MockLabelSymbol {
        name: String,
        address: Address,
    }

    impl Symbol for MockLabelSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockLabelSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }

    impl TraceSymbolWithLifespan for MockLabelSymbol {
        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            0
        }
        fn set_end_snap(&mut self, _snap: i64) {}
        fn get_end_snap(&self) -> i64 {
            10
        }
    }

    impl TraceLabelSymbol for MockLabelSymbol {
        fn get_code_unit(&self) -> Box<dyn TraceCodeUnit> {
            Box::new(MockCodeUnit { min_address: self.address.clone() })
        }
    }

    #[derive(Clone)]
    struct MockManager {
        global: Arc<MockNamespaceSymbol>,
    }

    impl TraceSymbolManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_global_namespace(&self) -> Arc<dyn TraceNamespaceSymbol> {
            self.global.clone()
        }
        fn labels(&self) -> Box<dyn TraceLabelSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn namespaces(&self) -> Box<dyn crate::trace::model::symbol::trace_namespace_symbol_view::TraceNamespaceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn classes(&self) -> Box<dyn crate::trace::model::symbol::trace_class_symbol_view::TraceClassSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn all_namespaces(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_view::TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn not_labels(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_no_duplicates_view::TraceSymbolNoDuplicatesView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn all_symbols(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_view::TraceSymbolView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_ids_added(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_ids_removed(&self, _from: i64, _to: i64) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockThread;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            0
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    struct MockRegisterUtils {
        space: Arc<AddressSpace>,
    }

    impl TraceRegisterUtils for MockRegisterUtils {
        fn get_thread(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> Box<dyn TraceThread> {
            Box::new(MockThread)
        }
        fn get_frame_level(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> i32 {
            0
        }
        fn get_register_address_space(
            &self,
            _thread: &dyn TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            Some(self.space.clone())
        }

        fn buffer_for_value(
            &self,
            _register: &Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    /// A view that records every added label, keyed by (min-snap, address, name), to prove the
    /// required/default method wiring actually works.
    struct MockView {
        space: Arc<AddressSpace>,
        manager: MockManager,
        register_utils: MockRegisterUtils,
        added: RefCell<Vec<(i64, Address, String)>>,
    }

    impl TraceSymbolView for MockView {
        fn get_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(self.manager.clone())
        }

        fn get_all(&self, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_children_named(&self, _name: &str, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_children(&self, _parent: &dyn TraceNamespaceSymbol) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_named(&self, _name: &str) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_with_matching_name(&self, _glob: &str, _case_sensitive: bool) -> Vec<Arc<dyn TraceSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn scan_by_name(&self, _start_name: &str) -> Box<dyn Iterator<Item = Arc<dyn TraceSymbol>> + '_> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceSymbolWithLocationView for MockView {
        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.register_utils
        }
        fn get_child_with_name_at(
            &self,
            _name: &str,
            _snap: i64,
            _address: &Address,
            _parent: &dyn TraceNamespaceSymbol,
        ) -> Option<Arc<dyn TraceSymbol>> {
            None
        }
        fn get_intersecting(
            &self,
            _span: Lifespan,
            _range: &AddressRange,
            _include_dynamic_symbols: bool,
            _forward: bool,
        ) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }
        fn get_at(&self, _snap: i64, _address: &Address, _include_dynamic_symbols: bool) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }
    }

    impl TraceLabelSymbolView for MockView {
        fn add(
            &self,
            lifespan: Lifespan,
            address: &Address,
            name: &str,
            _parent: &dyn TraceNamespaceSymbol,
            _source: SourceType,
        ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
            if name.is_empty() {
                return Err(InvalidInputException::with_message("name must not be empty"));
            }
            self.added.borrow_mut().push((lifespan.lmin(), address.clone(), name.to_string()));
            Ok(Arc::new(MockLabelSymbol { name: name.to_string(), address: address.clone() }))
        }

        fn create(
            &self,
            snap: i64,
            address: &Address,
            name: &str,
            parent: &dyn TraceNamespaceSymbol,
            source: SourceType,
        ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
            self.add(now_on(snap), address, name, parent, source)
        }

        fn create_thread(
            &self,
            snap: i64,
            thread: &dyn TraceThread,
            register: &Register,
            name: &str,
            parent: &dyn TraceNamespaceSymbol,
            source: SourceType,
        ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
            self.add_thread(now_on(snap), thread, register, name, parent, source)
        }

        fn create_platform_thread(
            &self,
            platform: &dyn TracePlatform,
            snap: i64,
            thread: &dyn TraceThread,
            register: &Register,
            name: &str,
            parent: &dyn TraceNamespaceSymbol,
            source: SourceType,
        ) -> Result<Arc<dyn TraceLabelSymbol>, InvalidInputException> {
            self.add_register(platform, now_on(snap), thread, register, name, parent, source)
        }
    }

    fn make_view() -> MockView {
        let ram = space();
        let global = Arc::new(MockNamespaceSymbol {
            id: crate::program::model::symbol::GLOBAL_NAMESPACE_ID,
            name: "Global".to_string(),
        });
        MockView {
            space: ram.clone(),
            manager: MockManager { global },
            register_utils: MockRegisterUtils { space: ram },
            added: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn add_records_lifespan_min_and_address() {
        let view = make_view();
        let addr = view.space.address(0x1000);
        let sym = view
            .add(Lifespan::span(5, 20), &addr, "LAB_1000", view.manager.global.as_ref(), SourceType::UserDefined)
            .expect("add should succeed");
        assert_eq!(sym.get_name(), "LAB_1000");
        assert_eq!(view.added.borrow().len(), 1);
        assert_eq!(view.added.borrow()[0], (5, addr, "LAB_1000".to_string()));
    }

    #[test]
    fn add_rejects_invalid_name() {
        let view = make_view();
        let addr = view.space.address(0x1000);
        let result = view.add(Lifespan::span(0, 10), &addr, "", view.manager.global.as_ref(), SourceType::UserDefined);
        match result {
            Ok(_) => panic!("empty name should be rejected"),
            Err(e) => assert!(e.0.contains("empty")),
        }
    }

    #[test]
    fn create_delegates_to_add_with_now_on_lifespan() {
        let view = make_view();
        let addr = view.space.address(0x2000);
        let sym = view
            .create(7, &addr, "LAB_2000", view.manager.global.as_ref(), SourceType::UserDefined)
            .expect("create should succeed");
        assert_eq!(sym.get_name(), "LAB_2000");
        assert_eq!(view.added.borrow()[0].0, 7);
    }

    #[test]
    fn add_register_resolves_conventional_range_and_delegates_to_add() {
        let view = make_view();
        let register_ref = Register::new("r0", "general register", view.space.address(0x100), 4, false, 0);
        let register = register_ref.borrow();
        let sym = view
            .add_register(
                &MockPlatform,
                Lifespan::span(0, 10),
                &MockThread,
                &register,
                "LAB_r0",
                view.manager.global.as_ref(),
                SourceType::UserDefined,
            )
            .expect("add_register should succeed");
        assert_eq!(sym.get_name(), "LAB_r0");
        assert_eq!(view.added.borrow()[0].1, view.space.address(0x100));
    }

    #[test]
    #[should_panic(expected = "not byte-bound")]
    fn add_register_panics_on_non_byte_bound_register() {
        let view = make_view();
        let register_ref = Register::with_bit_range("bit0", "sub-register", view.space.address(0x100), 4, 1, 4, false, 0);
        let register = register_ref.borrow();
        let _ = view.add_register(
            &MockPlatform,
            Lifespan::span(0, 10),
            &MockThread,
            &register,
            "LAB_bad",
            view.manager.global.as_ref(),
            SourceType::UserDefined,
        );
    }

    #[test]
    fn is_object_safe_and_boxed_dyn_dispatches_create() {
        let view = make_view();
        let space = view.space.clone();
        let global = view.manager.global.clone();
        // Exercises the real `TraceSymbolWithLocationView`/`TraceSymbolView` supertrait plumbing
        // (boxed trait object), proving the required-method wiring works through `dyn` dispatch.
        let boxed: Box<dyn TraceLabelSymbolView> = Box::new(view);
        let addr = space.address(0x3000);
        let sym = boxed
            .create(9, &addr, "LAB_3000", global.as_ref(), SourceType::UserDefined)
            .expect("create should succeed");
        assert_eq!(sym.get_name(), "LAB_3000");
    }
}
