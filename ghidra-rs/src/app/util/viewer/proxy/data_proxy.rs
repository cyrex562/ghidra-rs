use std::cell::RefCell;
use std::sync::Arc;

use crate::app::util::viewer::listingpanel::listing_model::ListingModel;
use crate::program::model::address::Address;
use crate::program::model::listing::{Data, Program};

use super::proxy_obj::{ProxyObj, ProxyObjBase};

/// Stores information about a data item in a program such that the data item can be retrieved
/// when needed.
///
/// Port of `ghidra.app.util.viewer.proxy.DataProxy`.
///
/// Java's `DataProxy extends ProxyObj<Data>`, contributing the `program`/`data`/`addr`/`path`
/// fields and the two abstract methods. Following this crate's established composition
/// convention (see [`ProxyObjBase`]'s module doc comment), this embeds a `base: ProxyObjBase`
/// field rather than inheriting.
///
/// Java's `getObject()` mutates the `data` field, but [`ProxyObj::get_object`] takes `&self`
/// (matching every other implementor of that trait in this crate -- see
/// [`CodeUnitProxy`](super::code_unit_proxy::CodeUnitProxy)'s analogous doc comment), so the
/// cached `data` -- and the `program` handle needed to refresh it -- are held behind [`RefCell`]
/// for interior mutability. The cached value is [`Arc<dyn Data>`] rather than `Box<dyn Data>` so
/// [`Self::get_object`] can hand back a cheap clone of it from a shared borrow, the same reason
/// [`CodeUnitProxy`](super::code_unit_proxy::CodeUnitProxy) uses `Arc<dyn CodeUnit>`; a
/// `Box<dyn Data>` component fetched via [`Data::get_component_by_path`] is converted into an
/// `Arc` with `Arc::from`.
pub struct DataProxy {
    base: ProxyObjBase,
    program: RefCell<Arc<dyn Program>>,
    data: RefCell<Option<Arc<dyn Data>>>,
    addr: Address,
    path: Vec<i32>,
}

impl DataProxy {
    /// Construct a proxy for the given Data object.
    ///
    /// `model` is the listing model, `program` is the program containing the data object, and
    /// `data` is the Data object to proxy.
    ///
    /// Mirrors `DataProxy(ListingModel model, Program program, Data data)`.
    pub fn new(model: Box<dyn ListingModel>, program: Arc<dyn Program>, data: Arc<dyn Data>) -> Self {
        let addr = data.get_min_address();
        let path = data.get_component_path();
        Self {
            base: ProxyObjBase::new(model),
            program: RefCell::new(program),
            data: RefCell::new(Some(data)),
            addr,
            path,
        }
    }
}

impl ProxyObj<Arc<dyn Data>> for DataProxy {
    fn base(&self) -> &ProxyObjBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ProxyObjBase {
        &mut self.base
    }

    /// Mirrors `getObject()`.
    ///
    /// Java: if a cached `data` is present, it defensively calls `data.getMinAddress()`,
    /// catching a `ConcurrentModificationException` (thrown if the underlying DB record went
    /// stale mid-iteration) to fall through and reload via
    /// `program.getListing().getDataContaining(addr).getComponent(path)`; otherwise it reloads
    /// directly. This crate's [`crate::program::model::listing::CodeUnit::get_min_address`] is
    /// infallible -- no DB-staleness-exception mechanism has been ported alongside the DB data
    /// representation -- so the call below can never trigger that fallback path; the cached
    /// `data` is always returned as-is once present, matching the non-exceptional
    /// (overwhelmingly common) case Java also takes. See
    /// [`CodeUnitProxy::get_object`](super::code_unit_proxy::CodeUnitProxy) for the analogous
    /// situation.
    fn get_object(&self) -> Option<Arc<dyn Data>> {
        if let Some(data) = self.data.borrow().clone() {
            let _ = data.get_min_address();
            return Some(data);
        }
        let mut program = self.program.borrow_mut();
        let top = Arc::get_mut(&mut program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_data_containing(&self.addr));
        let component: Option<Arc<dyn Data>> =
            top.and_then(|t| t.get_component_by_path(&self.path)).map(Arc::from);
        *self.data.borrow_mut() = component.clone();
        component
    }

    /// Mirrors `contains(Address)`.
    fn contains(&self, a: &Address) -> bool {
        match self.get_object() {
            Some(d) => d.contains(a),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{FormatManager, Layout};
    use crate::app::util::viewer::listingpanel::listing_model_listener::ListingModelListener;
    use crate::docking::settings::settings::Settings;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{address_set::AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction_stub::InstructionStub;
    use crate::program::model::listing::{Listing, StubListing};
    use crate::program::seam_stubs::{RefType, Reference};
    use crate::util::task::TaskMonitor;
    use std::any::{Any, TypeId};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    /// Minimal `Data` test double. [`InstructionStub`] blanket-implements `MemBuffer`/
    /// `PropertySet`/`CodeUnit` with panicking bodies; only `get_min_address`/
    /// `contains`/`get_component_path` are overridden -- everything else in `Data`'s own surface
    /// has no default and must still be implemented directly.
    struct MockData {
        min: Address,
        component_path: Vec<i32>,
        component_by_path: Option<Address>,
    }

    impl InstructionStub for MockData {
        fn get_min_address(&self) -> Address {
            self.min.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min.clone()
        }
        fn contains(&self, test_addr: &Address) -> bool {
            &self.min == test_addr
        }
    }

    impl Settings for MockData {}

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
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
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
            Box::new(MockData {
                min: self.min.clone(),
                component_path: Vec::new(),
                component_by_path: None,
            })
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
            self.component_by_path.clone().map(|a| {
                Box::new(MockData { min: a, component_path: Vec::new(), component_by_path: None })
                    as Box<dyn Data>
            })
        }
        fn get_component_path(&self) -> Vec<i32> {
            self.component_path.clone()
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

    struct MockProgram;
    impl DomainObject for MockProgram {}

    struct MockListing {
        data_at: Option<Address>,
        component_by_path: Option<Address>,
    }

    impl StubListing for MockListing {
        fn get_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            self.data_at.as_ref().map(|a| {
                Arc::new(MockData {
                    min: a.clone(),
                    component_path: Vec::new(),
                    component_by_path: self.component_by_path.clone(),
                }) as Arc<dyn Data>
            })
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }
    }

    // A second program type whose `get_listing` returns a real listing, used only by the reload
    // tests (kept separate so `MockProgram`'s `Listing` field-based override stays simple).
    struct ReloadableProgram {
        listing: MockListing,
    }
    impl DomainObject for ReloadableProgram {}
    impl Program for ReloadableProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            Some(&mut self.listing)
        }
    }

    struct MockListingModel;
    impl ListingModel for MockListingModel {
        fn get_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_address_after(&self, _address: &Address) -> Option<Address> {
            None
        }
        fn get_address_before(&self, _address: &Address) -> Option<Address> {
            None
        }
        fn get_layout(&mut self, _address: &Address, _is_gap_address: bool) -> Option<Box<dyn Layout>> {
            None
        }
        fn get_max_width(&self) -> i32 {
            0
        }
        fn is_open(&self, _data: &dyn Data) -> bool {
            false
        }
        fn toggle_open(&mut self, _data: &dyn Data) {}
        fn set_function_variables_open(&mut self, _function_address: &Address, _open: bool) {}
        fn are_function_variables_open(&self, _function_address: &Address) -> bool {
            false
        }
        fn set_all_function_variables_open(&mut self, _open: bool) {}
        fn open_data(&mut self, _data: &dyn Data) -> bool {
            false
        }
        fn open_all_data(&mut self, _data: &dyn Data, _monitor: &dyn TaskMonitor) {}
        fn open_all_data_in_addresses(&mut self, _addresses: &dyn AddressSetView, _monitor: &dyn TaskMonitor) {}
        fn close_data(&mut self, _data: &dyn Data) {}
        fn close_all_data(&mut self, _data: &dyn Data, _monitor: &dyn TaskMonitor) {}
        fn close_all_data_in_addresses(&mut self, _addresses: &dyn AddressSetView, _monitor: &dyn TaskMonitor) {}
        fn add_listener(&mut self, _listener: Box<dyn ListingModelListener>) {}
        fn remove_listener(&mut self, _listener: &dyn ListingModelListener) {}
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn is_closed(&self) -> bool {
            false
        }
        fn set_format_manager(&mut self, _format_manager: Box<dyn FormatManager>) {}
        fn dispose(&mut self) {}
        fn adjust_address_set_to_code_unit_boundaries(&self, address_set: &AddressSet) -> AddressSet {
            address_set.clone()
        }
        fn copy(&self) -> Box<dyn ListingModel> {
            Box::new(MockListingModel)
        }
        fn is_function_open(&self, _function_address: &Address) -> bool {
            false
        }
        fn set_function_open(&mut self, _function_address: &Address, _open: bool) {}
        fn set_all_functions_open(&mut self, _open: bool) {}
    }

    fn model() -> Box<dyn ListingModel> {
        Box::new(MockListingModel)
    }

    fn data(min: Address, component_path: Vec<i32>) -> Arc<dyn Data> {
        Arc::new(MockData { min, component_path, component_by_path: None })
    }

    #[test]
    fn get_object_returns_the_cached_data() {
        let d = data(addr(0x1000), vec![]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let proxy = DataProxy::new(model(), program, d);

        let fetched = proxy.get_object().expect("data is cached");
        assert_eq!(fetched.get_min_address(), addr(0x1000));
    }

    #[test]
    fn contains_delegates_to_the_cached_data() {
        let d = data(addr(0x2000), vec![]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let proxy = DataProxy::new(model(), program, d);

        assert!(proxy.contains(&addr(0x2000)));
        assert!(!proxy.contains(&addr(0x2001)));
    }

    #[test]
    fn constructor_captures_min_address_and_component_path() {
        let d = data(addr(0x3000), vec![1, 2]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let proxy = DataProxy::new(model(), program, d);
        assert_eq!(proxy.addr, addr(0x3000));
        assert_eq!(proxy.path, vec![1, 2]);
    }

    #[test]
    fn base_accessors_expose_the_constructed_model() {
        let d = data(addr(0x4000), vec![]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut proxy = DataProxy::new(model(), program, d);
        assert!(!proxy.base().get_listing_layout_model().is_closed());
        assert!(!proxy.base_mut().get_listing_layout_model().is_closed());
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let d = data(addr(0x5000), vec![]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let proxy: Box<dyn ProxyObj<Arc<dyn Data>>> = Box::new(DataProxy::new(model(), program, d));
        assert!(proxy.contains(&addr(0x5000)));
        assert!(proxy.get_object().is_some());
    }

    #[test]
    fn reload_path_descends_through_component_path_when_cache_is_cleared() {
        // Exercise the `program.getListing().getDataContaining(addr).getComponent(path)` reload
        // path by manually clearing the cache (simulating a prior `None` result) and swapping in
        // a program whose Listing actually answers `get_data_containing`.
        let component_addr = addr(0x6100);
        let listing = MockListing {
            data_at: Some(addr(0x6000)),
            component_by_path: Some(component_addr.clone()),
        };
        let program: Arc<dyn Program> = Arc::new(ReloadableProgram { listing });
        let d = data(addr(0x6000), vec![0]);
        let proxy = DataProxy::new(model(), program, d);

        // Force the cache empty, as if `get_object` had never been called and the value came from
        // a program with no cached `data` yet.
        *proxy.data.borrow_mut() = None;

        let fetched = proxy.get_object().expect("reload should find a component");
        assert_eq!(fetched.get_min_address(), component_addr);
    }

    #[test]
    fn reload_path_returns_none_when_listing_has_no_data_at_the_address() {
        let listing = MockListing { data_at: None, component_by_path: None };
        let program: Arc<dyn Program> = Arc::new(ReloadableProgram { listing });
        let d = data(addr(0x7000), vec![]);
        let proxy = DataProxy::new(model(), program, d);

        *proxy.data.borrow_mut() = None;
        assert!(proxy.get_object().is_none());
        assert!(!proxy.contains(&addr(0x7000)));
    }

    #[test]
    fn reload_path_returns_none_when_program_has_no_listing() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let d = data(addr(0x8000), vec![]);
        let proxy = DataProxy::new(model(), program, d);

        *proxy.data.borrow_mut() = None;
        assert!(proxy.get_object().is_none());
    }
}
