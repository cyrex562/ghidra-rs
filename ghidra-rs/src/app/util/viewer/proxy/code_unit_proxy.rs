use std::cell::RefCell;
use std::sync::Arc;

use crate::app::util::viewer::listingpanel::listing_model::ListingModel;
use crate::program::model::address::Address;
use crate::program::model::listing::{CodeUnit, Program};

use super::proxy_obj::{ProxyObj, ProxyObjBase};

/// Stores information about a code unit in a program.
///
/// Port of `ghidra.app.util.viewer.proxy.CodeUnitProxy`.
///
/// Java's `CodeUnitProxy extends ProxyObj<CodeUnit>`, contributing the `program`/`cu`/`addr`
/// fields and the two abstract methods. Following this crate's established composition
/// convention (see [`ProxyObjBase`]'s module doc comment), this embeds a `base: ProxyObjBase`
/// field rather than inheriting.
///
/// Java's `getObject()` mutates the `cu` field, but [`ProxyObj::get_object`] takes `&self`
/// (matching every other implementor of that trait in this crate), so the cached `cu` -- and the
/// `program` handle needed to refresh it -- are held behind [`RefCell`] for interior mutability.
pub struct CodeUnitProxy {
    base: ProxyObjBase,
    program: RefCell<Arc<dyn Program>>,
    cu: RefCell<Option<Arc<dyn CodeUnit>>>,
    addr: Address,
}

impl CodeUnitProxy {
    /// Constructs a proxy for a code unit.
    ///
    /// `model` is the listing model, `program` is the program containing the code unit, and `cu`
    /// is the code unit to proxy.
    ///
    /// Mirrors `CodeUnitProxy(ListingModel model, Program program, CodeUnit cu)`.
    pub fn new(model: Box<dyn ListingModel>, program: Arc<dyn Program>, cu: Arc<dyn CodeUnit>) -> Self {
        let addr = cu.get_min_address();
        Self {
            base: ProxyObjBase::new(model),
            program: RefCell::new(program),
            cu: RefCell::new(Some(cu)),
            addr,
        }
    }
}

impl ProxyObj<Arc<dyn CodeUnit>> for CodeUnitProxy {
    fn base(&self) -> &ProxyObjBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ProxyObjBase {
        &mut self.base
    }

    /// Mirrors `getObject()`.
    ///
    /// Java: if a cached `cu` is present, it defensively calls `cu.getMinAddress()`, catching a
    /// `ConcurrentModificationException` (thrown if the underlying DB record went stale
    /// mid-iteration) to fall through and reload via
    /// `program.getListing().getCodeUnitAt(addr)`; otherwise it reloads directly. This crate's
    /// [`CodeUnit::get_min_address`] is infallible -- no DB-staleness-exception mechanism has been
    /// ported alongside the DB code-unit representation -- so the call below can never trigger
    /// that fallback path; the cached `cu` is always returned as-is once present, matching the
    /// non-exceptional (overwhelmingly common) case Java also takes.
    fn get_object(&self) -> Option<Arc<dyn CodeUnit>> {
        if let Some(cu) = self.cu.borrow().clone() {
            let _ = cu.get_min_address();
            return Some(cu);
        }
        let mut program = self.program.borrow_mut();
        let fresh = Arc::get_mut(&mut program)
            .and_then(|p| p.get_listing())
            .and_then(|listing| listing.get_code_unit_at(&self.addr));
        *self.cu.borrow_mut() = fresh.clone();
        fresh
    }

    /// Mirrors `contains(Address)`.
    fn contains(&self, a: &Address) -> bool {
        match self.get_object() {
            Some(c) => c.contains(a),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{FormatManager, Layout};
    use crate::app::util::viewer::listingpanel::listing_model_listener::ListingModelListener;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{address_set::AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::instruction_stub::InstructionStub;
    use crate::program::model::listing::Listing;
    use crate::util::task::TaskMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// Minimal `CodeUnit` test double occupying a single address.
    ///
    /// [`InstructionStub`] blanket-implements [`MemBuffer`](crate::program::model::mem::MemBuffer),
    /// [`PropertySet`](crate::program::model::util::PropertySet), and [`CodeUnit`] with
    /// panicking bodies for everything; only the handful of methods this proxy actually calls
    /// (`get_min_address`, `contains`) need overriding.
    struct MockCodeUnit {
        min: Address,
    }

    impl InstructionStub for MockCodeUnit {
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

    struct MockProgram;
    impl DomainObject for MockProgram {}
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

    #[test]
    fn get_object_returns_the_cached_code_unit() {
        let cu: Arc<dyn CodeUnit> = Arc::new(MockCodeUnit { min: addr(0x1000) });
        let proxy = CodeUnitProxy::new(model(), Arc::new(MockProgram), cu.clone());
        let fetched = proxy.get_object().expect("cu is cached");
        assert_eq!(fetched.get_min_address(), addr(0x1000));
    }

    #[test]
    fn contains_delegates_to_the_code_unit() {
        let cu: Arc<dyn CodeUnit> = Arc::new(MockCodeUnit { min: addr(0x2000) });
        let proxy = CodeUnitProxy::new(model(), Arc::new(MockProgram), cu);
        assert!(proxy.contains(&addr(0x2000)));
        assert!(!proxy.contains(&addr(0x2001)));
    }

    #[test]
    fn base_accessors_expose_the_constructed_model() {
        let cu: Arc<dyn CodeUnit> = Arc::new(MockCodeUnit { min: addr(0x3000) });
        let mut proxy = CodeUnitProxy::new(model(), Arc::new(MockProgram), cu);
        assert!(!proxy.base().get_listing_layout_model().is_closed());
        assert!(!proxy.base_mut().get_listing_layout_model().is_closed());
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let cu: Arc<dyn CodeUnit> = Arc::new(MockCodeUnit { min: addr(0x4000) });
        let proxy: Box<dyn ProxyObj<Arc<dyn CodeUnit>>> =
            Box::new(CodeUnitProxy::new(model(), Arc::new(MockProgram), cu));
        assert!(proxy.contains(&addr(0x4000)));
        assert!(proxy.get_object().is_some());
    }
}
