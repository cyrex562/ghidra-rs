use crate::app::util::viewer::listingpanel::listing_model::ListingModel;
use crate::program::model::address::Address;

use super::proxy_obj::{ProxyObj, ProxyObjBase};

/// Stores information about an address in a program.
///
/// Port of `ghidra.app.util.viewer.proxy.AddressProxy`.
///
/// Java's `AddressProxy extends ProxyObj<Address>`, contributing only the `addr` field and the
/// two abstract methods. Following this crate's established composition convention (see
/// [`ProxyObjBase`]'s module doc comment), this embeds a `base: ProxyObjBase` field rather than
/// inheriting.
///
/// `AddressProxy` and [`CodeUnitProxy`](super::code_unit_proxy::CodeUnitProxy) are siblings, not
/// parent/child: both extend `ProxyObj` directly in Java, neither extends the other.
pub struct AddressProxy {
    base: ProxyObjBase,
    addr: Address,
}

impl AddressProxy {
    /// Constructs an address proxy.
    ///
    /// Mirrors `AddressProxy(ListingModel model, Address addr)`.
    pub fn new(model: Box<dyn ListingModel>, addr: Address) -> Self {
        Self {
            base: ProxyObjBase::new(model),
            addr,
        }
    }
}

impl ProxyObj<Address> for AddressProxy {
    fn base(&self) -> &ProxyObjBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ProxyObjBase {
        &mut self.base
    }

    /// Mirrors `getObject()`, which always returns the proxied address.
    fn get_object(&self) -> Option<Address> {
        Some(self.addr.clone())
    }

    /// Mirrors `contains(Address)`.
    fn contains(&self, address: &Address) -> bool {
        &self.addr == address
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
    use crate::program::model::listing::program::Program;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
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
    fn get_object_always_returns_the_proxied_address() {
        let proxy = AddressProxy::new(model(), addr(0x1000));
        assert_eq!(proxy.get_object(), Some(addr(0x1000)));
    }

    #[test]
    fn contains_matches_only_the_proxied_address() {
        let proxy = AddressProxy::new(model(), addr(0x2000));
        assert!(proxy.contains(&addr(0x2000)));
        assert!(!proxy.contains(&addr(0x2001)));
    }

    #[test]
    fn base_accessors_expose_the_constructed_model() {
        let mut proxy = AddressProxy::new(model(), addr(0x3000));
        assert!(!proxy.base().get_listing_layout_model().is_closed());
        assert!(!proxy.base_mut().get_listing_layout_model().is_closed());
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let proxy: Box<dyn ProxyObj<Address>> = Box::new(AddressProxy::new(model(), addr(0x4000)));
        assert!(proxy.contains(&addr(0x4000)));
        assert_eq!(proxy.get_object(), Some(addr(0x4000)));
    }
}
