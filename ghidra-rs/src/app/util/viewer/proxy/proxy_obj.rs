//! Shared state and concrete behavior for "proxy object" implementations that hold an object from
//! a program (e.g. `CodeUnit`, `Function`, ...) in a way that is robust against changes to the
//! program (avoiding stale references).
//!
//! Port of `ghidra.app.util.viewer.proxy.ProxyObj`.
//!
//! Java's `ProxyObj<T>` is an abstract class: it carries the `model` field, a package-private
//! constructor that sets it, and a concrete `getListingLayoutModel()` accessor, while leaving
//! `getObject()` and `contains(Address)` abstract for each concrete subclass to implement. Rust
//! has no field inheritance, so [`ProxyObjBase`] holds the shared field plus the concrete,
//! non-abstract logic, while [`ProxyObj`] (a trait, generic over `T` to mirror Java's `<T>`)
//! declares only the two methods a concrete proxy must still supply, plus `base`/`base_mut`
//! accessors a concrete type uses to expose its embedded [`ProxyObjBase`]. This is the same
//! "`*Base` struct + accessor trait" shape already established by
//! [`AbstractStep`](crate::trace::model::time::schedule::abstract_step::AbstractStep) for the
//! analogous Java `AbstractStep` abstract class.
//!
//! The seven concrete subclasses in Java (`AddressProxy`, `ClosedVariableProxy`, `CodeUnitProxy`,
//! `DataProxy`, `EmptyProxy`, `FunctionProxy`, `VariableProxy`) are not ported yet; each would
//! embed a [`ProxyObjBase`], implement [`ProxyObj::base`]/[`ProxyObj::base_mut`] to expose it, and
//! implement [`ProxyObj::get_object`]/[`ProxyObj::contains`] with its own logic (mirroring how they
//! call `super(model)` and override the two abstract methods in Java).
//!
//! Java's `getObject()` returns `T` and is documented as returning `null` "if the object no
//! longer exists"; that nullability is made explicit here as `Option<T>` rather than relying on a
//! (potentially non-nullable) `T` to represent absence.

use crate::app::util::viewer::listingpanel::listing_model::ListingModel;
use crate::program::model::address::Address;

/// The shared state of a [`ProxyObj`] implementation: the [`ListingModel`] it was constructed
/// with.
///
/// Port of the field and constructor of `ghidra.app.util.viewer.proxy.ProxyObj`.
pub struct ProxyObjBase {
    model: Box<dyn ListingModel>,
}

impl ProxyObjBase {
    /// Mirrors the package-private constructor `ProxyObj(ListingModel model)`.
    pub fn new(model: Box<dyn ListingModel>) -> Self {
        ProxyObjBase { model }
    }

    /// Returns the layout model which corresponds to this field proxy.
    ///
    /// Port of `ProxyObj.getListingLayoutModel()`.
    pub fn get_listing_layout_model(&self) -> &dyn ListingModel {
        self.model.as_ref()
    }
}

/// Implementing types hold an object from a program (e.g. `CodeUnit`, `Function`, ...) in such a
/// way as to be robust against changes to the program. In other words, it protects against
/// holding on to "stale" objects. [`ProxyObj::get_object`] returns the represented object
/// (refreshed if it was stale) or `None` if it no longer exists.
///
/// `T` is the proxy object type.
///
/// Port of `ghidra.app.util.viewer.proxy.ProxyObj<T>`. See the module docs for how this relates to
/// [`ProxyObjBase`].
pub trait ProxyObj<T> {
    /// Access the shared proxy state.
    fn base(&self) -> &ProxyObjBase;

    /// Mutably access the shared proxy state.
    fn base_mut(&mut self) -> &mut ProxyObjBase;

    /// Returns the layout model which corresponds to this field proxy.
    ///
    /// Port of `ProxyObj.getListingLayoutModel()`, forwarded to the embedded [`ProxyObjBase`].
    fn get_listing_layout_model(&self) -> &dyn ListingModel {
        self.base().get_listing_layout_model()
    }

    /// Returns the object that this proxy represents, or `None` if the object no longer exists.
    ///
    /// Port of the abstract method `ProxyObj.getObject()`.
    fn get_object(&self) -> Option<T>;

    /// Returns true if the proxy object of this type contains the given address.
    ///
    /// Port of the abstract method `ProxyObj.contains(Address)`.
    fn contains(&self, address: &Address) -> bool;
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

    /// Minimal `ListingModel` test double; only `is_closed`/`copy` are exercised by these tests,
    /// the rest exist purely to satisfy the trait's object-safety.
    struct MockListingModel {
        closed: bool,
    }

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
            self.closed
        }
        fn set_format_manager(&mut self, _format_manager: Box<dyn FormatManager>) {}
        fn dispose(&mut self) {
            self.closed = true;
        }
        fn adjust_address_set_to_code_unit_boundaries(&self, address_set: &AddressSet) -> AddressSet {
            address_set.clone()
        }
        fn copy(&self) -> Box<dyn ListingModel> {
            Box::new(MockListingModel { closed: self.closed })
        }
        fn is_function_open(&self, _function_address: &Address) -> bool {
            false
        }
        fn set_function_open(&mut self, _function_address: &Address, _open: bool) {}
        fn set_all_functions_open(&mut self, _open: bool) {}
    }

    /// A minimal concrete proxy over a plain address, standing in for a not-yet-ported
    /// `AddressProxy`. `get_object()` returns `None` once "stale" (mirroring how a real subclass
    /// would return `None` if the underlying program object no longer exists), and `contains`
    /// checks for exact address equality (an `AddressProxy` only "contains" its own address).
    struct MockAddressProxy {
        base: ProxyObjBase,
        address: Address,
        stale: bool,
    }

    impl MockAddressProxy {
        fn new(model: Box<dyn ListingModel>, address: Address) -> Self {
            MockAddressProxy { base: ProxyObjBase::new(model), address, stale: false }
        }
    }

    impl ProxyObj<Address> for MockAddressProxy {
        fn base(&self) -> &ProxyObjBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut ProxyObjBase {
            &mut self.base
        }

        fn get_object(&self) -> Option<Address> {
            if self.stale {
                None
            } else {
                Some(self.address.clone())
            }
        }

        fn contains(&self, address: &Address) -> bool {
            !self.stale && self.address.offset() == address.offset()
        }
    }

    #[test]
    fn get_listing_layout_model_returns_the_constructed_model() {
        let model: Box<dyn ListingModel> = Box::new(MockListingModel { closed: false });
        let proxy = MockAddressProxy::new(model, addr(0x10));

        assert!(!proxy.get_listing_layout_model().is_closed());
    }

    #[test]
    fn base_and_base_mut_expose_the_same_underlying_model() {
        let model: Box<dyn ListingModel> = Box::new(MockListingModel { closed: false });
        let mut proxy = MockAddressProxy::new(model, addr(0x10));

        assert!(!proxy.base().get_listing_layout_model().is_closed());

        // Mutate the model through the mutable base accessor and observe the change through the
        // trait's default `get_listing_layout_model`, proving `base`/`base_mut` share one model.
        let model_mut = proxy.base_mut();
        // ListingModel::dispose is the only mutating method available on the trait object.
        let boxed: &mut Box<dyn ListingModel> = &mut model_mut.model;
        boxed.dispose();
        assert!(proxy.get_listing_layout_model().is_closed());
    }

    #[test]
    fn get_object_returns_none_once_stale() {
        let model: Box<dyn ListingModel> = Box::new(MockListingModel { closed: false });
        let mut proxy = MockAddressProxy::new(model, addr(0x20));

        assert_eq!(proxy.get_object(), Some(addr(0x20)));

        proxy.stale = true;
        assert_eq!(proxy.get_object(), None);
    }

    #[test]
    fn contains_matches_only_the_proxied_address() {
        let model: Box<dyn ListingModel> = Box::new(MockListingModel { closed: false });
        let proxy = MockAddressProxy::new(model, addr(0x30));

        assert!(proxy.contains(&addr(0x30)));
        assert!(!proxy.contains(&addr(0x31)));
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let model: Box<dyn ListingModel> = Box::new(MockListingModel { closed: false });
        let proxy: Box<dyn ProxyObj<Address>> = Box::new(MockAddressProxy::new(model, addr(0x40)));

        assert!(proxy.contains(&addr(0x40)));
        assert_eq!(proxy.get_object(), Some(addr(0x40)));
    }
}
