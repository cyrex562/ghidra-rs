//! Port of `ghidra.app.util.viewer.proxy.EmptyProxy`.
//!
//! Used as a proxy for a null value. Java's `EmptyProxy` is a private-constructor singleton
//! (`EMPTY_PROXY`) whose constructor calls `super(null)` -- i.e. the inherited `ProxyObj.model`
//! field is genuinely `null` for this one subclass. `ProxyObj.getListingLayoutModel()` simply
//! returns that field verbatim (no dereference, so no `NullPointerException` there); it's only a
//! caller that goes on to invoke a method on the returned `null` that would ever NPE.
//!
//! Rust's [`ProxyObj::base`](crate::app::util::viewer::proxy::proxy_obj::ProxyObj::base) contract
//! (see `proxy_obj.rs`) hands back a live `&ProxyObjBase` wrapping a real `Box<dyn ListingModel>`
//! -- there is no reference-typed way to represent "a valid handle to nothing" the way Java's
//! `null` can. Since [`EmptyProxy`] has no real model to hand back, and every real Java caller of
//! `getListingLayoutModel()` on it would either immediately NPE (if they dereference the result)
//! or otherwise be unable to use a `null` `ListingModel`, this port makes that failure immediate
//! and explicit instead of fabricating a fake non-null model Java never had: [`EmptyProxy`] does
//! not embed a [`ProxyObjBase`](crate::app::util::viewer::proxy::proxy_obj::ProxyObjBase) at all,
//! and [`ProxyObj::base`]/[`ProxyObj::base_mut`] panic if ever called. This is documented here and
//! covered by a dedicated test rather than silently "fixed" into always-succeeding accessors.

use crate::app::util::viewer::proxy::proxy_obj::{ProxyObj, ProxyObjBase};
use crate::program::model::address::Address;

/// Used as proxy for a null value.
///
/// Port of `ghidra.app.util.viewer.proxy.EmptyProxy`. Java's `getObject()` return type is the raw
/// `Object` (the type argument of `ProxyObj<Object>`) and always returns `null`; `()` stands in
/// for that always-absent `Object` type parameter here, with [`ProxyObj::get_object`] always
/// returning `None`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyProxy;

impl EmptyProxy {
    /// The singleton empty proxy instance.
    ///
    /// Port of the public field `EmptyProxy.EMPTY_PROXY`. Java allocates this once via the
    /// private constructor (`private EmptyProxy() { super(null); }`); since [`EmptyProxy`] here
    /// carries no state at all (see the module docs), a `const` zero-sized value serves the same
    /// purpose without needing lazy/static initialization.
    pub const EMPTY_PROXY: EmptyProxy = EmptyProxy;
}

impl ProxyObj<()> for EmptyProxy {
    /// # Panics
    ///
    /// Always panics. See the [module docs](self) for why: Java's real `model` field is `null`
    /// for this one subclass, and there is no non-panicking way to hand back a live
    /// `&ProxyObjBase` when there is no real model underneath it.
    fn base(&self) -> &ProxyObjBase {
        panic!("EmptyProxy has no backing ProxyObjBase -- its Java model field is null (see module docs)")
    }

    /// # Panics
    ///
    /// Always panics; see [`base`](Self::base).
    fn base_mut(&mut self) -> &mut ProxyObjBase {
        panic!("EmptyProxy has no backing ProxyObjBase -- its Java model field is null (see module docs)")
    }

    /// Mirrors `EmptyProxy.getObject()`, which always returns `null`.
    fn get_object(&self) -> Option<()> {
        None
    }

    /// Mirrors `EmptyProxy.contains(Address)`, which always returns `false`.
    fn contains(&self, _address: &Address) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn get_object_always_returns_none() {
        assert_eq!(EmptyProxy::EMPTY_PROXY.get_object(), None);
        assert_eq!(EmptyProxy.get_object(), None);
    }

    #[test]
    fn contains_always_returns_false() {
        assert!(!EmptyProxy::EMPTY_PROXY.contains(&addr(0)));
        assert!(!EmptyProxy::EMPTY_PROXY.contains(&addr(0x1000)));
    }

    #[test]
    #[should_panic(expected = "EmptyProxy has no backing ProxyObjBase")]
    fn base_panics_mirroring_the_null_java_model_field() {
        // Faithful quirk: Java's EmptyProxy passes `null` as its ProxyObj.model field. Calling
        // getListingLayoutModel() (which just returns that field) wouldn't itself NPE in Java,
        // but no Rust reference can stand in for that null, so base() panics instead. See the
        // module docs for the full rationale.
        let _ = EmptyProxy::EMPTY_PROXY.base();
    }

    #[test]
    #[should_panic(expected = "EmptyProxy has no backing ProxyObjBase")]
    fn base_mut_panics_mirroring_the_null_java_model_field() {
        let mut proxy = EmptyProxy::EMPTY_PROXY;
        let _ = proxy.base_mut();
    }

    #[test]
    #[should_panic(expected = "EmptyProxy has no backing ProxyObjBase")]
    fn get_listing_layout_model_default_method_panics_via_base() {
        // The trait's default get_listing_layout_model() forwards to base(), so it inherits the
        // same panic.
        let _ = EmptyProxy::EMPTY_PROXY.get_listing_layout_model();
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let proxy: Box<dyn ProxyObj<()>> = Box::new(EmptyProxy::EMPTY_PROXY);
        assert_eq!(proxy.get_object(), None);
        assert!(!proxy.contains(&addr(0)));
    }

    #[test]
    fn empty_proxy_instances_are_all_equal() {
        // Zero-sized, stateless type: every instance behaves identically, matching how Java's
        // singleton EMPTY_PROXY is the one and only instance ever constructed.
        assert_eq!(EmptyProxy, EmptyProxy::EMPTY_PROXY);
    }
}
