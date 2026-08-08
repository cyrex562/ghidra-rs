//! Port of `ghidra.trace.database.space.DBTraceSpaceBased`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::trace::util::trace_space_mixin::TraceSpaceMixin;

/// Common behavior for database objects that are keyed by an address space.
///
/// Port of `ghidra.trace.database.space.DBTraceSpaceBased`.
pub trait DBTraceSpaceBased: TraceSpaceMixin {
    /// Check whether the given address space is this object's own address space.
    ///
    /// Mirrors Java's `space == getAddressSpace()` reference-identity check.
    fn is_my_space(&self, space: &Arc<AddressSpace>) -> bool {
        Arc::ptr_eq(space, &self.get_address_space())
    }

    /// Append a hint when a foreign address space's name collides with this object's own,
    /// suggesting the two addresses likely come from different languages.
    fn explain_languages(&self, space: &Arc<AddressSpace>) -> String {
        if space.name() == self.get_address_space().name() {
            ". It's likely they come from different languages. Check the platform.".to_string()
        } else {
            String::new()
        }
    }

    /// Assert that `addr` belongs to this object's address space, returning its offset.
    ///
    /// Panics, mirroring Java's `IllegalArgumentException`, if the address is foreign.
    fn assert_in_space(&self, addr: &Address) -> i64 {
        if !self.is_my_space(addr.space()) {
            panic!(
                "Address '{}' is not in this space: '{}'{}",
                addr,
                self.get_address_space().name(),
                self.explain_languages(addr.space())
            );
        }
        addr.offset()
    }

    /// Assert that `range` belongs to this object's address space.
    ///
    /// Panics, mirroring Java's `IllegalArgumentException`, if the range is foreign.
    fn assert_range_in_space(&self, range: &AddressRange) {
        if !self.is_my_space(range.space()) {
            panic!(
                "Address Range '{}' is not in this space: '{}'{}",
                range,
                self.get_address_space().name(),
                self.explain_languages(range.space())
            );
        }
    }

    /// Translate a physical address into this object's (possibly overlay) address space.
    ///
    /// The base `AddressSpace` never requires overlay translation, so this returns the address
    /// unchanged, matching `AbstractAddressSpace.getOverlayAddress`'s default behavior in Java.
    fn to_overlay(&self, physical: &Address) -> Address {
        physical.clone()
    }

    /// Build an address at the given offset in this object's address space.
    fn to_address(&self, offset: i64) -> Address {
        self.get_address_space().address(offset)
    }

    /// Invalidate any cached address-set view backed by this space.
    fn invalidate_cache(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::{TraceRegisterUtils, TraceThread};

    struct MockThread;
    impl TraceThread for MockThread {}

    struct MockRegisterUtils;
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
            unimplemented!("not exercised by this smoke test")
        }

        fn buffer_for_value(
            &self,
            _register: &crate::program::model::lang::Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &crate::program::model::lang::Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockSpaceBased {
        space: Arc<AddressSpace>,
        utils: MockRegisterUtils,
        invalidated: bool,
    }

    impl TraceSpaceMixin for MockSpaceBased {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.utils
        }
    }

    impl DBTraceSpaceBased for MockSpaceBased {
        fn invalidate_cache(&mut self) {
            self.invalidated = true;
        }
    }

    #[test]
    fn assert_in_space_accepts_own_addresses_and_rejects_foreign_ones() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let other = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let obj = MockSpaceBased { space: space.clone(), utils: MockRegisterUtils, invalidated: false };

        let own_addr = Address::new(space.clone(), 0x100);
        assert_eq!(obj.assert_in_space(&own_addr), 0x100);

        let foreign_addr = Address::new(other, 0x10);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            obj.assert_in_space(&foreign_addr)
        }));
        assert!(result.is_err());
    }

    #[test]
    fn to_overlay_and_to_address_and_invalidate_via_trait_object() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let mut obj = MockSpaceBased { space: space.clone(), utils: MockRegisterUtils, invalidated: false };

        let physical = Address::new(space.clone(), 0x40);
        assert_eq!(obj.to_overlay(&physical), physical);
        assert_eq!(obj.to_address(0x40), physical);

        let dyn_obj: &mut dyn DBTraceSpaceBased = &mut obj;
        dyn_obj.invalidate_cache();
        assert!(obj.invalidated);
    }
}
