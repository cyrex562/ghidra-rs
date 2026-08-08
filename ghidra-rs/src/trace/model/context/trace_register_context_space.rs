use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::context::trace_register_context_operations::TraceRegisterContextOperations;

/// A single address space's view of register (processor context) values within a trace.
///
/// Port of `ghidra.trace.model.context.TraceRegisterContextSpace`.
pub trait TraceRegisterContextSpace: TraceRegisterContextOperations {
    /// Gets the address space to which this register context space applies.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSetView, AddressSpaceType};
    use crate::program::model::lang::{Language, Register};
    use crate::program::seam_stubs::RegisterValue;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TracePlatform;

    /// A minimal implementor proving `TraceRegisterContextSpace` is object-safe and that
    /// `get_address_space` returns the space bound at construction.
    struct MockContextSpace {
        space: Arc<AddressSpace>,
    }

    impl TraceRegisterContextOperations for MockContextSpace {
        fn get_default_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn set_value(
            &mut self,
            _language: &dyn Language,
            _value: &dyn RegisterValue,
            _lifespan: &dyn Lifespan,
            _range: &AddressRange,
        ) {
        }

        fn remove_value(
            &mut self,
            _language: &dyn Language,
            _register: &Register,
            _span: &dyn Lifespan,
            _range: &AddressRange,
        ) {
        }

        fn get_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_entry(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)> {
            None
        }

        fn get_value_with_default(
            &self,
            _platform: &dyn TracePlatform,
            _register: &Register,
            _snap: i64,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_register_value_address_ranges_within(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn get_register_value_address_ranges(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
        ) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn has_register_value_in_address_range(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _snap: i64,
            _within: &AddressRange,
        ) -> bool {
            false
        }

        fn has_register_value(&self, _language: &dyn Language, _register: &Register, _snap: i64) -> bool {
            false
        }

        fn clear(&mut self, _span: &dyn Lifespan, _range: &AddressRange) {}
    }

    impl TraceRegisterContextSpace for MockContextSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    #[test]
    fn get_address_space_round_trips_through_trait_object() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let ctx_space: Box<dyn TraceRegisterContextSpace> =
            Box::new(MockContextSpace { space: space.clone() });

        assert_eq!(ctx_space.get_address_space().name(), space.name());
        assert!(Arc::ptr_eq(&ctx_space.get_address_space(), &space));
    }
}
