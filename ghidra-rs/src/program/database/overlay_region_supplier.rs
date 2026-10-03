//! Port of `ghidra.program.database.OverlayRegionSupplier`.
//!
//! Provides a callback mechanism which allows a `ProgramOverlayAddressSpace` to identify
//! defined memory regions within its space so that it may properly implement
//! `OverlayAddressSpace::contains`.

use crate::program::model::address::{AddressSetView, OverlayAddressSpace};

/// Callback mechanism which allows an overlay address space to identify defined memory regions
/// within its space.
pub trait OverlayRegionSupplier {
    /// Get the set of memory addresses defined within the specified overlay space, or `None` if
    /// no regions are defined.
    fn get_overlay_address_set(
        &self,
        overlay_space: &OverlayAddressSpace,
    ) -> Option<Box<dyn AddressSetView>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct SingleRegionSupplier {
        region: AddressSet,
    }

    impl OverlayRegionSupplier for SingleRegionSupplier {
        fn get_overlay_address_set(
            &self,
            _overlay_space: &OverlayAddressSpace,
        ) -> Option<Box<dyn AddressSetView>> {
            if self.region.is_empty() {
                None
            } else {
                Some(Box::new(self.region.clone()))
            }
        }
    }

    fn make_overlay_space(base: &Arc<AddressSpace>) -> OverlayAddressSpace {
        OverlayAddressSpace::new("OV_test", base.clone(), 1, "0", AddressSet::new())
    }

    #[test]
    fn supplier_reports_defined_overlay_regions() {
        let base = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let mut region = AddressSet::new();
        region.add_range(&base.address(0x1000), &base.address(0x1010));
        let supplier = SingleRegionSupplier { region };

        let overlay_space = make_overlay_space(&base);
        let result = supplier.get_overlay_address_set(&overlay_space);
        let set = result.expect("expected a defined region");
        assert!(set.contains(&base.address(0x1005)));
        assert!(!set.contains(&base.address(0x2000)));
    }

    #[test]
    fn supplier_reports_no_region_when_empty() {
        let base = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let supplier = SingleRegionSupplier {
            region: AddressSet::new(),
        };

        let overlay_space = make_overlay_space(&base);
        assert!(supplier.get_overlay_address_set(&overlay_space).is_none());
    }

    // Exercise the trait object surface to confirm object-safety.
    #[test]
    fn supplier_is_object_safe() {
        let base = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let mut region = AddressSet::new();
        region.add_range(&base.address(0), &base.address(0));
        let supplier: Box<dyn OverlayRegionSupplier> = Box::new(SingleRegionSupplier { region });

        let overlay_space = make_overlay_space(&base);
        assert!(supplier.get_overlay_address_set(&overlay_space).is_some());
    }
}
