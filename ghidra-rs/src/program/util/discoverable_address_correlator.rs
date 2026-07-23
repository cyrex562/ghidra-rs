use crate::program::util::address_correlation::AddressCorrelation;
use crate::util::classfinder::ExtensionPoint;

/// `AddressCorrelator`s that want to be discovered by version tracking should implement this
/// trait.
///
/// Port of `ghidra.program.util.DiscoverableAddressCorrelator`, a marker interface extending
/// `AddressCorrelator` (ported as [`AddressCorrelation`]) and `ExtensionPoint`. The Java interface
/// has no methods of its own; it simply provides an extension point for address correlators,
/// since we don't want all `AddressCorrelator` classes discovered, only the ones that opt in by
/// implementing this trait.
///
/// Selected as a dependency-cycle cut-point.
pub trait DiscoverableAddressCorrelator: AddressCorrelation + ExtensionPoint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::seam_stubs::AddressCorrelationRangeLike;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    struct NullCorrelator;

    impl AddressCorrelation for NullCorrelator {
        fn get_correlated_destination_range(
            &self,
            _source_address: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException> {
            monitor.check_cancelled()?;
            Ok(None)
        }
    }

    impl ExtensionPoint for NullCorrelator {}

    impl DiscoverableAddressCorrelator for NullCorrelator {}

    #[test]
    fn trait_object_is_both_correlator_and_extension_point() {
        let boxed: Box<dyn DiscoverableAddressCorrelator> = Box::new(NullCorrelator);
        let monitor = crate::util::task::DummyMonitor;
        let source = Address::new(
            crate::program::model::address::AddressSpace::new(
                "test",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                0,
            ),
            0x1000,
        );

        let result = boxed
            .get_correlated_destination_range(&source, &monitor)
            .expect("not cancelled");
        assert!(result.is_none());
    }
}
