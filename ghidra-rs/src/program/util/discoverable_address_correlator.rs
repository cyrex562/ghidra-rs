use crate::program::util::address_correlator::AddressCorrelator;
use crate::util::classfinder::ExtensionPoint;

/// `AddressCorrelator`s that want to be discovered by version tracking should implement this
/// trait.
///
/// Port of `ghidra.program.util.DiscoverableAddressCorrelator`, a marker interface extending
/// [`AddressCorrelator`] and `ExtensionPoint`. The Java interface has no methods of its own; it
/// simply provides an extension point for address correlators, since we don't want all
/// `AddressCorrelator` classes discovered, only the ones that opt in by implementing this trait.
///
/// Selected as a dependency-cycle cut-point.
///
/// This previously bounded on [`AddressCorrelation`](crate::program::util::AddressCorrelation)
/// as a stand-in, since `AddressCorrelator` had not yet been ported; now that
/// [`AddressCorrelator`] exists, this trait's supertrait matches the Java `extends` clause.
pub trait DiscoverableAddressCorrelator: AddressCorrelator + ExtensionPoint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::options::Options;
    use crate::framework::seam_stubs::ToolOptions;
    use crate::program::model::address::Address;
    use crate::program::model::listing::{Data, Function};
    use crate::program::util::address_correlation::AddressCorrelation;
    use crate::program::seam_stubs::AddressCorrelationRangeLike;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    struct NullCorrelation;

    impl AddressCorrelation for NullCorrelation {
        fn get_correlated_destination_range(
            &self,
            _source_address: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException> {
            monitor.check_cancelled()?;
            Ok(None)
        }
    }

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    struct NullCorrelator;

    impl AddressCorrelator for NullCorrelator {
        fn correlate_functions(
            &self,
            _source_function: &dyn Function,
            _destination_function: &dyn Function,
        ) -> Option<Box<dyn AddressCorrelation>> {
            Some(Box::new(NullCorrelation))
        }

        fn correlate_data(
            &self,
            _source_data: &dyn Data,
            _destination_data: &dyn Data,
        ) -> Option<Box<dyn AddressCorrelation>> {
            Some(Box::new(NullCorrelation))
        }

        fn get_options(&self) -> Box<dyn ToolOptions> {
            Box::new(StubToolOptions)
        }

        fn set_options(&mut self, _options: Box<dyn ToolOptions>) {}

        fn get_default_options(&self) -> Box<dyn Options> {
            struct EmptyOptions;
            impl Options for EmptyOptions {}
            Box::new(EmptyOptions)
        }
    }

    impl ExtensionPoint for NullCorrelator {}

    impl DiscoverableAddressCorrelator for NullCorrelator {}

    #[test]
    fn trait_object_is_both_correlator_and_extension_point() {
        let boxed: Box<dyn DiscoverableAddressCorrelator> = Box::new(NullCorrelator);

        // Default priority is inherited from `AddressCorrelator::get_priority`'s default body,
        // reachable through the combined `AddressCorrelator + ExtensionPoint` trait object.
        assert_eq!(
            boxed.get_priority(),
            crate::program::util::address_correlator::DEFAULT_PRIORITY
        );

        // `AddressCorrelation` mappings reached through `get_options`/`get_default_options` on
        // the same trait object confirm both supertraits are simultaneously reachable, not just
        // separately implementable.
        let _ = boxed.get_options();
        let default_options = boxed.get_default_options();
        assert_eq!(default_options.get_name(), String::new());
    }
}
