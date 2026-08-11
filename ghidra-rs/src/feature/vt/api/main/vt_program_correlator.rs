use std::sync::Arc;

use crate::program::model::address::AddressSetView;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

use super::vt_match_set::VTMatchSet;
use super::vt_session::VTSession;
use crate::feature::seam_stubs::ToolOptions;

/// Interface for a program correlator that performs correlation between two programs.
///
/// A VTProgramCorrelator performs the correlation between two programs looking for how well
/// functions in one program correlate to functions in another program. The correlation
/// results are stored in a VTMatchSet.
///
/// Port of `ghidra.feature.vt.api.main.VTProgramCorrelator`.
pub trait VTProgramCorrelator: Send + Sync {
    /// Performs the correlation between two programs looking for how well functions in one program
    /// correlate to functions in another program.
    ///
    /// # Arguments
    ///
    /// * `session` - An existing manager that may contain previous results that may
    ///   influence this correlation.
    /// * `monitor` - A task monitor for reporting progress during the correlation.
    ///
    /// # Returns
    ///
    /// The match set created by this correlator used to store results.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the correlation operation fails or is cancelled via the task monitor.
    fn correlate(
        &self,
        session: &dyn VTSession,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Box<dyn VTMatchSet>>;

    /// Returns the name of the correlator.
    fn get_name(&self) -> String;

    /// Returns an options object populated with the options for this correlator instance.
    fn get_options(&self) -> Box<dyn ToolOptions>;

    /// Returns the address set associated with this correlator instance.
    fn get_source_address_set(&self) -> Box<dyn AddressSetView>;

    /// Returns the source program for this correlator instance.
    fn get_source_program(&self) -> Arc<dyn Program>;

    /// Returns the destination program for this correlator instance.
    fn get_destination_program(&self) -> Arc<dyn Program>;

    /// Returns the address set associated with this correlator instance.
    fn get_destination_address_set(&self) -> Box<dyn AddressSetView>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_object_can_be_created() {
        let correlator: Box<dyn VTProgramCorrelator> = Box::new(MockCorrelator {
            name: "test_correlator".to_string(),
        });

        assert_eq!(correlator.get_name(), "test_correlator");
    }

    #[test]
    fn get_name_returns_correlator_name() {
        let correlator = MockCorrelator {
            name: "my_correlator".to_string(),
        };

        assert_eq!(correlator.get_name(), "my_correlator");
    }

    #[test]
    fn get_options_returns_options() {
        let correlator = MockCorrelator {
            name: "correlator".to_string(),
        };

        let options = correlator.get_options();
        assert_eq!(options.get_option("key"), None);
    }

    #[test]
    fn get_source_address_set_returns_empty_set() {
        let correlator = MockCorrelator {
            name: "correlator".to_string(),
        };

        let addr_set = correlator.get_source_address_set();
        assert!(addr_set.is_empty());
    }

    #[test]
    fn get_destination_address_set_returns_empty_set() {
        let correlator = MockCorrelator {
            name: "correlator".to_string(),
        };

        let addr_set = correlator.get_destination_address_set();
        assert!(addr_set.is_empty());
    }

    struct MockCorrelator {
        name: String,
    }

    impl VTProgramCorrelator for MockCorrelator {
        fn correlate(
            &self,
            _session: &dyn VTSession,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<Box<dyn VTMatchSet>> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "not implemented"))
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_options(&self) -> Box<dyn ToolOptions> {
            Box::new(MockToolOptions)
        }

        fn get_source_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(MockAddressSetView)
        }

        fn get_source_program(&self) -> Arc<dyn Program> {
            panic!("not implemented")
        }

        fn get_destination_program(&self) -> Arc<dyn Program> {
            panic!("not implemented")
        }

        fn get_destination_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(MockAddressSetView)
        }
    }

    struct MockToolOptions;

    impl ToolOptions for MockToolOptions {
        fn get_option(&self, _key: &str) -> Option<String> {
            None
        }
    }

    struct MockAddressSetView;

    impl AddressSetView for MockAddressSetView {
        fn contains(&self, _address: &crate::program::model::address::Address) -> bool {
            false
        }

        fn contains_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }

        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn num_address_ranges(&self) -> usize {
            0
        }

        fn address_ranges(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            panic!("not implemented")
        }

        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            panic!("not implemented")
        }

        fn address_ranges_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            panic!("not implemented")
        }

        fn num_addresses(&self) -> u64 {
            0
        }

        fn addresses(
            &self,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            panic!("not implemented")
        }

        fn addresses_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            panic!("not implemented")
        }

        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn intersects_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }

        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn intersect_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn union(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn subtract(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn xor(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn range_containing(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn find_first_address_in_common(
            &self,
            _set: &dyn AddressSetView,
        ) -> Option<crate::program::model::address::Address> {
            None
        }
    }
}
