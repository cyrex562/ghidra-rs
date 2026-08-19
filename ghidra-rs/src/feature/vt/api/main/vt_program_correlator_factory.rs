use std::sync::Arc;

use crate::feature::seam_stubs::VtOptions;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::program::Program;
use crate::util::classfinder::ExtensionPoint;

use super::vt_program_correlator::VTProgramCorrelator;
use super::vt_program_correlator_address_restriction_preference::VtProgramCorrelatorAddressRestrictionPreference;

/// Factory that creates [`VTProgramCorrelator`] instances configured for a given pair of
/// programs and address sets.
///
/// Port of `ghidra.feature.vt.api.main.VTProgramCorrelatorFactory`.
pub trait VTProgramCorrelatorFactory: ExtensionPoint + Send + Sync {
    /// Returns the name of the correlator for display to the user in the GUI.
    fn get_name(&self) -> String;

    /// Returns the description of the correlator for display to the user in the GUI.
    fn get_description(&self) -> String;

    /// Returns the listing priority of the correlator; lower means higher in the list.
    fn get_priority(&self) -> i32;

    /// Returns the restriction preference of the correlator.
    fn get_address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference;

    /// Returns an options object populated with all supported options for the algorithm and
    /// their default values.
    fn create_default_options(&self) -> VtOptions;

    /// Returns a [`VTProgramCorrelator`] instance created specifically for the given parameters.
    fn create_correlator(
        &self,
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: &VtOptions,
    ) -> Box<dyn VTProgramCorrelator>;

    /// Returns a [`VTProgramCorrelator`] instance created specifically for the given parameters.
    #[deprecated(note = "use create_correlator instead")]
    fn create_correlator_with_service_provider(
        &self,
        service_provider: &dyn ServiceProvider,
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: &VtOptions,
    ) -> Box<dyn VTProgramCorrelator>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::ToolOptions;
    use crate::feature::vt::api::main::vt_session::VTSession;
    use crate::util::task::TaskMonitor;

    struct MockFactory;

    impl ExtensionPoint for MockFactory {}

    impl VTProgramCorrelatorFactory for MockFactory {
        fn get_name(&self) -> String {
            "Exact Symbol Match".to_string()
        }

        fn get_description(&self) -> String {
            "Matches functions with identical symbol names".to_string()
        }

        fn get_priority(&self) -> i32 {
            50
        }

        fn get_address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference
        }

        fn create_default_options(&self) -> VtOptions {
            VtOptions::default()
        }

        fn create_correlator(
            &self,
            _source_program: Arc<dyn Program>,
            _source_address_set: &dyn AddressSetView,
            _destination_program: Arc<dyn Program>,
            _destination_address_set: &dyn AddressSetView,
            _options: &VtOptions,
        ) -> Box<dyn VTProgramCorrelator> {
            Box::new(MockCorrelator)
        }

        fn create_correlator_with_service_provider(
            &self,
            _service_provider: &dyn ServiceProvider,
            source_program: Arc<dyn Program>,
            source_address_set: &dyn AddressSetView,
            destination_program: Arc<dyn Program>,
            destination_address_set: &dyn AddressSetView,
            options: &VtOptions,
        ) -> Box<dyn VTProgramCorrelator> {
            self.create_correlator(
                source_program,
                source_address_set,
                destination_program,
                destination_address_set,
                options,
            )
        }
    }

    struct MockCorrelator;

    impl VTProgramCorrelator for MockCorrelator {
        fn correlate(
            &self,
            _session: &dyn VTSession,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<Box<dyn crate::feature::vt::api::main::vt_match_set::VTMatchSet>> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "not implemented"))
        }

        fn get_name(&self) -> String {
            "Exact Symbol Match".to_string()
        }

        fn get_options(&self) -> Box<dyn ToolOptions> {
            panic!("not implemented")
        }

        fn get_source_address_set(&self) -> Box<dyn AddressSetView> {
            panic!("not implemented")
        }

        fn get_source_program(&self) -> Arc<dyn Program> {
            panic!("not implemented")
        }

        fn get_destination_program(&self) -> Arc<dyn Program> {
            panic!("not implemented")
        }

        fn get_destination_address_set(&self) -> Box<dyn AddressSetView> {
            panic!("not implemented")
        }
    }

    #[test]
    fn getters_return_expected_values() {
        let factory = MockFactory;

        assert_eq!(factory.get_name(), "Exact Symbol Match");
        assert_eq!(
            factory.get_description(),
            "Matches functions with identical symbol names"
        );
        assert_eq!(factory.get_priority(), 50);
        assert_eq!(
            factory.get_address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference
        );
    }

    #[test]
    fn trait_object_can_be_created_and_dispatched() {
        let factory: Box<dyn VTProgramCorrelatorFactory> = Box::new(MockFactory);
        assert_eq!(factory.get_name(), "Exact Symbol Match");
        assert_eq!(factory.get_priority(), 50);

        let options = factory.create_default_options();
        assert_eq!(options, VtOptions::default());
    }
}
