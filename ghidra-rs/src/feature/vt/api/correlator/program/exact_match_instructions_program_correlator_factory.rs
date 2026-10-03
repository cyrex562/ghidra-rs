use std::sync::Arc;

use crate::feature::seam_stubs::VtOptions;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::feature::vt::api::main::vt_program_correlator_address_restriction_preference::VtProgramCorrelatorAddressRestrictionPreference;
use crate::feature::vt::api::main::vt_program_correlator_factory::VTProgramCorrelatorFactory;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::program::Program;
use crate::util::classfinder::ExtensionPoint;

use super::seam_stubs::{ExactInstructionsFunctionHasher, FunctionMatchProgramCorrelator};

/// Compares code by hashing instructions, looking for identical functions. Reports back any
/// that have ONLY ONE identical match.
///
/// Port of `ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory`.
/// Java `extends VTAbstractProgramCorrelatorFactory`; since Rust has no class inheritance, this
/// folds in the abstract base's template-method behavior (the base's `createCorrelator`
/// delegating to this subclass's `doCreateCorrelator`, and its default address-restriction
/// preference) directly into the [`VTProgramCorrelatorFactory`] impl below, rather than porting
/// `VTAbstractProgramCorrelatorFactory` itself (out of scope for this leaf).
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactMatchInstructionsProgramCorrelatorFactory;

impl ExactMatchInstructionsProgramCorrelatorFactory {
    /// Port of `ExactMatchInstructionsProgramCorrelatorFactory.DESC`.
    pub const DESC: &'static str = "Compares code by hashing instructions, looking for identical functions. It reports back any that have ONLY ONE identical match.";
    /// Port of `ExactMatchInstructionsProgramCorrelatorFactory.EXACT_MATCH`.
    pub const EXACT_MATCH: &'static str = "Exact Function Instructions Match";
    /// Port of `ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE`.
    pub const FUNCTION_MINIMUM_SIZE: &'static str = "Function Minimum Size";
    /// Port of `ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE_DEFAULT`.
    pub const FUNCTION_MINIMUM_SIZE_DEFAULT: i32 = 10;

    pub fn new() -> Self {
        Self
    }
}

impl ExtensionPoint for ExactMatchInstructionsProgramCorrelatorFactory {}

impl VTProgramCorrelatorFactory for ExactMatchInstructionsProgramCorrelatorFactory {
    /// Port of `getName()`.
    fn get_name(&self) -> String {
        Self::EXACT_MATCH.to_string()
    }

    /// Port of `getDescription()`.
    fn get_description(&self) -> String {
        Self::DESC.to_string()
    }

    /// Port of `getPriority()`.
    fn get_priority(&self) -> i32 {
        30
    }

    /// Port of `VTAbstractProgramCorrelatorFactory`'s default (this class does not override it):
    /// `VTProgramCorrelatorAddressRestrictionPreference.PREFER_RESTRICTING_ACCEPTED_MATCHES`.
    fn get_address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
    }

    /// Port of `createDefaultOptions()`. The real Java method also calls
    /// `options.setInt(FUNCTION_MINIMUM_SIZE, FUNCTION_MINIMUM_SIZE_DEFAULT)`, but the `VtOptions`
    /// placeholder does not yet carry option values (see `crate::feature::seam_stubs::VtOptions`);
    /// `FUNCTION_MINIMUM_SIZE`/`FUNCTION_MINIMUM_SIZE_DEFAULT` are kept as associated constants
    /// above so the real port can wire them in once `VtOptions` grows storage.
    fn create_default_options(&self) -> VtOptions {
        VtOptions::default()
    }

    /// Port of `VTAbstractProgramCorrelatorFactory.createCorrelator`, folded together with this
    /// class's `doCreateCorrelator` override: builds a `FunctionMatchProgramCorrelator` comparing
    /// whole functions (`onlyOneFunctionPair = true`) using `ExactInstructionsFunctionHasher`.
    fn create_correlator(
        &self,
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: &VtOptions,
    ) -> Box<dyn VTProgramCorrelator> {
        Box::new(FunctionMatchProgramCorrelator::new(
            source_program,
            source_address_set,
            destination_program,
            destination_address_set,
            options.clone(),
            Self::EXACT_MATCH.to_string(),
            true,
            ExactInstructionsFunctionHasher,
        ))
    }

    /// Deprecated in Java; delegates to [`create_correlator`](Self::create_correlator).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getters_match_java_constants() {
        let factory = ExactMatchInstructionsProgramCorrelatorFactory::new();
        assert_eq!(factory.get_name(), "Exact Function Instructions Match");
        assert_eq!(factory.get_priority(), 30);
        assert_eq!(
            factory.get_description(),
            "Compares code by hashing instructions, looking for identical functions. It reports back any that have ONLY ONE identical match."
        );
        assert_eq!(
            factory.get_address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
        );
        assert_eq!(
            ExactMatchInstructionsProgramCorrelatorFactory::FUNCTION_MINIMUM_SIZE_DEFAULT,
            10
        );
    }

    #[test]
    fn create_default_options_returns_options() {
        let factory = ExactMatchInstructionsProgramCorrelatorFactory::new();
        let options = factory.create_default_options();
        assert_eq!(options, VtOptions::default());
    }

    #[test]
    fn trait_object_usable_via_factory_interface() {
        let factory: Box<dyn VTProgramCorrelatorFactory> =
            Box::new(ExactMatchInstructionsProgramCorrelatorFactory::new());
        assert_eq!(factory.get_name(), "Exact Function Instructions Match");
        assert_eq!(factory.get_priority(), 30);
    }
}
