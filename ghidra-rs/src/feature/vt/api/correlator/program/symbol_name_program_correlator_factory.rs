use std::sync::Arc;

use crate::feature::seam_stubs::VtOptions;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::feature::vt::api::main::vt_program_correlator_address_restriction_preference::VtProgramCorrelatorAddressRestrictionPreference;
use crate::feature::vt::api::main::vt_program_correlator_factory::VTProgramCorrelatorFactory;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::program::Program;
use crate::util::classfinder::ExtensionPoint;

use super::seam_stubs::SymbolNameProgramCorrelator;

/// Compares symbols by iterating over all defined function and data symbols meeting the minimum
/// size requirement in the source program and looking for identical symbol matches in the
/// destination program. It ignores default symbols such as those starting with `FUN_`, `DAT_`,
/// `s_`, and `u_`. It strips off the ending address that is sometimes included on symbols. It
/// reports back any that have ONLY ONE identical match.
///
/// Port of `ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory`. Java
/// `extends VTAbstractProgramCorrelatorFactory`; since Rust has no class inheritance, this folds
/// in the abstract base's template-method behavior (the base's `createCorrelator` delegating to
/// this subclass's `doCreateCorrelator`, and its default address-restriction preference) directly
/// into the [`VTProgramCorrelatorFactory`] impl below, rather than porting
/// `VTAbstractProgramCorrelatorFactory` itself -- the same treatment
/// `ExactMatchInstructionsProgramCorrelatorFactory` gives it.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymbolNameProgramCorrelatorFactory;

impl SymbolNameProgramCorrelatorFactory {
    /// Port of `SymbolNameProgramCorrelatorFactory.DESC`.
    pub const DESC: &'static str = "Compares symbols by iterating over all defined function and data symbols meeting the minimum size requirement in the source program and looking for identical symbol matches in the destination program. It ignores default symbols such as those starting with FUN_, DAT_, s_, and u_. It strips off the ending address that is sometimes included on symbols. It reports back any that have ONLY ONE identical match.";
    /// Port of `SymbolNameProgramCorrelatorFactory.EXACT_SYMBOL_MATCH`.
    pub const EXACT_SYMBOL_MATCH: &'static str = "Exact Symbol Name Match";
    /// Port of `SymbolNameProgramCorrelatorFactory.MIN_SYMBOL_NAME_LENGTH`.
    pub const MIN_SYMBOL_NAME_LENGTH: &'static str = "Minimum Symbol Name Length";
    /// Port of `SymbolNameProgramCorrelatorFactory.MIN_SYMBOL_NAME_LENGTH_DEFAULT`.
    pub const MIN_SYMBOL_NAME_LENGTH_DEFAULT: i32 = 3;
    /// Port of `SymbolNameProgramCorrelatorFactory.INCLUDE_EXTERNAL_SYMBOLS`.
    pub const INCLUDE_EXTERNAL_SYMBOLS: &'static str = "Include External Function Symbols";
    /// Port of `SymbolNameProgramCorrelatorFactory.INCLUDE_EXTERNAL_SYMBOLS_DEFAULT`.
    pub const INCLUDE_EXTERNAL_SYMBOLS_DEFAULT: bool = true;

    pub fn new() -> Self {
        Self
    }
}

impl ExtensionPoint for SymbolNameProgramCorrelatorFactory {}

impl VTProgramCorrelatorFactory for SymbolNameProgramCorrelatorFactory {
    /// Port of `getName()`.
    fn get_name(&self) -> String {
        Self::EXACT_SYMBOL_MATCH.to_string()
    }

    /// Port of `getDescription()`.
    fn get_description(&self) -> String {
        Self::DESC.to_string()
    }

    /// Port of `getPriority()`.
    fn get_priority(&self) -> i32 {
        40
    }

    /// Port of `VTAbstractProgramCorrelatorFactory`'s default (this class does not override it):
    /// `VTProgramCorrelatorAddressRestrictionPreference.PREFER_RESTRICTING_ACCEPTED_MATCHES`.
    fn get_address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
    }

    /// Port of `createDefaultOptions()`. The real Java method also calls
    /// `options.setInt(MIN_SYMBOL_NAME_LENGTH, MIN_SYMBOL_NAME_LENGTH_DEFAULT)` and
    /// `options.setBoolean(INCLUDE_EXTERNAL_SYMBOLS, INCLUDE_EXTERNAL_SYMBOLS_DEFAULT)`, but the
    /// `VtOptions` placeholder does not yet carry option values (see
    /// `crate::feature::seam_stubs::VtOptions`); the constants above are kept as associated
    /// constants so the real port can wire them in once `VtOptions` grows storage.
    fn create_default_options(&self) -> VtOptions {
        VtOptions::default()
    }

    /// Port of `VTAbstractProgramCorrelatorFactory.createCorrelator`, folded together with this
    /// class's `doCreateCorrelator` override: builds a `SymbolNameProgramCorrelator` comparing
    /// symbol names one-to-one (`oneToOne = true`).
    fn create_correlator(
        &self,
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: &VtOptions,
    ) -> Box<dyn VTProgramCorrelator> {
        Box::new(SymbolNameProgramCorrelator::new(
            source_program,
            source_address_set,
            destination_program,
            destination_address_set,
            options.clone(),
            Self::EXACT_SYMBOL_MATCH.to_string(),
            true,
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
        let factory = SymbolNameProgramCorrelatorFactory::new();
        assert_eq!(factory.get_name(), "Exact Symbol Name Match");
        assert_eq!(factory.get_priority(), 40);
        assert!(factory.get_description().starts_with("Compares symbols by iterating"));
        assert_eq!(
            factory.get_address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
        );
        assert_eq!(SymbolNameProgramCorrelatorFactory::MIN_SYMBOL_NAME_LENGTH_DEFAULT, 3);
        assert!(SymbolNameProgramCorrelatorFactory::INCLUDE_EXTERNAL_SYMBOLS_DEFAULT);
    }

    #[test]
    fn create_default_options_returns_options() {
        let factory = SymbolNameProgramCorrelatorFactory::new();
        let options = factory.create_default_options();
        assert_eq!(options, VtOptions::default());
    }

    #[test]
    fn trait_object_usable_via_factory_interface() {
        let factory: Box<dyn VTProgramCorrelatorFactory> =
            Box::new(SymbolNameProgramCorrelatorFactory::new());
        assert_eq!(factory.get_name(), "Exact Symbol Name Match");
        assert_eq!(factory.get_priority(), 40);
    }
}
