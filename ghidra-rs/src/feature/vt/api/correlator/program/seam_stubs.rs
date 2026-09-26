//! Minimal placeholder types for Java classes not yet ported that factories in this module
//! reference (`ExactMatchInstructionsProgramCorrelatorFactory`,
//! `SymbolNameProgramCorrelatorFactory`). See `STUBS.tsv` for provenance.

use std::sync::Arc;

use crate::feature::seam_stubs::VtOptions;
use crate::framework::seam_stubs::ToolOptions;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::feature::vt::api::main::vt_session::VTSession;
use crate::program::model::address::{AddressSet, AddressSetView};
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Placeholder for the unported Java type `ExactInstructionsFunctionHasher`, referenced by
/// `ExactMatchInstructionsProgramCorrelatorFactory`. `ExactInstructionsFunctionHasher` is a
/// concrete Java class (a `FunctionHasher` implementation) that exposes a singleton `INSTANCE`;
/// modeled here as a unit struct until the hashing algorithm itself is ported.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactInstructionsFunctionHasher;

/// Placeholder for the unported Java type `FunctionMatchProgramCorrelator`, referenced by
/// `ExactMatchInstructionsProgramCorrelatorFactory::doCreateCorrelator`.
/// `FunctionMatchProgramCorrelator` is a concrete Java class (extends the not-yet-ported
/// `VTAbstractProgramCorrelator`), so this stub is a struct that implements the real
/// `VTProgramCorrelator` trait using owned copies of its constructor arguments. `correlate`
/// is left unimplemented -- the real algorithm (`MatchFunctions.matchFunctions`) is out of
/// scope for this port. Replace with the real port when
/// `FunctionMatchProgramCorrelator.java` is ported.
pub struct FunctionMatchProgramCorrelator {
    source_program: Arc<dyn Program>,
    source_address_set: AddressSet,
    destination_program: Arc<dyn Program>,
    destination_address_set: AddressSet,
    #[allow(dead_code)]
    options: VtOptions,
    name: String,
    #[allow(dead_code)]
    one_to_one: bool,
    #[allow(dead_code)]
    hasher: ExactInstructionsFunctionHasher,
}

impl FunctionMatchProgramCorrelator {
    pub fn new(
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: VtOptions,
        name: String,
        one_to_one: bool,
        hasher: ExactInstructionsFunctionHasher,
    ) -> Self {
        Self {
            source_program,
            source_address_set: source_address_set.intersect(source_address_set),
            destination_program,
            destination_address_set: destination_address_set.intersect(destination_address_set),
            options,
            name,
            one_to_one,
            hasher,
        }
    }
}

impl VTProgramCorrelator for FunctionMatchProgramCorrelator {
    fn correlate(
        &self,
        _session: &dyn VTSession,
        _monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Box<dyn crate::feature::vt::api::main::vt_match_set::VTMatchSet>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "FunctionMatchProgramCorrelator::correlate is not implemented (stub)",
        ))
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_options(&self) -> Box<dyn ToolOptions> {
        panic!("FunctionMatchProgramCorrelator::get_options is not implemented (stub)")
    }

    fn get_source_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(self.source_address_set.clone())
    }

    fn get_source_program(&self) -> Arc<dyn Program> {
        self.source_program.clone()
    }

    fn get_destination_program(&self) -> Arc<dyn Program> {
        self.destination_program.clone()
    }

    fn get_destination_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(self.destination_address_set.clone())
    }
}

/// Placeholder for the unported Java type `SymbolNameProgramCorrelator`, referenced by
/// `SymbolNameProgramCorrelatorFactory::doCreateCorrelator`. `SymbolNameProgramCorrelator` is a
/// concrete Java class (extends the not-yet-ported `VTAbstractProgramCorrelator`), so this stub
/// mirrors the same treatment [`FunctionMatchProgramCorrelator`] gets: a struct implementing the
/// real [`VTProgramCorrelator`] trait using owned copies of its constructor arguments, with
/// `correlate` left unimplemented since the real `doCorrelate` symbol-matching algorithm is out
/// of scope for this port. Replace with the real port when `SymbolNameProgramCorrelator.java` is
/// ported.
pub struct SymbolNameProgramCorrelator {
    source_program: Arc<dyn Program>,
    source_address_set: AddressSet,
    destination_program: Arc<dyn Program>,
    destination_address_set: AddressSet,
    #[allow(dead_code)]
    options: VtOptions,
    name: String,
    #[allow(dead_code)]
    one_to_one: bool,
}

impl SymbolNameProgramCorrelator {
    /// Mirrors `SymbolNameProgramCorrelator(Program, AddressSetView, Program, AddressSetView,
    /// ToolOptions, String, boolean)`.
    pub fn new(
        source_program: Arc<dyn Program>,
        source_address_set: &dyn AddressSetView,
        destination_program: Arc<dyn Program>,
        destination_address_set: &dyn AddressSetView,
        options: VtOptions,
        name: String,
        one_to_one: bool,
    ) -> Self {
        Self {
            source_program,
            source_address_set: source_address_set.intersect(source_address_set),
            destination_program,
            destination_address_set: destination_address_set.intersect(destination_address_set),
            options,
            name,
            one_to_one,
        }
    }
}

impl VTProgramCorrelator for SymbolNameProgramCorrelator {
    fn correlate(
        &self,
        _session: &dyn VTSession,
        _monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Box<dyn crate::feature::vt::api::main::vt_match_set::VTMatchSet>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "SymbolNameProgramCorrelator::correlate is not implemented (stub)",
        ))
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_options(&self) -> Box<dyn ToolOptions> {
        panic!("SymbolNameProgramCorrelator::get_options is not implemented (stub)")
    }

    fn get_source_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(self.source_address_set.clone())
    }

    fn get_source_program(&self) -> Arc<dyn Program> {
        self.source_program.clone()
    }

    fn get_destination_program(&self) -> Arc<dyn Program> {
        self.destination_program.clone()
    }

    fn get_destination_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(self.destination_address_set.clone())
    }
}

