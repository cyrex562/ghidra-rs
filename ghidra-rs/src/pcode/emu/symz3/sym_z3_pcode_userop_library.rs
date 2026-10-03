//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeUseropLibrary`.

use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
};
use crate::pcode::exec::pcode_userop_library::{ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap};

/// The userop library for the symbolic Z3 emulator.
///
/// Port of `public class SymZ3PcodeUseropLibrary extends
/// AnnotatedPcodeUseropLibrary<Pair<byte[], SymValueZ3>> {}`. Java's class body is empty -- it
/// declares no `@PcodeUserop`-annotated methods of its own, relying entirely on the inherited
/// machinery -- so [`SymZ3PcodeUseropLibrary::collect_definitions`] likewise contributes nothing.
///
/// Java's `Pair<byte[], SymValueZ3>` is rendered as the tuple `(Vec<u8>, SymValueZ3)`, matching
/// this crate's established convention for `AuxPcodeEmulator`/`AuxEmulatorPartsFactory` and
/// friends.
pub struct SymZ3PcodeUseropLibrary {
    base: AnnotatedPcodeUseropLibraryBase<(Vec<u8>, SymValueZ3)>,
}

impl SymZ3PcodeUseropLibrary {
    /// Construct the library and collect its (currently empty) set of userops.
    ///
    /// Port of the implicit default constructor, which runs `AnnotatedPcodeUseropLibrary`'s own
    /// constructor logic (Java dispatches to `collectDefinitions()` polymorphically from within
    /// it); this port runs the equivalent [`AnnotatedPcodeUseropLibrary::init`] explicitly once
    /// `self` exists, matching that trait's own documented divergence.
    pub fn new() -> Self {
        let mut lib = Self { base: AnnotatedPcodeUseropLibraryBase::new() };
        lib.init();
        lib
    }
}

impl Default for SymZ3PcodeUseropLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl ErasedPcodeUseropLibrary for SymZ3PcodeUseropLibrary {}

impl PcodeUseropLibrary<(Vec<u8>, SymValueZ3)> for SymZ3PcodeUseropLibrary {
    fn get_userops(&self) -> &UseropMap<(Vec<u8>, SymValueZ3)> {
        self.base.get_userops()
    }
}

impl AnnotatedPcodeUseropLibrary<(Vec<u8>, SymValueZ3)> for SymZ3PcodeUseropLibrary {
    fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<(Vec<u8>, SymValueZ3)> {
        &mut self.base
    }

    fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<(Vec<u8>, SymValueZ3)>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_library_declares_no_userops() {
        let lib = SymZ3PcodeUseropLibrary::new();
        assert!(lib.get_userops().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let lib = SymZ3PcodeUseropLibrary::default();
        assert!(lib.get_userops().is_empty());
    }

    #[test]
    fn get_operand_type_reports_the_pair_type() {
        let lib = SymZ3PcodeUseropLibrary::new();
        assert_eq!(
            lib.get_operand_type(),
            std::any::TypeId::of::<(Vec<u8>, SymValueZ3)>()
        );
    }
}
