//! The stand-alone Symbolic Z3 Emulator state components.
//!
//! This module and [`crate::pcode::emu::symz3`] together contain all the parts necessary to
//! construct a stand-alone emulator. Because this is a working solution, the state components
//! already have provisions in place for extension to support the fully-integrated solution.
//! Generally, it's a bit easier to get the basic state components implemented, put tests in
//! place, and then re-factor them to permit extension as you address each more integrated
//! emulator.
//!
//! For this module, a top-down approach is recommended, since the top component provides a
//! flat catalog of the lower components. That top piece is actually in a separate module. See
//! `SymZ3PartsFactory`. That factory is then used in `SymZ3PcodeEmulator` to realize the
//! stand-alone emulator. When you get to the state pieces, you may want to pause and read
//! `SymZ3Space` first.

#[cfg(test)]
mod tests {
    #[test]
    fn state_module_exists() {
        // Verifies that the symz3::state module is reachable and compiles correctly.
        // Substantive tests live in the submodule files as they are ported.
    }
}
