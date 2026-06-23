//! The Taint Emulator.
//!
//! This module and [`super::super::emu::taint`] (the `taint::state` submodule) contain all
//! the parts necessary to construct the taint emulator.
//!
//! A top-down reading approach is recommended: the top component provides a flat catalog of
//! the lower components. That top piece is `TaintPartsFactory`, which is used by
//! `TaintPcodeEmulator` to realise the emulator.

#[cfg(test)]
mod tests {
    #[test]
    fn module_exists() {
        // Package-info port: verifies the taint emulator module is wired into the crate.
    }
}
