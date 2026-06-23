//! The trace-integrated Symbolic Z3 Emulator.
//!
//! This module builds on [`crate::pcode::emu::symz3`] to construct a trace-integrated emulator.
//! See that module for remarks about this "working solution." Those state components were factored
//! to accommodate the state components introduced by this module.
//!
//! For this module, a bottom-up approach is recommended, since you should already be familiar with
//! the parts factory and the structure of the stand-alone state part. `SymZ3TraceSpace` adds the
//! ability to read and write symbolic value sets from a trace.
//! `SymZ3TracePcodeExecutorStatePiece` works that into a state piece derived from
//! `SymZ3PcodeExecutorStatePiece`. Then, `SymZ3TracePcodeExecutorState` composes that with a
//! given concrete state piece. The factory creates that state for use by
//! `SymZ3TracePcodeEmulator`.

#[cfg(test)]
mod tests {
    #[test]
    fn trace_module_exists() {
        // Verifies that the symz3::trace module is reachable and compiles correctly.
        // Substantive tests live in the submodule files as they are ported.
    }
}
