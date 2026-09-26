//! The Symbolic Z3 Analysis module.
//!
//! This emulator was based on the TaintAnalysis module, but was modified to support the intended
//! purpose (creating symbolic Z3 expressions).

pub mod gui;
pub mod model;
#[cfg(feature = "z3")]
pub mod z3_solver_context;

#[cfg(test)]
mod tests {
    #[test]
    fn module_exists() {
        // Package-info port: verifies the symz3 module is wired into the crate.
    }
}
