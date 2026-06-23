//! UI components for the Taint Analyzer.
//!
//! This module contains a few odds and ends for making the taint analyzer's machine state
//! visible to the user. It provides a custom column for the Registers panel, and a custom
//! field for the Listing panels. Both just render the taint markings using
//! `TaintVec::to_display`. There's no particular recommended reading order.

#[cfg(test)]
mod tests {
    #[test]
    fn module_exists() {
        // Package-info port: verifies the taint gui field module is wired into the crate.
    }
}
