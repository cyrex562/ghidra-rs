//! Headless entry point for ghidra-rs. The desktop UI is the separate
//! `ghidra-qt` binary (see docs/superpowers/specs/2026-10-01-qt6-ui-design.md).

fn main() {
    println!(
        "ghidra-rs {} (headless). The desktop UI is the `ghidra-qt` binary.",
        env!("CARGO_PKG_VERSION")
    );
}
