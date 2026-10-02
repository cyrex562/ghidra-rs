//! Toolkit-neutral ports of `java.awt` value types. Renderers (the
//! `ghidra-qt` shell) convert these at the UI edge; model code must never use
//! Qt or egui types. Decided 2026-10-01.

pub mod color;

pub use color::Color;
