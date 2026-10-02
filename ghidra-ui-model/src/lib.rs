//! Toolkit-neutral UI model for ghidra-rs.
//!
//! This crate is the contract between the Rust model and any renderer (the
//! `ghidra-qt` shell). It must never depend on Qt, egui or any other UI
//! toolkit. See `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`.

mod session;

pub use session::UiSession;
