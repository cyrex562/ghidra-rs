//! Toolkit-neutral UI model for ghidra-rs.
//!
//! This crate is the contract between the Rust model and any renderer (the
//! `ghidra-qt` shell). It must never depend on Qt, egui or any other UI
//! toolkit. See `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`.

pub mod demo;
pub mod demo_tool;
mod events;
pub mod menus;
mod session;
mod view_kind;
mod view_models;

pub use events::{UiEvent, UiEventQueue, WakeHandle};
pub use session::{UiSession, ViewModelBox};
pub use view_kind::ViewKind;
pub use view_models::{CellValue, FormField, FormFieldKind, FormModel, NodeId, StyledRun, TableModel, TextModel, TreeModel};
