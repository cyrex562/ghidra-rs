//! `FixedHandle` used to be defined twice: here (with unsigned offsets, a derived `Default`
//! whose `fixable` was `false`, and none of the varnode accessors) and as the faithful port of
//! `ghidra.app.plugin.processors.sleigh.FixedHandle` in
//! [`crate::app::plugin::processors::sleigh::fixed_handle`]. This re-export makes the latter the
//! one type every sleigh module uses.

pub use crate::app::plugin::processors::sleigh::fixed_handle::FixedHandle;
