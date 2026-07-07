//! The Taint Analysis module.
//!
//! This serves as the archetype for custom emulators and the bells and whistles needed to make
//! them accessible and useful. Because this is already a working solution, we provide a "tour"
//! working mostly in bottom-up fashion rather than a tutorial that steps through intermediate
//! solutions.
//!
//! Before even starting with the emulator, the domain of analysis must be implemented. For some
//! use cases, the domain may already be implemented by a third-party library. The Taint Analyzer
//! implements the domain itself (see [`model`]) as it is fairly simple and allows tailoring to
//! specific needs.
//!
//! Next, the emulator is implemented using an auxiliary emulator parts factory. The implementation
//! of each method moves attention to each part necessary to construct the emulator.
//!
//! Next, trace integration is provided. Finally, UI components make the emulator's machine state
//! visible to the user (see [`gui`]).

pub mod gui;
pub mod model;
