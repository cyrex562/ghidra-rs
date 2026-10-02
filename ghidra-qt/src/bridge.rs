//! The cxx bridge between the C++ Qt shell and the Rust UI model.
//! Rules (spec §3): C++ calls Rust for data only; Rust never calls back into
//! C++ widgets; every `extern "Rust"` function returns through `guard`.

use crate::guard::guard;

/// Bridge-local handle for the UI session. cxx requires opaque Rust types to be
/// defined in this crate (orphan rule), so it wraps the toolkit-neutral
/// `ghidra_ui_model::UiSession`; C++ sees it as `ghidra_qt::UiSession`.
pub struct UiSession(ghidra_ui_model::UiSession);

impl UiSession {
    /// Wraps a model session for handing to the C++ shell.
    pub fn new(model: ghidra_ui_model::UiSession) -> Self {
        Self(model)
    }
}

#[cxx::bridge(namespace = "ghidra_qt")]
pub mod ffi {
    /// Startup options passed from `main` to the C++ shell.
    pub struct AppOptions {
        /// PNG path for the auto-quit screenshot; empty = none.
        pub screenshot_path: String,
        /// Auto-quit delay in ms; 0 = interactive.
        pub quit_after_ms: u32,
    }

    extern "Rust" {
        type UiSession;
        fn session_title(session: &UiSession) -> Result<String>;
    }

    unsafe extern "C++" {
        include!("ghidra-qt/cpp/app.h");
        fn run_app(session: &UiSession, options: &AppOptions) -> i32;
    }
}

fn session_title(session: &UiSession) -> Result<String, String> {
    guard("session_title", || session.0.title())
}
