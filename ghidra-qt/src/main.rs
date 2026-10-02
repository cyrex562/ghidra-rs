//! `ghidra-qt`: the Qt6 Widgets desktop shell for ghidra-rs.

mod bridge;
mod cli;
mod guard;

use clap::Parser;

fn main() {
    let args = cli::Args::parse();
    if let Err(msg) = cli::validate(&args) {
        eprintln!("ghidra-qt: {msg}");
        std::process::exit(64);
    }
    let session = bridge::UiSession::new(ghidra_ui_model::UiSession::new());
    let options = bridge::ffi::AppOptions {
        screenshot_path: args
            .screenshot
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        quit_after_ms: args.quit_after_ms,
    };
    std::process::exit(bridge::ffi::run_app(&session, &options));
}
