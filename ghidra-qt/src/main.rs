//! `ghidra-qt`: the Qt6 Widgets desktop shell for ghidra-rs.

mod bridge;
mod cli;
mod guard;
mod keys;

use clap::Parser;

fn main() {
    let args = match cli::Args::try_parse() {
        Ok(args) => args,
        // --help / --version print and exit 0; every real usage error exits 64
        // (exit 2 is reserved for "screenshot write failed").
        Err(e) if !e.use_stderr() => e.exit(),
        Err(e) => {
            let _ = e.print();
            std::process::exit(64);
        }
    };
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
