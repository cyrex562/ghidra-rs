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
    let session = bridge::install(ghidra_ui_model::demo_tool::build_demo_session());
    let options = bridge::ffi::AppOptions {
        screenshot_path: args
            .screenshot
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        quit_after_ms: args.quit_after_ms,
        dump_docks: args.dump_docks,
        dump_menus: args.dump_menus,
        restore_geometry: args.restore_geometry.map(|p| p.display().to_string()).unwrap_or_default(),
        press: args.press.unwrap_or_default(),
        focus: args.focus.unwrap_or_default(),
        invoke_missing_action: args.invoke_missing_action,
    };
    std::process::exit(bridge::ffi::run_app(&session, &options));
}
