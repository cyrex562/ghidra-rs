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
    let session = match &args.open {
        None => ghidra_ui_model::demo_tool::build_demo_session(),
        Some(path) => match open_program(path) {
            Ok(program) => ghidra_ui_model::demo_tool::build_session_for(Some(&program)),
            Err(msg) => {
                eprintln!("ghidra-qt: {msg}");
                std::process::exit(66); // EX_NOINPUT
            }
        },
    };
    let session = bridge::install(session);
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
        count_after_rebuilds: args.count_after_rebuilds,
        dump_listing: args.dump_listing,
        listing_font_change: args.listing_font_change,
        has_prompt_answer: args.prompt_answer.is_some(),
        prompt_answer: args.prompt_answer.unwrap_or_default(),
        print_listing_state: args.print_listing_state,
        float_dock: args.float_dock.unwrap_or_default(),
        invoke_menu: args.invoke_menu.unwrap_or_default(),
        print_clipboard: args.print_clipboard,
        print_palette: args.print_palette,
    };
    std::process::exit(bridge::ffi::run_app(&session, &options));
}

fn open_program(path: &std::path::Path) -> Result<ghidra_ui_model::program_import::ImportedProgram, String> {
    use ghidra_ui_model::program_import::{default_ghidra_dist, import_elf};
    let dist = default_ghidra_dist()
        .ok_or("no Ghidra distribution for compiled languages (set GHIDRA_RS_GHIDRA_DIST, or run scripts/fixtures/setup_ghidra.sh)")?;
    import_elf(path, &dist)
}
