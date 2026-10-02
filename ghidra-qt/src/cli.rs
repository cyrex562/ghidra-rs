//! Command-line options for the `ghidra-qt` binary.

use std::path::PathBuf;

use clap::Parser;

/// `ghidra-qt` command line.
#[derive(Debug, Parser)]
#[command(name = "ghidra-qt", version, about = "Ghidra-rs desktop UI (Qt6)")]
pub struct Args {
    /// Save a PNG of the main window just before quitting (needs --quit-after-ms).
    #[arg(long, value_name = "PNG")]
    pub screenshot: Option<PathBuf>,

    /// Quit automatically after this many milliseconds (0 = run interactively).
    #[arg(long, value_name = "MS", default_value_t = 0)]
    pub quit_after_ms: u32,

    /// Print one line per dock (`title<TAB>area<TAB>view`) and exit.
    #[arg(long)]
    pub dump_docks: bool,

    /// Print the built menu bar and exit.
    #[arg(long)]
    pub dump_menus: bool,

    /// Restore ADS geometry from this file before showing.
    #[arg(long, value_name = "FILE")]
    pub restore_geometry: Option<PathBuf>,

    /// After showing, send this key press (e.g. `Ctrl-F`) to the focused dock.
    #[arg(long, value_name = "KEYS")]
    pub press: Option<String>,

    /// Focus the dock with this title before `--press`.
    #[arg(long, value_name = "TITLE")]
    pub focus: Option<String>,

    /// Invoke a non-existent action from a Qt slot (error-path smoke test).
    #[arg(long, hide = true)]
    pub invoke_missing_action: bool,

    /// Print the first N rows the Listing view would paint, then exit.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub dump_listing: u32,

    /// Scroll the Listing 3 rows, print its first row's index and run x
    /// positions, double the font size, print them again, exit (smoke test).
    #[arg(long, hide = true)]
    pub listing_font_change: bool,

    /// Rebuild menus/toolbar N times, print menubar+toolbar child counts, exit (leak test).
    #[arg(long, hide = true, value_name = "N", default_value_t = 0)]
    pub count_after_rebuilds: u32,
}

/// Rejects option combinations the shell cannot honour.
pub fn validate(args: &Args) -> Result<(), String> {
    if args.screenshot.is_some() && args.quit_after_ms == 0 {
        return Err("--screenshot requires --quit-after-ms > 0".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn interactive_launch_is_valid() {
        let a = Args::parse_from(["ghidra-qt"]);
        assert_eq!(validate(&a), Ok(()));
    }

    #[test]
    fn screenshot_requires_quit_after() {
        let a = Args::parse_from(["ghidra-qt", "--screenshot", "out.png"]);
        assert_eq!(
            validate(&a),
            Err("--screenshot requires --quit-after-ms > 0".to_owned())
        );
    }

    #[test]
    fn screenshot_with_quit_after_is_valid() {
        let a = Args::parse_from(["ghidra-qt", "--screenshot", "o.png", "--quit-after-ms", "500"]);
        assert_eq!(validate(&a), Ok(()));
    }
}
