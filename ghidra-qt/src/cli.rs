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
