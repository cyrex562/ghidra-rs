//! Port of `ghidra.app.util.demangler.swift.SwiftNativeDemangler`.
//!
//! A class used to launch the Swift native demangler.
//!
//! The Swift native demangler binary comes in 2 forms, and can thus be invoked in 2 ways:
//! * `./swift demangle args`
//! * `./swift-demangle args`
//!
//! The latter is how it is done in the Windows version of Swift. This is referred to as the
//! "standalone demangler binary".
//!
//! # Promotion from seam stub
//!
//! This was previously a placeholder in `crate::demangler::seam_stubs` (a unit struct whose
//! `demangle` always reported "not yet ported"), depended on by
//! [`SwiftDemangler`](crate::demangler::swift::swift_demangler::SwiftDemangler) and
//! [`SwiftDemangledTree`](crate::demangler::swift::swift_demangled_tree::SwiftDemangledTree). This
//! module supplies the real port; those two callers now import from here instead.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The output of the native Swift demangler.
///
/// Port of the record `SwiftNativeDemangler.SwiftNativeDemangledOutput`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwiftNativeDemangledOutput {
    /// The demangled string, or `None` if demangling finished gracefully but returned nothing.
    pub demangled: Option<String>,
    /// The lines of the demangled expanded tree.
    pub tree: Vec<String>,
}

impl std::fmt::Display for SwiftNativeDemangledOutput {
    /// Port of `toString()`: `"%s\n%s".formatted(demangled != null ? demangled : "<NULL>",
    /// tree.stream().collect(Collectors.joining("\n")))`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let demangled = self.demangled.as_deref().unwrap_or("<NULL>");
        write!(f, "{}\n{}", demangled, self.tree.join("\n"))
    }
}

/// Launches the Swift native demangler binary and parses its output.
///
/// Port of `ghidra.app.util.demangler.swift.SwiftNativeDemangler`.
pub struct SwiftNativeDemangler {
    native_demangler_path: String,
    standalone_demangler_binary: bool,
}

impl SwiftNativeDemangler {
    /// Creates a new [`SwiftNativeDemangler`].
    ///
    /// Port of `SwiftNativeDemangler(File swiftDir)`: tries `swift-demangle`, then `swift`
    /// (optionally rooted at `swift_dir`), invoking each with `--version` until one succeeds.
    ///
    /// # Errors
    /// Returns an error if there was a problem finding or running the native Swift demangler --
    /// the last error encountered while trying every candidate name.
    pub fn new(swift_dir: Option<PathBuf>) -> io::Result<Self> {
        const DEMANGLER_NAMES: [&str; 2] = ["swift-demangle", "swift"];
        let mut last_err: Option<io::Error> = None;
        for name in DEMANGLER_NAMES {
            let native_demangler_path = match &swift_dir {
                Some(dir) => dir.join(name).to_string_lossy().into_owned(),
                None => name.to_string(),
            };
            match Command::new(&native_demangler_path).arg("--version").status() {
                Ok(status) if status.success() => {
                    let standalone_demangler_binary = Path::new(&native_demangler_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().contains("-demangle"))
                        .unwrap_or(false);
                    return Ok(Self { native_demangler_path, standalone_demangler_binary });
                }
                Ok(status) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Native Swift demangler exited with code: {}", status.code().unwrap_or(-1)),
                    ));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no native Swift demangler binary found")
        }))
    }

    /// Uses the Swift executable to demangle the given mangled string.
    ///
    /// Port of `demangle(String mangled)`.
    ///
    /// # Errors
    /// Returns an error if there was an IO-related issue, or the native demangler's output could
    /// not be parsed.
    pub fn demangle(&self, mangled: &str) -> io::Result<SwiftNativeDemangledOutput> {
        // Compact mode (only emit the demangled names); expand mode (show node structure of the
        // demangling).
        let options = ["--compact", "--expand"];
        let output = self.run_demangler(mangled, &options)?;
        Self::parse_demangle_output(output.lines().map(str::to_string))
    }

    /// Runs the Swift demangler to demangle the given mangled string with the given demangle
    /// options, returning the combined stdout/stderr text.
    ///
    /// Port of the private `demangle(String mangled, List<String> options)`, which returns a
    /// `BufferedReader` over the process's merged (`redirectErrorStream(true)`) output streams.
    /// Rust's standard library has no safe way to merge a child's stdout/stderr into a single
    /// ordered stream without an OS-specific `dup2` (which this crate avoids -- no `unsafe`), so
    /// this instead captures stdout and stderr separately (via [`Command::output`]) and
    /// concatenates stdout followed by stderr. In practice the demangler's diagnostic messages (if
    /// any) go to stderr and its actual output to stdout, so this only affects error-path
    /// diagnostics ordering, not the successful-parse case [`parse_demangle_output`] handles.
    fn run_demangler(&self, mangled: &str, options: &[&str]) -> io::Result<String> {
        let mut command = Command::new(&self.native_demangler_path);
        if !self.standalone_demangler_binary {
            command.arg("demangle");
        }
        command.args(options);
        command.arg(mangled);
        let output = command.output()?;
        let mut merged = output.stdout;
        merged.extend_from_slice(&output.stderr);
        Ok(String::from_utf8_lossy(&merged).into_owned())
    }

    /// Parses the native demangler's textual output into a [`SwiftNativeDemangledOutput`].
    ///
    /// Port of the body of `demangle(String mangled)` following the process launch: reads a
    /// `"Demangling for ..."` header line, then either a `"<<NULL>>"` marker (not a demangleable
    /// string) or a sequence of `kind=...` tree lines followed by the final demangled-string line.
    ///
    /// # Errors
    /// Returns an error if the first line is missing or does not start with `"Demangling for"`
    /// (mirroring Java's own `throw new IOException("Unexpected output: " + line)`; an entirely
    /// empty output, which Java's `reader.readLine().trim()` would NPE on, is likewise reported as
    /// an error here rather than as a panic).
    fn parse_demangle_output(
        mut lines: impl Iterator<Item = String>,
    ) -> io::Result<SwiftNativeDemangledOutput> {
        let first = lines.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "no output from native Swift demangler")
        })?;
        let first = first.trim();
        if !first.starts_with("Demangling for") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected output: {first}"),
            ));
        }

        let mut demangled: Option<String> = None;
        let mut tree_lines: Vec<String> = Vec::new();
        for line in lines {
            if line.starts_with("<<NULL>>") {
                // Not a demangleable string.
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            if tree_lines.is_empty() && !line.trim().starts_with("kind") {
                // Mainly for when the mangled string has newline characters in it, which are
                // printed as part of the first "Demangling for..." line. Skip those and get to
                // the tree.
                continue;
            }
            if !tree_lines.is_empty() && !line.starts_with(' ') {
                // The last line after the tree is the full demangled string.
                demangled = Some(line);
                break;
            }
            tree_lines.push(line);
        }

        Ok(SwiftNativeDemangledOutput { demangled, tree: tree_lines })
    }
}

/// Test-only constructor bypassing binary discovery, so tests can exercise
/// [`SwiftNativeDemangler::demangle`]'s process-invocation error path deterministically without
/// depending on whether this environment happens to have a real `swift`/`swift-demangle`
/// toolchain installed. Not part of the Java API.
#[cfg(test)]
impl SwiftNativeDemangler {
    pub(crate) fn for_testing(
        native_demangler_path: impl Into<String>,
        standalone_demangler_binary: bool,
    ) -> Self {
        Self {
            native_demangler_path: native_demangler_path.into(),
            standalone_demangler_binary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_when_no_native_demangler_binary_is_available() {
        // This test environment has no swift/swift-demangle toolchain installed.
        let result = SwiftNativeDemangler::new(None);
        assert!(result.is_err());
    }

    #[test]
    fn new_with_a_swift_dir_still_fails_without_a_real_toolchain() {
        let result = SwiftNativeDemangler::new(Some(PathBuf::from("/definitely/not/a/real/swift/dir")));
        assert!(result.is_err());
    }

    #[test]
    fn demangle_fails_when_the_binary_does_not_exist() {
        let demangler = SwiftNativeDemangler::for_testing("definitely-not-a-real-binary-xyz", false);
        assert!(demangler.demangle("$s4main3fooV").is_err());
    }

    #[test]
    fn parse_demangle_output_extracts_tree_lines_and_demangled_string() {
        let lines = [
            "Demangling for $s4main3fooV",
            "kind=Global",
            "  kind=Function",
            "    kind=Module, text=\"Swift\"",
            "    kind=Identifier, text=\"print\"",
            "Swift.print",
        ];
        let output =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap();
        assert_eq!(output.demangled.as_deref(), Some("Swift.print"));
        assert_eq!(
            output.tree,
            vec![
                "kind=Global",
                "  kind=Function",
                "    kind=Module, text=\"Swift\"",
                "    kind=Identifier, text=\"print\"",
            ]
        );
    }

    #[test]
    fn parse_demangle_output_stops_at_null_marker() {
        let lines = ["Demangling for garbage", "<<NULL>>", "kind=ShouldNotAppear"];
        let output =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap();
        assert!(output.demangled.is_none());
        assert!(output.tree.is_empty());
    }

    #[test]
    fn parse_demangle_output_rejects_unexpected_first_line() {
        let lines = ["not the expected header"];
        let err =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap_err();
        assert!(err.to_string().contains("Unexpected output"));
    }

    #[test]
    fn parse_demangle_output_reports_error_on_completely_empty_output() {
        let lines: [&str; 0] = [];
        let err =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_demangle_output_skips_blank_lines_and_pretree_continuation() {
        let lines = [
            "Demangling for $s4main3fooV\u{0}embedded-newline-continuation",
            "continuation of first line, not a kind= line",
            "",
            "kind=Global",
            "Result.name",
        ];
        let output =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap();
        assert_eq!(output.tree, vec!["kind=Global"]);
        assert_eq!(output.demangled.as_deref(), Some("Result.name"));
    }

    #[test]
    fn parse_demangle_output_with_no_trailing_demangled_line_leaves_it_none() {
        // If the tree lines run all the way to the end of output with no final unindented line,
        // `demangled` stays `None` -- mirrors Java's `demangled` field only ever being assigned
        // inside that specific branch.
        let lines = ["Demangling for $s4main3fooV", "kind=Global", "  kind=Function"];
        let output =
            SwiftNativeDemangler::parse_demangle_output(lines.iter().map(|s| s.to_string())).unwrap();
        assert!(output.demangled.is_none());
        assert_eq!(output.tree, vec!["kind=Global", "  kind=Function"]);
    }

    #[test]
    fn display_matches_java_format_with_demangled_value() {
        let output = SwiftNativeDemangledOutput {
            demangled: Some("Swift.print".to_string()),
            tree: vec!["kind=Global".to_string(), "  kind=Function".to_string()],
        };
        assert_eq!(output.to_string(), "Swift.print\nkind=Global\n  kind=Function");
    }

    #[test]
    fn display_uses_the_null_placeholder_when_demangled_is_none() {
        let output = SwiftNativeDemangledOutput { demangled: None, tree: vec![] };
        assert_eq!(output.to_string(), "<NULL>\n");
    }
}
