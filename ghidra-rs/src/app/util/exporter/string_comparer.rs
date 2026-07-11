//! Utility for comparing expected output lines against the contents of a file.

use crate::util::msg::Msg;
use anyhow::{bail, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Compares a list of expected lines against the lines actually present in `actual_file`.
///
/// Each actual line is considered a match if it equals the corresponding expected line
/// (after trimming both) or if the actual line starts with the expected line. Fails if
/// the file contains more or fewer lines than expected, or if any line fails to match.
///
/// Mirrors `ghidra.app.util.exporter.StringComparer.compareLines(List<String>, File)`.
pub fn compare_lines(expected_list: &[String], actual_file: &Path) -> Result<()> {
    let mut file_printer = FilePrinter::new(actual_file);

    let mut index = 0usize;
    let mut has_failure = false;
    let reader = BufReader::new(File::open(actual_file)?);
    let mut excess = 0usize;

    for line in reader.lines() {
        let actual_line = line?;

        if index >= expected_list.len() {
            excess += 1;
            continue;
        }
        let expected_line = expected_list[index].trim().to_string();
        index += 1;

        let actual_line = actual_line.trim();

        let is_match = expected_line == actual_line || actual_line.starts_with(&expected_line);
        has_failure |= !is_match;

        if !is_match {
            file_printer.print();
            Msg::debug(
                "StringComparer",
                &format!(
                    "Expected line does not match actual line ({}): \nExpected: {}\nActual: {}",
                    index, expected_line, actual_line
                ),
            );
        }
    }

    if excess > 0 {
        file_printer.print();
        let message = format!("Actual file contains {} more lines than expected", excess);
        Msg::debug("StringComparer", &message);
        bail!(message);
    } else if !has_failure && index < expected_list.len() {
        file_printer.print();
        let fewer = expected_list.len() - index;
        let message = format!("Actual file contains {} fewer lines than expected", fewer);
        Msg::debug("StringComparer", &message);
        bail!(message);
    }

    if has_failure {
        bail!("One or more failures--see output for data");
    }

    Ok(())
}

/// Prints the path of the file under comparison at most once.
///
/// Mirrors the private `StringComparer.FilePrinter` helper class.
struct FilePrinter<'a> {
    path: &'a Path,
    printed: bool,
}

impl<'a> FilePrinter<'a> {
    fn new(path: &'a Path) -> Self {
        Self {
            path,
            printed: false,
        }
    }

    fn print(&mut self) {
        if !self.printed {
            Msg::debug(
                "StringComparer",
                &format!("Test file: {}", self.path.display()),
            );
            self.printed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_exact_match() {
        let file = write_temp_file("line one\nline two\n");
        let expected = vec!["line one".to_string(), "line two".to_string()];
        assert!(compare_lines(&expected, file.path()).is_ok());
    }

    #[test]
    fn test_trims_whitespace_before_comparing() {
        let file = write_temp_file("  line one  \n line two\n");
        let expected = vec!["line one".to_string(), "line two  ".to_string()];
        assert!(compare_lines(&expected, file.path()).is_ok());
    }

    #[test]
    fn test_actual_line_starts_with_expected() {
        let file = write_temp_file("line one extra stuff\n");
        let expected = vec!["line one".to_string()];
        assert!(compare_lines(&expected, file.path()).is_ok());
    }

    #[test]
    fn test_mismatch_fails() {
        let file = write_temp_file("something else\n");
        let expected = vec!["line one".to_string()];
        let err = compare_lines(&expected, file.path()).unwrap_err();
        assert!(err.to_string().contains("One or more failures"));
    }

    #[test]
    fn test_actual_has_more_lines_fails() {
        let file = write_temp_file("line one\nline two\n");
        let expected = vec!["line one".to_string()];
        let err = compare_lines(&expected, file.path()).unwrap_err();
        assert!(err.to_string().contains("more lines than expected"));
    }

    #[test]
    fn test_actual_has_fewer_lines_fails() {
        let file = write_temp_file("line one\n");
        let expected = vec!["line one".to_string(), "line two".to_string()];
        let err = compare_lines(&expected, file.path()).unwrap_err();
        assert!(err.to_string().contains("fewer lines than expected"));
    }

    #[test]
    fn test_empty_expected_and_actual() {
        let file = write_temp_file("");
        let expected: Vec<String> = Vec::new();
        assert!(compare_lines(&expected, file.path()).is_ok());
    }

    #[test]
    fn test_missing_file_returns_error() {
        let expected = vec!["line one".to_string()];
        let result = compare_lines(&expected, Path::new("/nonexistent/path/for/test.txt"));
        assert!(result.is_err());
    }
}
