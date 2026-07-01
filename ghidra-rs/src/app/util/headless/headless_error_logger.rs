//! Custom headless error logger which is used when log4j is disabled.

use std::fmt::Display;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::util::error_logger::ErrorLogger;

/// Custom headless error logger which is used when log4j is disabled.
///
/// Port of `ghidra.app.util.headless.HeadlessErrorLogger`.
pub struct HeadlessErrorLogger {
    log_writer: Mutex<Option<BufWriter<File>>>,
}

impl HeadlessErrorLogger {
    /// Creates a new logger, optionally opening `log_file` immediately.
    pub fn new(log_file: Option<&Path>) -> Self {
        let logger = HeadlessErrorLogger {
            log_writer: Mutex::new(None),
        };
        if let Some(log_file) = log_file {
            logger.set_log_file(Some(log_file));
        }
        logger
    }

    /// Switches the active log file, closing any previously open file.
    ///
    /// Passing `None` disables file logging.
    pub fn set_log_file(&self, log_file: Option<&Path>) {
        let mut guard = self.log_writer.lock().unwrap();
        match log_file {
            None => {
                if guard.is_some() {
                    Self::write_log_locked(&mut guard, "INFO", "File logging disabled");
                    *guard = None;
                }
            }
            Some(path) => match File::create(path) {
                Ok(file) => {
                    if guard.is_some() {
                        Self::write_log_locked(
                            &mut guard,
                            "INFO ",
                            &format!("Switching log file to: {}", path.display()),
                        );
                    }
                    *guard = Some(BufWriter::new(file));
                }
                Err(e) => {
                    eprintln!("Failed to open log file {}: {}", path.display(), e);
                }
            },
        }
    }

    fn write_line(guard: &mut Option<BufWriter<File>>, line: &str) {
        if let Some(writer) = guard {
            let _ = writeln!(writer, "{}", line);
        }
    }

    fn write_log_locked(guard: &mut Option<BufWriter<File>>, level: &str, text: &str) {
        if guard.is_none() {
            return;
        }
        for line in chop_lines(text) {
            Self::write_line(guard, &format!("{} {}", level, line));
        }
        if let Some(writer) = guard {
            let _ = writer.flush();
        }
    }

    fn write_log(&self, level: &str, text: &str) {
        let mut guard = self.log_writer.lock().unwrap();
        Self::write_log_locked(&mut guard, level, text);
    }

    fn write_log_with_error(&self, level: &str, text: &str, error: &dyn std::error::Error) {
        let mut guard = self.log_writer.lock().unwrap();
        if guard.is_none() {
            return;
        }
        for line in chop_lines(text) {
            Self::write_line(&mut guard, &format!("{} {}", level, line));
        }
        let mut source: Option<&dyn std::error::Error> = Some(error);
        while let Some(e) = source {
            Self::write_line(&mut guard, &format!("{} {}", level, e));
            source = e.source();
        }
        if let Some(writer) = guard.as_mut() {
            let _ = writer.flush();
        }
    }
}

fn chop_lines(text: &str) -> Vec<&str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

impl ErrorLogger for HeadlessErrorLogger {
    fn trace(&self, _originator: &str, _message: &dyn Display) {
        // Tracing is intentionally disabled, matching the original Java implementation.
    }

    fn trace_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
        // Tracing is intentionally disabled, matching the original Java implementation.
    }

    fn debug(&self, _originator: &str, _message: &dyn Display) {
        // Debug logging is intentionally disabled, matching the original Java implementation.
    }

    fn debug_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
        // Debug logging is intentionally disabled, matching the original Java implementation.
    }

    fn info(&self, _originator: &str, message: &dyn Display) {
        self.write_log("INFO ", &message.to_string());
    }

    fn info_with_error(
        &self,
        _originator: &str,
        _message: &dyn Display,
        _error: &dyn std::error::Error,
    ) {
        // Intentionally disabled, matching the original Java implementation.
    }

    fn warn(&self, _originator: &str, message: &dyn Display) {
        self.write_log("WARN ", &message.to_string());
    }

    fn warn_with_error(
        &self,
        _originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        self.write_log_with_error("WARN ", &message.to_string(), error);
    }

    fn error(&self, _originator: &str, message: &dyn Display) {
        self.write_log("ERROR", &message.to_string());
    }

    fn error_with_error(
        &self,
        _originator: &str,
        message: &dyn Display,
        error: &dyn std::error::Error,
    ) {
        self.write_log_with_error("ERROR", &message.to_string(), error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "headless_error_logger_test_{}_{}",
            std::process::id(),
            name
        ));
        path
    }

    #[test]
    fn test_chop_lines_splits_and_strips_cr() {
        let lines = chop_lines("first\r\nsecond\nthird");
        assert_eq!(lines, vec!["first", "second", "third"]);
    }

    #[test]
    fn test_no_log_file_writes_nothing() {
        let logger = HeadlessErrorLogger::new(None);
        logger.error("Origin", &"boom");
        // Nothing to assert against a file; just confirm no panic occurs.
    }

    #[test]
    fn test_error_written_to_log_file() {
        let path = temp_path("error");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.error("Origin", &"something failed");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("ERROR something failed"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_warn_written_to_log_file() {
        let path = temp_path("warn");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.warn("Origin", &"careful now");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("WARN  careful now"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_info_written_to_log_file() {
        let path = temp_path("info");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.info("Origin", &"informational");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("INFO  informational"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_debug_and_trace_are_noops() {
        let path = temp_path("noop");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.debug("Origin", &"should not appear");
        logger.trace("Origin", &"should not appear either");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.is_empty());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_error_with_error_includes_cause_chain() {
        let path = temp_path("error_with_error");
        let logger = HeadlessErrorLogger::new(Some(&path));
        let err = std::io::Error::new(std::io::ErrorKind::Other, "root cause");
        logger.error_with_error("Origin", &"top level failure", &err);
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("ERROR top level failure"));
        assert!(contents.contains("ERROR root cause"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_set_log_file_switches_and_closes_previous() {
        let first = temp_path("switch_first");
        let second = temp_path("switch_second");
        let logger = HeadlessErrorLogger::new(Some(&first));
        logger.set_log_file(Some(&second));
        logger.error("Origin", &"after switch");

        let first_contents = fs::read_to_string(&first).unwrap();
        assert!(first_contents.contains("Switching log file to"));

        let second_contents = fs::read_to_string(&second).unwrap();
        assert!(second_contents.contains("ERROR after switch"));

        fs::remove_file(&first).ok();
        fs::remove_file(&second).ok();
    }

    #[test]
    fn test_set_log_file_none_disables_logging() {
        let path = temp_path("disable");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.set_log_file(None);
        logger.error("Origin", &"should not be written");

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("File logging disabled"));
        assert!(!contents.contains("should not be written"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_multiline_message_is_split_per_line() {
        let path = temp_path("multiline");
        let logger = HeadlessErrorLogger::new(Some(&path));
        logger.error("Origin", &"line one\nline two");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("ERROR line one"));
        assert!(contents.contains("ERROR line two"));
        fs::remove_file(&path).ok();
    }
}
