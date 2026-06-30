use std::fmt;

/// Platform-specific line separator, mirroring Java's `System.getProperty("line.separator")`.
#[cfg(windows)]
const LINE_SEPARATOR: &str = "\r\n";
#[cfg(not(windows))]
const LINE_SEPARATOR: &str = "\n";

/// A writer that accumulates text line by line into an array list.
///
/// Mirrors `ghidra.sleigh.grammar.LineArrayListWriter`. The writer is never
/// actually closed or flushed — those operations are intentional no-ops. Call
/// [`new_line`] to advance to the next line; all text written between successive
/// [`new_line`] calls accumulates in the current line's buffer.
///
/// [`new_line`]: LineArrayListWriter::new_line
pub struct LineArrayListWriter {
    lines: Vec<String>,
    lineno: usize,
}

impl LineArrayListWriter {
    /// Creates a new writer positioned at line 1.
    pub fn new() -> Self {
        let mut writer = Self {
            lines: Vec::new(),
            lineno: 0,
        };
        writer.new_line();
        writer
    }

    /// Appends a new empty line buffer and advances the line counter.
    pub fn new_line(&mut self) {
        self.lineno += 1;
        self.lines.push(String::new());
    }

    /// Appends `s` to the current line's buffer.
    pub fn write(&mut self, s: &str) {
        self.lines[self.lineno - 1].push_str(s);
    }

    /// No-op; the writer never actually closes.
    pub fn close(&self) {}

    /// No-op; the writer always flushes all the time.
    pub fn flush(&self) {}

    /// Returns a snapshot of all accumulated lines as individual [`String`]s.
    pub fn get_lines(&self) -> Vec<String> {
        self.lines.clone()
    }
}

impl Default for LineArrayListWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for LineArrayListWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}

impl fmt::Display for LineArrayListWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            f.write_str(line)?;
            f.write_str(LINE_SEPARATOR)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as FmtWrite;

    #[test]
    fn new_writer_starts_at_line_one() {
        let w = LineArrayListWriter::new();
        assert_eq!(w.lineno, 1);
        assert_eq!(w.lines.len(), 1);
    }

    #[test]
    fn empty_writer_has_one_empty_line() {
        let w = LineArrayListWriter::new();
        let lines = w.get_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "");
    }

    #[test]
    fn write_appends_to_current_line() {
        let mut w = LineArrayListWriter::new();
        w.write("hello");
        w.write(" world");
        assert_eq!(w.get_lines()[0], "hello world");
    }

    #[test]
    fn new_line_advances_and_separates_content() {
        let mut w = LineArrayListWriter::new();
        w.write("line1");
        w.new_line();
        w.write("line2");
        let lines = w.get_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[1], "line2");
    }

    #[test]
    fn get_lines_returns_all_lines() {
        let mut w = LineArrayListWriter::new();
        w.write("a");
        w.new_line();
        w.write("b");
        w.new_line();
        w.write("c");
        assert_eq!(w.get_lines(), vec!["a", "b", "c"]);
    }

    #[test]
    fn multiple_new_lines_create_empty_intermediate_lines() {
        let mut w = LineArrayListWriter::new();
        w.new_line();
        w.new_line();
        let lines = w.get_lines();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.is_empty()));
    }

    #[test]
    fn display_appends_line_separator_after_each_line() {
        let mut w = LineArrayListWriter::new();
        w.write("foo");
        w.new_line();
        w.write("bar");
        let expected = format!("foo{}bar{}", LINE_SEPARATOR, LINE_SEPARATOR);
        assert_eq!(w.to_string(), expected);
    }

    #[test]
    fn fmt_write_trait_delegates_to_write() {
        let mut w = LineArrayListWriter::new();
        write!(w, "via trait").unwrap();
        assert_eq!(w.get_lines()[0], "via trait");
    }

    #[test]
    fn close_and_flush_are_noops() {
        let mut w = LineArrayListWriter::new();
        w.write("text");
        w.flush();
        w.close();
        assert_eq!(w.get_lines()[0], "text");
    }

    #[test]
    fn default_equals_new() {
        let d: LineArrayListWriter = Default::default();
        assert_eq!(d.lineno, 1);
        assert_eq!(d.lines.len(), 1);
    }
}
