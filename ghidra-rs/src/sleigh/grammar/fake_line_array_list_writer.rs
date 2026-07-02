/// A writer that discards all written content.
///
/// Mirrors `ghidra.sleigh.grammar.FakeLineArrayListWriter`, a no-op subclass of
/// `LineArrayListWriter`. All write operations are discarded; the writer maintains
/// no state and produces no output.
pub struct FakeLineArrayListWriter;

impl FakeLineArrayListWriter {
    /// Creates a new fake writer.
    pub fn new() -> Self {
        Self
    }

    /// No-op; discards the request to advance to the next line.
    pub fn new_line(&mut self) {}

    /// No-op; discards all written content.
    pub fn write(&mut self, _s: &str) {}

    /// No-op; the writer never actually closes.
    pub fn close(&self) {}

    /// No-op; the writer has nothing to flush.
    pub fn flush(&self) {}
}

impl Default for FakeLineArrayListWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_instance() {
        let _w = FakeLineArrayListWriter::new();
    }

    #[test]
    fn default_creates_instance() {
        let _w = FakeLineArrayListWriter::default();
    }

    #[test]
    fn new_line_accepts_call() {
        let mut w = FakeLineArrayListWriter::new();
        w.new_line();
    }

    #[test]
    fn write_accepts_call() {
        let mut w = FakeLineArrayListWriter::new();
        w.write("test");
        w.write("");
        w.write("longer text");
    }

    #[test]
    fn multiple_calls_produce_no_effect() {
        let mut w = FakeLineArrayListWriter::new();
        w.write("line1");
        w.new_line();
        w.write("line2");
        w.new_line();
        w.write("line3");
        w.flush();
        w.close();
    }

    #[test]
    fn close_and_flush_noops() {
        let w = FakeLineArrayListWriter::new();
        w.close();
        w.flush();
    }
}
