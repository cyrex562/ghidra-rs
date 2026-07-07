use egui::Color32;
use std::io::Write;

/// A print writer that allows clients to specify the text color.
///
/// Ported from `ghidra.app.script.DecoratingPrintWriter`.
pub trait DecoratingPrintWriter: Write {
    /// Print a line of text with the given color.
    fn println(&mut self, s: &str, c: Color32) -> std::io::Result<()>;

    /// Print text with the given color.
    fn print(&mut self, s: &str, c: Color32) -> std::io::Result<()>;
}

/// A generic decorating print writer implementation that wraps any `Write` type.
pub struct DecoratingWriter<W: Write> {
    writer: W,
}

impl<W: Write> DecoratingWriter<W> {
    /// Create a new decorating writer wrapping the given writer.
    pub fn new(writer: W) -> Self {
        DecoratingWriter { writer }
    }

    /// Consume this decorating writer and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for DecoratingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> DecoratingPrintWriter for DecoratingWriter<W> {
    fn println(&mut self, s: &str, _c: Color32) -> std::io::Result<()> {
        writeln!(self.writer, "{}", s)
    }

    fn print(&mut self, s: &str, _c: Color32) -> std::io::Result<()> {
        write!(self.writer, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decorating_writer_new() {
        let buf: Vec<u8> = Vec::new();
        let writer = DecoratingWriter::new(buf);
        assert_eq!(writer.into_inner().len(), 0);
    }

    #[test]
    fn test_print_with_color() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = DecoratingWriter::new(buf);
        let color = Color32::RED;

        writer.print("Hello", color).unwrap();
        let result = writer.into_inner();
        assert_eq!(String::from_utf8(result).unwrap(), "Hello");
    }

    #[test]
    fn test_println_with_color() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = DecoratingWriter::new(buf);
        let color = Color32::BLUE;

        writer.println("World", color).unwrap();
        let result = writer.into_inner();
        assert_eq!(String::from_utf8(result).unwrap(), "World\n");
    }

    #[test]
    fn test_multiple_prints() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = DecoratingWriter::new(buf);

        writer.print("Hello", Color32::RED).unwrap();
        writer.print(" ", Color32::GREEN).unwrap();
        writer.println("World", Color32::BLUE).unwrap();

        let result = writer.into_inner();
        assert_eq!(
            String::from_utf8(result).unwrap(),
            "Hello World\n"
        );
    }

    #[test]
    fn test_write_trait() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = DecoratingWriter::new(buf);

        write!(writer, "test").unwrap();
        let result = writer.into_inner();
        assert_eq!(String::from_utf8(result).unwrap(), "test");
    }

    #[test]
    fn test_flush() {
        let buf: Vec<u8> = Vec::new();
        let mut writer = DecoratingWriter::new(buf);

        writer.write_all(b"data").unwrap();
        writer.flush().unwrap();

        let result = writer.into_inner();
        assert_eq!(result, b"data");
    }
}
