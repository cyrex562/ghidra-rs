use std::io::{BufRead, Error, ErrorKind};

/// Wraps a buffered reader to allow pushing back an entire line.
///
/// Models `ghidra.pcodeCPort.slgh_compile.regression.PushbackEntireLine`:
/// caches a single line read from the underlying reader, allowing it to be
/// "pushed back" and returned on the next read call.
pub struct PushbackEntireLine<R: BufRead> {
    reader: R,
    line: Option<String>,
}

impl<R: BufRead> PushbackEntireLine<R> {
    /// Creates a new wrapper around the given buffered reader.
    pub fn new(reader: R) -> Self {
        PushbackEntireLine {
            reader,
            line: None,
        }
    }

    /// Returns the next line from the reader or the previously pushed-back line.
    ///
    /// If a line was pushed back via `putback_line()`, returns that line.
    /// Otherwise, reads and returns the next line from the underlying reader.
    /// Returns `Ok(String)` for a line with no newline, or `Ok("")` for EOF.
    /// Returns `Err` if the underlying reader encounters an I/O error.
    pub fn read_line(&mut self) -> Result<String, Error> {
        if let Some(cached_line) = self.line.take() {
            return Ok(cached_line);
        }
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(String::new());
        }
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line)
    }

    /// Pushes back a line to be returned on the next `read_line()` call.
    ///
    /// Returns `Ok(())` if successful.
    /// Returns `Err` if a line is already cached (only one line can be pushed back).
    pub fn putback_line(&mut self, pushed_line: String) -> Result<(), Error> {
        if self.line.is_some() {
            return Err(Error::new(
                ErrorKind::Other,
                "can only putback one line",
            ));
        }
        self.line = Some(pushed_line);
        Ok(())
    }

    /// Closes the underlying reader.
    pub fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_line_from_reader() {
        let data = "line1\nline2\nline3";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        assert_eq!(reader.read_line().unwrap(), "line1");
        assert_eq!(reader.read_line().unwrap(), "line2");
        assert_eq!(reader.read_line().unwrap(), "line3");
    }

    #[test]
    fn read_line_strips_newlines() {
        let data = "hello\nworld\n";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        assert_eq!(reader.read_line().unwrap(), "hello");
        assert_eq!(reader.read_line().unwrap(), "world");
        assert_eq!(reader.read_line().unwrap(), "");
    }

    #[test]
    fn read_line_strips_crlf() {
        let data = "line1\r\nline2\r\n";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        assert_eq!(reader.read_line().unwrap(), "line1");
        assert_eq!(reader.read_line().unwrap(), "line2");
    }

    #[test]
    fn putback_line_returns_pushed_line() {
        let data = "line1\nline2";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        reader.read_line().unwrap();
        reader.putback_line("pushed".to_string()).unwrap();

        assert_eq!(reader.read_line().unwrap(), "pushed");
        assert_eq!(reader.read_line().unwrap(), "line2");
    }

    #[test]
    fn putback_line_only_one_allowed() {
        let data = "";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        reader.putback_line("line1".to_string()).unwrap();

        let err = reader.putback_line("line2".to_string());
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().to_string(),
            "can only putback one line"
        );
    }

    #[test]
    fn empty_reader() {
        let data = "";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        assert_eq!(reader.read_line().unwrap(), "");
    }

    #[test]
    fn putback_clears_on_read() {
        let data = "line2\nline3";
        let cursor = Cursor::new(data);
        let mut reader = PushbackEntireLine::new(cursor);

        reader.putback_line("line1".to_string()).unwrap();
        assert_eq!(reader.read_line().unwrap(), "line1");

        reader.putback_line("another".to_string()).unwrap();
        assert_eq!(reader.read_line().unwrap(), "another");
        assert_eq!(reader.read_line().unwrap(), "line2");
    }
}
