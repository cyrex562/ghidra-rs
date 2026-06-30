use std::io::{self, Read, Seek, SeekFrom};

const BUFFER_SIZE: u64 = 8192;

/// Reads lines from a file in reverse order, starting from the current file position.
///
/// CONOPS:
/// 1. Start at a given position in the file and read up to `BUFFER_SIZE` bytes into a buffer.
/// 2. From the end of the buffer, scan backwards one byte at a time.
/// 3. If a newline (`\n`) or carriage-return (`\r`) is encountered, the line is complete; return it.
/// 4. Otherwise continue scanning until the beginning of the buffer is exhausted.
pub struct ReverseLineReader<F: Read + Seek> {
    encoding: String,
    buf: Vec<u8>,
    /// The underlying seekable file handle.
    pub file: F,
}

impl<F: Read + Seek> ReverseLineReader<F> {
    /// Creates a new `ReverseLineReader`.
    ///
    /// `encoding` mirrors the Java API parameter; byte-to-string conversion always uses
    /// UTF-8 (with replacement characters for invalid sequences).
    pub fn new(encoding: impl Into<String>, file: F) -> io::Result<Self> {
        Ok(Self {
            encoding: encoding.into(),
            buf: Vec::new(),
            file,
        })
    }

    /// Returns the encoding hint supplied at construction time.
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    /// Moves the file pointer to `position`, clamping negative values to 0.
    pub fn set_file_pos(&mut self, position: i64) {
        let pos = if position < 0 { 0 } else { position as u64 };
        let _ = self.file.seek(SeekFrom::Start(pos));
    }

    /// Reads a single line from the current file-pointer position, scanning backwards.
    ///
    /// Returns `Ok(None)` when the file pointer is already at the beginning of the file.
    /// Windows (`\r\n`) and Unix (`\n`) line endings are both handled.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let end = self.file.seek(SeekFrom::Current(0))?;
        if end == 0 {
            return Ok(None);
        }

        let start = end.saturating_sub(BUFFER_SIZE);
        let len = (end - start) as usize;
        let mut line_buf = vec![0u8; len];

        self.file.seek(SeekFrom::Start(start))?;
        self.file.read_exact(&mut line_buf)?;
        // file pointer is now back at `end`

        for i in (0..len).rev() {
            let c = line_buf[i];
            if c == b'\r' || c == b'\n' {
                let s = self.buf_to_string();
                let newline_subtrahend =
                    if c == b'\n' && i > 0 && line_buf[i - 1] == b'\r' { 1u64 } else { 0u64 };
                let new_pos = start + i as u64 - newline_subtrahend;
                self.file.seek(SeekFrom::Start(new_pos))?;
                return Ok(Some(s));
            }
            self.buf.push(c);
        }

        // Consumed the entire buffer without finding a newline; we are at the file start.
        self.file.seek(SeekFrom::Start(0))?;
        Ok(Some(self.buf_to_string()))
    }

    fn buf_to_string(&mut self) -> String {
        if self.buf.is_empty() {
            return String::new();
        }
        self.buf.reverse();
        let s = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader_at_end(content: &[u8]) -> ReverseLineReader<Cursor<Vec<u8>>> {
        let len = content.len() as u64;
        let mut cursor = Cursor::new(content.to_vec());
        cursor.seek(SeekFrom::Start(len)).unwrap();
        ReverseLineReader::new("UTF-8", cursor).unwrap()
    }

    #[test]
    fn at_start_returns_none() {
        let mut r = reader_at_end(b"hello");
        r.set_file_pos(0);
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn empty_file_returns_none() {
        let mut r = reader_at_end(b"");
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn single_line_no_newline() {
        let mut r = reader_at_end(b"hello");
        assert_eq!(r.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn two_lines_unix() {
        let mut r = reader_at_end(b"line1\nline2");
        assert_eq!(r.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn windows_line_endings() {
        let mut r = reader_at_end(b"line1\r\nline2");
        assert_eq!(r.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn trailing_newline_yields_empty_last_line() {
        let mut r = reader_at_end(b"hello\n");
        assert_eq!(r.read_line().unwrap(), Some("".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn multiple_lines() {
        let mut r = reader_at_end(b"a\nb\nc");
        assert_eq!(r.read_line().unwrap(), Some("c".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("b".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("a".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn set_file_pos_negative_clamps_to_zero() {
        let mut r = reader_at_end(b"hello");
        r.set_file_pos(-100);
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn set_file_pos_positions_correctly() {
        let content = b"line1\nline2";
        let cursor = Cursor::new(content.to_vec());
        let mut r = ReverseLineReader::new("UTF-8", cursor).unwrap();
        r.set_file_pos(content.len() as i64);
        assert_eq!(r.read_line().unwrap(), Some("line2".to_string()));
    }

    #[test]
    fn encoding_accessor() {
        let cursor = Cursor::new(vec![]);
        let r = ReverseLineReader::new("ISO-8859-1", cursor).unwrap();
        assert_eq!(r.encoding(), "ISO-8859-1");
    }

    #[test]
    fn standalone_newline_line() {
        let mut r = reader_at_end(b"a\n\nb");
        assert_eq!(r.read_line().unwrap(), Some("b".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("a".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }
}
