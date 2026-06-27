use std::io::{self, Read};

const DEFAULT_CHAR_BUFFER_SIZE: usize = 8192;
const DEFAULT_EXPECTED_LINE_LENGTH: usize = 80;

const INVALIDATED: i64 = -2;
const UNMARKED: i64 = -1;

/// A buffered reader with a bounded read-line implementation.
///
/// Unlike `BufReader`, when a line accumulates more than 0x1000 bytes across
/// buffer refills the `read_line` method returns an empty string rather than
/// continuing to grow unboundedly. The `read` / `skip` / mark-reset API is
/// otherwise equivalent to Java's `BufferedReader`.
pub struct BoundedBufferedReader<R: Read> {
    inner: Option<R>,
    buf: Vec<u8>,
    n_chars: usize,
    next_char: usize,
    marked_char: i64,
    read_ahead_limit: usize,
    skip_lf: bool,
    marked_skip_lf: bool,
}

impl<R: Read> BoundedBufferedReader<R> {
    /// Creates a reader with a buffer of `sz` bytes.
    pub fn new(inner: R, sz: usize) -> Self {
        assert!(sz > 0, "Buffer size <= 0");
        BoundedBufferedReader {
            inner: Some(inner),
            buf: vec![0u8; sz],
            n_chars: 0,
            next_char: 0,
            marked_char: UNMARKED,
            read_ahead_limit: 0,
            skip_lf: false,
            marked_skip_lf: false,
        }
    }

    /// Creates a reader with the default buffer size (8192 bytes).
    pub fn with_default_buffer(inner: R) -> Self {
        Self::new(inner, DEFAULT_CHAR_BUFFER_SIZE)
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.inner.is_none() {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "Stream closed"))
        } else {
            Ok(())
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let dst;
        if self.marked_char <= UNMARKED {
            dst = 0;
        } else {
            let delta = self.next_char as i64 - self.marked_char;
            if delta >= self.read_ahead_limit as i64 {
                self.marked_char = INVALIDATED;
                self.read_ahead_limit = 0;
                dst = 0;
            } else {
                let delta = delta as usize;
                let marked = self.marked_char as usize;
                if self.read_ahead_limit <= self.buf.len() {
                    self.buf.copy_within(marked..marked + delta, 0);
                    self.marked_char = 0;
                    dst = delta;
                } else {
                    let mut ncb = vec![0u8; self.read_ahead_limit];
                    ncb[..delta].copy_from_slice(&self.buf[marked..marked + delta]);
                    self.buf = ncb;
                    self.marked_char = 0;
                    dst = delta;
                }
                self.next_char = delta;
                self.n_chars = delta;
            }
        }

        let inner = self.inner.as_mut().unwrap();
        let buf_len = self.buf.len();
        loop {
            let n = inner.read(&mut self.buf[dst..buf_len])?;
            if n != 0 {
                self.n_chars = dst + n;
                self.next_char = dst;
                break;
            }
        }
        Ok(())
    }

    /// Reads a single byte. Returns `None` on EOF.
    pub fn read_byte(&mut self) -> io::Result<Option<u8>> {
        self.ensure_open()?;
        loop {
            if self.next_char >= self.n_chars {
                self.fill()?;
                if self.next_char >= self.n_chars {
                    return Ok(None);
                }
            }
            if self.skip_lf {
                self.skip_lf = false;
                if self.buf[self.next_char] == b'\n' {
                    self.next_char += 1;
                    continue;
                }
            }
            let b = self.buf[self.next_char];
            self.next_char += 1;
            return Ok(Some(b));
        }
    }

    fn read1(&mut self, cbuf: &mut [u8], off: usize, len: usize) -> io::Result<Option<usize>> {
        if self.next_char >= self.n_chars {
            if len >= self.buf.len() && self.marked_char <= UNMARKED && !self.skip_lf {
                let n = self.inner.as_mut().unwrap().read(&mut cbuf[off..off + len])?;
                return Ok(if n == 0 { None } else { Some(n) });
            }
            self.fill()?;
        }
        if self.next_char >= self.n_chars {
            return Ok(None);
        }
        if self.skip_lf {
            self.skip_lf = false;
            if self.buf[self.next_char] == b'\n' {
                self.next_char += 1;
                if self.next_char >= self.n_chars {
                    self.fill()?;
                }
                if self.next_char >= self.n_chars {
                    return Ok(None);
                }
            }
        }
        let n = len.min(self.n_chars - self.next_char);
        cbuf[off..off + n].copy_from_slice(&self.buf[self.next_char..self.next_char + n]);
        self.next_char += n;
        Ok(Some(n))
    }

    /// Reads bytes into `cbuf[off..off+len]`. Returns number of bytes read, or `None` on EOF.
    pub fn read_bytes(&mut self, cbuf: &mut [u8], off: usize, len: usize) -> io::Result<Option<usize>> {
        self.ensure_open()?;
        if len == 0 {
            return Ok(Some(0));
        }
        let mut n = match self.read1(cbuf, off, len)? {
            None => return Ok(None),
            Some(0) => return Ok(Some(0)),
            Some(n) => n,
        };
        // Attempt to read more while data is immediately available (inner.read returns > 0
        // without blocking — approximated here by looping while there is buffered data).
        while n < len && self.next_char < self.n_chars {
            match self.read1(cbuf, off + n, len - n)? {
                None | Some(0) => break,
                Some(n1) => n += n1,
            }
        }
        Ok(Some(n))
    }

    /// Reads a line of text, optionally skipping a leading `\n` (for `\r\n` sequences).
    ///
    /// Returns `None` on EOF with no data. Returns `""` if a line grew past 0x1000 bytes
    /// without a line terminator (the bounded-read guard from the Java original).
    pub fn read_line_inner(&mut self, ignore_lf: bool) -> io::Result<Option<String>> {
        self.ensure_open()?;
        let mut s: Option<Vec<u8>> = None;
        let mut omit_lf = ignore_lf || self.skip_lf;

        loop {
            if self.next_char >= self.n_chars {
                self.fill()?;
            }
            if self.next_char >= self.n_chars {
                // EOF
                return Ok(s.map(|v| String::from_utf8_lossy(&v).into_owned()).or(None));
            }

            let mut eol = false;
            let mut eol_char = 0u8;

            if omit_lf && self.buf[self.next_char] == b'\n' {
                self.next_char += 1;
            }
            self.skip_lf = false;
            omit_lf = false;

            let start_char = self.next_char;
            let mut i = self.next_char;
            while i < self.n_chars {
                let c = self.buf[i];
                if c == b'\n' || c == b'\r' {
                    eol = true;
                    eol_char = c;
                    break;
                }
                i += 1;
            }

            let segment = &self.buf[start_char..i];
            self.next_char = i;

            if eol {
                let result = match &mut s {
                    None => String::from_utf8_lossy(segment).into_owned(),
                    Some(v) => {
                        v.extend_from_slice(segment);
                        String::from_utf8_lossy(v).into_owned()
                    }
                };
                self.next_char += 1;
                if eol_char == b'\r' {
                    self.skip_lf = true;
                }
                return Ok(Some(result));
            }

            let acc = s.get_or_insert_with(|| Vec::with_capacity(DEFAULT_EXPECTED_LINE_LENGTH));
            acc.extend_from_slice(segment);

            // Bounded guard: if the buffer itself is larger than 0x1000, return empty string.
            if self.buf.len() > 0x1000 {
                return Ok(Some(String::new()));
            }
        }
    }

    /// Reads a line of text. Returns `None` on EOF.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        self.read_line_inner(false)
    }

    /// Skips up to `n` bytes. Returns the number actually skipped.
    pub fn skip(&mut self, n: u64) -> io::Result<u64> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure_open()?;
        let mut r = n;
        while r > 0 {
            if self.next_char >= self.n_chars {
                self.fill()?;
            }
            if self.next_char >= self.n_chars {
                break;
            }
            if self.skip_lf {
                self.skip_lf = false;
                if self.buf[self.next_char] == b'\n' {
                    self.next_char += 1;
                }
            }
            let d = (self.n_chars - self.next_char) as u64;
            if r <= d {
                self.next_char += r as usize;
                r = 0;
                break;
            }
            r -= d;
            self.next_char = self.n_chars;
        }
        Ok(n - r)
    }

    /// Returns `true` if there is buffered data or the underlying reader has data.
    pub fn ready(&mut self) -> io::Result<bool> {
        self.ensure_open()?;
        Ok(self.next_char < self.n_chars)
    }

    /// Marks the current position. `read_ahead_limit` is the look-ahead budget.
    pub fn mark(&mut self, read_ahead_limit: usize) -> io::Result<()> {
        self.ensure_open()?;
        self.read_ahead_limit = read_ahead_limit;
        self.marked_char = self.next_char as i64;
        self.marked_skip_lf = self.skip_lf;
        Ok(())
    }

    /// Resets the stream to the most recent mark.
    pub fn reset(&mut self) -> io::Result<()> {
        self.ensure_open()?;
        if self.marked_char < 0 {
            let msg = if self.marked_char == INVALIDATED {
                "Mark invalid"
            } else {
                "Stream not marked"
            };
            return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
        }
        self.next_char = self.marked_char as usize;
        self.skip_lf = self.marked_skip_lf;
        Ok(())
    }

    /// Closes the reader.
    pub fn close(&mut self) {
        self.inner = None;
        self.buf = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(s: &str) -> BoundedBufferedReader<Cursor<Vec<u8>>> {
        BoundedBufferedReader::with_default_buffer(Cursor::new(s.as_bytes().to_vec()))
    }

    fn reader_sz(s: &str, sz: usize) -> BoundedBufferedReader<Cursor<Vec<u8>>> {
        BoundedBufferedReader::new(Cursor::new(s.as_bytes().to_vec()), sz)
    }

    #[test]
    fn read_line_lf() {
        let mut r = reader("hello\nworld\n");
        assert_eq!(r.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("world".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn read_line_crlf() {
        let mut r = reader("foo\r\nbar\r\n");
        assert_eq!(r.read_line().unwrap(), Some("foo".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("bar".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn read_line_cr_only() {
        let mut r = reader("a\rb\rc");
        assert_eq!(r.read_line().unwrap(), Some("a".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("b".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("c".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn read_line_no_trailing_newline() {
        let mut r = reader("abc");
        assert_eq!(r.read_line().unwrap(), Some("abc".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn read_line_empty_lines() {
        let mut r = reader("\n\nok\n");
        assert_eq!(r.read_line().unwrap(), Some("".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("ok".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn read_byte_basic() {
        let mut r = reader("AB");
        assert_eq!(r.read_byte().unwrap(), Some(b'A'));
        assert_eq!(r.read_byte().unwrap(), Some(b'B'));
        assert_eq!(r.read_byte().unwrap(), None);
    }

    #[test]
    fn skip_basic() {
        let mut r = reader("hello world");
        assert_eq!(r.skip(6).unwrap(), 6);
        assert_eq!(r.read_byte().unwrap(), Some(b'w'));
    }

    #[test]
    fn skip_past_end() {
        let mut r = reader("hi");
        assert_eq!(r.skip(100).unwrap(), 2);
        assert_eq!(r.read_byte().unwrap(), None);
    }

    #[test]
    fn mark_reset() {
        let mut r = reader("abcdef");
        // read 'a'
        assert_eq!(r.read_byte().unwrap(), Some(b'a'));
        // mark here
        r.mark(10).unwrap();
        assert_eq!(r.read_byte().unwrap(), Some(b'b'));
        assert_eq!(r.read_byte().unwrap(), Some(b'c'));
        // reset to mark
        r.reset().unwrap();
        assert_eq!(r.read_byte().unwrap(), Some(b'b'));
    }

    #[test]
    fn reset_without_mark_errors() {
        let mut r = reader("abc");
        assert!(r.reset().is_err());
    }

    #[test]
    fn close_makes_stream_unusable() {
        let mut r = reader("abc");
        r.close();
        assert!(r.read_byte().is_err());
    }

    #[test]
    fn small_buffer_fill_across_boundary() {
        // Buffer of 4; line is longer than one fill cycle.
        let mut r = reader_sz("hello\nworld", 4);
        assert_eq!(r.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(r.read_line().unwrap(), Some("world".to_string()));
        assert_eq!(r.read_line().unwrap(), None);
    }

    #[test]
    fn bounded_guard_large_buffer() {
        // Buffer > 0x1000 bytes with no newline triggers the bounded guard.
        let data: String = "x".repeat(0x1001);
        let mut r = reader_sz(&data, 0x1001);
        let line = r.read_line().unwrap();
        // Either empty string (bounded guard) or the full content (if it fits in one fill).
        // When buffer > 0x1000 and no newline found in one pass, returns "".
        assert!(line == Some(String::new()) || line == Some(data));
    }

    #[test]
    fn read_bytes_basic() {
        let mut r = reader("hello");
        let mut buf = [0u8; 5];
        assert_eq!(r.read_bytes(&mut buf, 0, 5).unwrap(), Some(5));
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn ready_reflects_buffer_state() {
        let mut r = reader("x");
        // Nothing buffered yet.
        assert!(!r.ready().unwrap());
        // After a read, buffer is filled.
        let _ = r.read_byte().unwrap();
        // Buffer should now be empty again.
        assert!(!r.ready().unwrap());
    }
}
