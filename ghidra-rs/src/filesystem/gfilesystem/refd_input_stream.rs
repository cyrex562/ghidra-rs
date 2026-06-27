use std::io::{self, Read, Write};

/// An [`io::Read`] wrapper that keeps a filesystem reference pinned until the stream is closed.
///
/// The type parameter `R` stands in for `FileSystemRef` until that class is ported; any owned
/// type whose [`Drop`] impl releases the filesystem reference will satisfy the bound.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.RefdInputStream`.
pub struct RefdInputStream<R> {
    fs_ref: Option<R>,
    inner: Box<dyn Read>,
}

impl<R> RefdInputStream<R> {
    /// Creates a new `RefdInputStream` wrapping `inner` and keeping `fs_ref` pinned.
    ///
    /// Mirrors `RefdInputStream(FileSystemRef, InputStream)` from the Java source.
    pub fn new(fs_ref: R, inner: Box<dyn Read>) -> Self {
        RefdInputStream {
            fs_ref: Some(fs_ref),
            inner,
        }
    }

    /// Releases the filesystem reference and drops the inner reader.
    ///
    /// Mirrors Java's `close()`: the filesystem reference is released first (idempotent),
    /// then the inner reader is dropped when `self` goes out of scope.
    pub fn close(mut self) {
        self.fs_ref.take();
    }

    /// Copies all remaining bytes from this stream into `out`.
    ///
    /// Mirrors Java's `transferTo(OutputStream)`.
    pub fn transfer_to<W: Write>(&mut self, out: &mut W) -> io::Result<u64> {
        io::copy(&mut self.inner, out)
    }

    /// Discards exactly `n` bytes from the stream, returning an error if fewer are available.
    ///
    /// Mirrors Java's `skipNBytes(long)`.
    pub fn skip_n_bytes(&mut self, n: u64) -> io::Result<()> {
        let mut remaining = n;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let to_read = remaining.min(buf.len() as u64) as usize;
            match self.inner.read(&mut buf[..to_read])? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended before skipNBytes could skip all requested bytes",
                    ))
                }
                n => remaining -= n as u64,
            }
        }
        Ok(())
    }

    /// Discards up to `n` bytes from the stream, returning the number of bytes skipped.
    ///
    /// Mirrors Java's `skip(long)`.
    pub fn skip(&mut self, n: u64) -> io::Result<u64> {
        let mut skipped = 0u64;
        let mut buf = [0u8; 8192];
        while skipped < n {
            let to_read = (n - skipped).min(buf.len() as u64) as usize;
            match self.inner.read(&mut buf[..to_read])? {
                0 => break,
                k => skipped += k as u64,
            }
        }
        Ok(skipped)
    }
}

impl<R> Read for RefdInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    // ── Drop-tracking filesystem ref mock ─────────────────────────────────────

    struct MockRef {
        closed: Rc<Cell<bool>>,
    }

    impl Drop for MockRef {
        fn drop(&mut self) {
            self.closed.set(true);
        }
    }

    fn make_ref() -> (MockRef, Rc<Cell<bool>>) {
        let flag = Rc::new(Cell::new(false));
        let r = MockRef { closed: Rc::clone(&flag) };
        (r, flag)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn read_delegates_to_inner() {
        let (r, _flag) = make_ref();
        let data = b"hello world";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[test]
    fn close_releases_fs_ref() {
        let (r, flag) = make_ref();
        let stream = RefdInputStream::new(r, Box::new(b"".as_ref()));
        assert!(!flag.get());
        stream.close();
        assert!(flag.get(), "fs_ref must be released after close()");
    }

    #[test]
    fn drop_releases_fs_ref() {
        let (r, flag) = make_ref();
        {
            let _stream = RefdInputStream::new(r, Box::new(b"".as_ref()));
            assert!(!flag.get());
        }
        assert!(flag.get(), "fs_ref must be released on drop");
    }

    #[test]
    fn fs_ref_released_before_inner_on_drop() {
        // Verify declaration-order drop: fs_ref (Option<R>) is first field → dropped first.
        use std::cell::RefCell;

        #[derive(Default)]
        struct DropLog(Rc<RefCell<Vec<&'static str>>>);

        struct FsRefGuard(DropLog);
        impl Drop for FsRefGuard {
            fn drop(&mut self) {
                self.0 .0.borrow_mut().push("fs_ref");
            }
        }

        struct InnerReader {
            log: DropLog,
            data: &'static [u8],
        }
        impl Read for InnerReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.data.read(buf)
            }
        }
        impl Drop for InnerReader {
            fn drop(&mut self) {
                self.log.0.borrow_mut().push("inner");
            }
        }

        let log = Rc::new(RefCell::new(Vec::new()));
        let fs_log = DropLog(Rc::clone(&log));
        let inner_log = DropLog(Rc::clone(&log));
        {
            let _stream = RefdInputStream::new(
                FsRefGuard(fs_log),
                Box::new(InnerReader { log: inner_log, data: b"" }),
            );
        }
        let order = log.borrow().clone();
        assert_eq!(order, vec!["fs_ref", "inner"], "fs_ref must drop before inner");
    }

    #[test]
    fn transfer_to_copies_all_bytes() {
        let (r, _flag) = make_ref();
        let data = b"transfer me";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        let mut out = Vec::new();
        let n = stream.transfer_to(&mut out).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(out, b"transfer me");
    }

    #[test]
    fn skip_discards_bytes() {
        let (r, _flag) = make_ref();
        let data = b"abcdef";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        let skipped = stream.skip(3).unwrap();
        assert_eq!(skipped, 3);
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"def");
    }

    #[test]
    fn skip_n_bytes_exact() {
        let (r, _flag) = make_ref();
        let data = b"123456";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        stream.skip_n_bytes(3).unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"456");
    }

    #[test]
    fn skip_n_bytes_returns_error_on_short_stream() {
        let (r, _flag) = make_ref();
        let data = b"ab";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        assert!(stream.skip_n_bytes(10).is_err());
    }

    #[test]
    fn read_partial_buffer() {
        let (r, _flag) = make_ref();
        let data = b"hello";
        let mut stream = RefdInputStream::new(r, Box::new(data.as_ref()));
        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf).unwrap();
        assert!(n <= 3);
        assert_eq!(&buf[..n], &b"hello"[..n]);
    }

    #[test]
    fn empty_stream_reads_zero_bytes() {
        let (r, _flag) = make_ref();
        let mut stream = RefdInputStream::new(r, Box::new(b"".as_ref()));
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
