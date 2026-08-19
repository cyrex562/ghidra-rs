use super::EmuUnixFileStat;
use crate::pcode::seam_stubs::EmuIOException;

/// The default file descriptor for stdin (standard input).
pub const FD_STDIN: i32 = 0;
/// The default file descriptor for stdout (standard output).
pub const FD_STDOUT: i32 = 1;
/// The default file descriptor for stderr (standard error output).
pub const FD_STDERR: i32 = 2;

/// A process's handle to a file (or other resource), storing values of type `T`.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixFileDescriptor`.
pub trait EmuUnixFileDescriptor<T> {
    /// Get the current offset of the file, or 0 if not applicable.
    fn offset(&self) -> T;

    /// Seek to the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn seek(&mut self, offset: T) -> Result<(), EmuIOException>;

    /// Read from the file opened by this handle.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn read(&mut self, buf: T) -> Result<T, EmuIOException>;

    /// Write into the file opened by this handle.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn write(&mut self, buf: T) -> Result<T, EmuIOException>;

    /// Obtain the `stat` structure of the file opened by this handle.
    fn stat(&self) -> EmuUnixFileStat;

    /// Close this descriptor.
    fn close(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-memory descriptor, used only to prove the trait's shape is implementable
    /// and behaves like Java's contract (offset tracking, read/write byte counts, stat/close).
    struct MockFileDescriptor {
        data: Vec<u8>,
        offset: i64,
        stat: EmuUnixFileStat,
        closed: bool,
    }

    impl EmuUnixFileDescriptor<i64> for MockFileDescriptor {
        fn offset(&self) -> i64 {
            self.offset
        }

        fn seek(&mut self, offset: i64) -> Result<(), EmuIOException> {
            if offset < 0 {
                return Err(EmuIOException::new("negative offset"));
            }
            self.offset = offset;
            Ok(())
        }

        fn read(&mut self, buf: i64) -> Result<i64, EmuIOException> {
            let start = self.offset as usize;
            let want = buf as usize;
            let avail = self.data.len().saturating_sub(start);
            let n = want.min(avail);
            self.offset += n as i64;
            Ok(n as i64)
        }

        fn write(&mut self, buf: i64) -> Result<i64, EmuIOException> {
            let n = buf;
            self.offset += n;
            Ok(n)
        }

        fn stat(&self) -> EmuUnixFileStat {
            self.stat
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    #[test]
    fn constants_match_java_values() {
        assert_eq!(FD_STDIN, 0);
        assert_eq!(FD_STDOUT, 1);
        assert_eq!(FD_STDERR, 2);
    }

    #[test]
    fn seek_updates_offset() {
        let mut fd = MockFileDescriptor {
            data: vec![0u8; 10],
            offset: 0,
            stat: EmuUnixFileStat::default(),
            closed: false,
        };
        fd.seek(5).unwrap();
        assert_eq!(fd.offset(), 5);
    }

    #[test]
    fn seek_rejects_negative_offset() {
        let mut fd = MockFileDescriptor {
            data: vec![0u8; 10],
            offset: 0,
            stat: EmuUnixFileStat::default(),
            closed: false,
        };
        assert!(fd.seek(-1).is_err());
    }

    #[test]
    fn read_advances_offset_by_bytes_read() {
        let mut fd = MockFileDescriptor {
            data: vec![0u8; 10],
            offset: 8,
            stat: EmuUnixFileStat::default(),
            closed: false,
        };
        let n = fd.read(5).unwrap();
        assert_eq!(n, 2);
        assert_eq!(fd.offset(), 10);
    }

    #[test]
    fn write_advances_offset_by_bytes_written() {
        let mut fd = MockFileDescriptor {
            data: vec![0u8; 10],
            offset: 0,
            stat: EmuUnixFileStat::default(),
            closed: false,
        };
        let n = fd.write(4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(fd.offset(), 4);
    }

    #[test]
    fn stat_returns_configured_stat() {
        let stat = EmuUnixFileStat {
            st_size: 42,
            ..Default::default()
        };
        let fd = MockFileDescriptor {
            data: vec![],
            offset: 0,
            stat,
            closed: false,
        };
        assert_eq!(fd.stat().st_size, 42);
    }

    #[test]
    fn close_marks_descriptor_closed() {
        let mut fd = MockFileDescriptor {
            data: vec![],
            offset: 0,
            stat: EmuUnixFileStat::default(),
            closed: false,
        };
        fd.close();
        assert!(fd.closed);
    }

    #[test]
    fn trait_object_is_usable() {
        let mut fd: Box<dyn EmuUnixFileDescriptor<i64>> = Box::new(MockFileDescriptor {
            data: vec![0u8; 3],
            offset: 0,
            stat: EmuUnixFileStat::default(),
            closed: false,
        });
        assert_eq!(fd.read(10).unwrap(), 3);
    }
}
