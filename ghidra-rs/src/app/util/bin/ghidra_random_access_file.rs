use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::util::msg::Msg;

const BUFFER_SIZE: usize = 0x100000;

/// Supports both reading and writing to a random access file, buffering reads
/// to limit the number of underlying I/O calls.
///
/// Mirrors `ghidra.app.util.bin.GhidraRandomAccessFile` from the original
/// Ghidra source. In Java this wraps `java.io.RandomAccessFile`; in Rust it
/// wraps [`std::fs::File`] directly, since there is no equivalent standard
/// type.
///
/// [`GhidraRandomAccessFile::seek`] only adjusts the read-buffer bookkeeping;
/// it does not move the underlying file's cursor. Only reads (via `ensure`)
/// reposition the underlying file, and writes go wherever that cursor
/// currently sits -- this mirrors the original Java behavior, quirks
/// included.
pub struct GhidraRandomAccessFile {
    path: PathBuf,
    file: Option<File>,
    buffer: Vec<u8>,
    buffer_offset: u64,
    buffer_file_start_index: u64,
    last_buffer: Vec<u8>,
    last_buffer_offset: u64,
    last_buffer_file_start_index: u64,
}

impl GhidraRandomAccessFile {
    /// Opens `path` with the mode string used by Java's `RandomAccessFile`:
    /// `"r"` for read-only, `"rw"` / `"rws"` / `"rwd"` for read-write.
    pub fn new<P: AsRef<Path>>(path: P, mode: &str) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let write = mode.contains('w');
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .create(write)
            .open(&path)?;
        Ok(GhidraRandomAccessFile {
            path,
            file: Some(file),
            buffer: Vec::new(),
            buffer_offset: 0,
            buffer_file_start_index: 0,
            last_buffer: Vec::new(),
            last_buffer_offset: 0,
            last_buffer_file_start_index: 0,
        })
    }

    fn check_open(&self) -> io::Result<()> {
        if self.file.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "GhidraRandomAccessFile is closed",
            ));
        }
        Ok(())
    }

    /// Closes this random access file stream and releases any system
    /// resources associated with the stream. A closed random access file
    /// cannot perform input or output operations and cannot be reopened.
    pub fn close(&mut self) -> io::Result<()> {
        self.check_open()?;
        self.file = None;
        self.buffer = Vec::new();
        self.last_buffer = Vec::new();
        Ok(())
    }

    /// Returns the length of this file, measured in bytes.
    pub fn length(&mut self) -> io::Result<u64> {
        self.check_open()?;
        Ok(self.file.as_ref().unwrap().metadata()?.len())
    }

    /// Sets the file-pointer offset, measured from the beginning of this
    /// file, at which the next read occurs. The offset may be set beyond the
    /// end of the file.
    pub fn seek(&mut self, pos: i64) -> io::Result<()> {
        self.check_open()?;

        if pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pos cannot be less than zero",
            ));
        }
        let pos = pos as u64;

        if pos < self.buffer_file_start_index
            || pos >= self.buffer_file_start_index + BUFFER_SIZE as u64
        {
            // check if the last buffer contained it, and swap in if necessary
            self.swap_in_last();
            if pos < self.buffer_file_start_index
                || pos >= self.buffer_file_start_index + BUFFER_SIZE as u64
            {
                // not in either, gotta get a new one
                self.buffer = Vec::new();
                self.buffer_offset = 0;
                self.buffer_file_start_index = pos;
            }
        }
        self.buffer_offset = pos - self.buffer_file_start_index;
        Ok(())
    }

    /// Reads a byte from the file, starting from the current file pointer.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        self.check_open()?;
        self.ensure(1)?;
        let b = self.buffer[self.buffer_offset as usize];
        self.buffer_offset += 1;
        Ok(b)
    }

    /// Reads `buf.len()` bytes of data from this file, filling `buf`
    /// entirely, starting at the current file pointer.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_open()?;
        let length = buf.len();
        let mut read_len = length;
        let mut out_offset = 0usize;
        loop {
            let remaining_in_buffer = BUFFER_SIZE as i64 - self.buffer_offset as i64;
            let blocklength = if read_len as i64 > remaining_in_buffer {
                if remaining_in_buffer <= 0 {
                    BUFFER_SIZE
                } else {
                    remaining_in_buffer as usize
                }
            } else {
                read_len
            };
            self.ensure(blocklength)?;
            let start = self.buffer_offset as usize;
            buf[out_offset..out_offset + blocklength]
                .copy_from_slice(&self.buffer[start..start + blocklength]);
            read_len -= blocklength;
            out_offset += blocklength;
            if read_len > 0 {
                let next_pos = self.buffer_file_start_index + self.buffer_offset + blocklength as u64;
                self.seek(next_pos as i64)?;
            }
            if read_len == 0 {
                break;
            }
        }
        Ok(length)
    }

    /// Writes a byte to this file, starting at the current file pointer.
    pub fn write_byte(&mut self, b: u8) -> io::Result<()> {
        self.check_open()?;
        self.write(&[b])
    }

    /// Writes `buf` to this file, starting at the current file pointer.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.check_open()?;
        self.file.as_mut().unwrap().write_all(buf)?;
        self.buffer = Vec::new();
        self.buffer_offset = 0;
        self.last_buffer = Vec::new();
        self.last_buffer_offset = 0;
        Ok(())
    }

    /// Ensures that enough bytes are cached to satisfy the next request to
    /// read.
    fn ensure(&mut self, bytes_needed: usize) -> io::Result<()> {
        self.check_open()?;
        let old_file_start_index = self.buffer_file_start_index;
        let old_buffer_offset = self.buffer_offset;
        let old_seek_pos = old_file_start_index + old_buffer_offset;

        if self.buffer_offset + bytes_needed as u64 > self.buffer.len() as u64 {
            // check if the last buffer contained it, and swap in if necessary
            self.swap_in_last();
            // must ensure that current read pos is in old buffer, and enough bytes
            let mut need_reload = old_seek_pos < self.buffer_file_start_index
                || old_seek_pos >= self.buffer_file_start_index + BUFFER_SIZE as u64;
            if !need_reload {
                let new_buffer_offset = old_seek_pos - self.buffer_file_start_index;
                if new_buffer_offset + bytes_needed as u64 > self.buffer.len() as u64 {
                    need_reload = true;
                } else {
                    self.buffer_offset = new_buffer_offset;
                }
            }
            if need_reload {
                self.buffer_file_start_index = old_file_start_index + old_buffer_offset;

                self.buffer = vec![0u8; BUFFER_SIZE];
                let file = self.file.as_mut().unwrap();
                file.seek(SeekFrom::Start(self.buffer_file_start_index))?;
                let bytes_read = file.read(&mut self.buffer)?;
                self.buffer_offset = 0;
                if bytes_read < bytes_needed {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "end of file reached",
                    ));
                }
            }
        }
        Ok(())
    }

    fn swap_in_last(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        // swap 'em and return
        std::mem::swap(&mut self.buffer, &mut self.last_buffer);
        std::mem::swap(&mut self.buffer_offset, &mut self.last_buffer_offset);
        std::mem::swap(
            &mut self.buffer_file_start_index,
            &mut self.last_buffer_file_start_index,
        );
    }
}

impl Drop for GhidraRandomAccessFile {
    fn drop(&mut self) {
        if self.file.is_some() {
            Msg::warn(
                "GhidraRandomAccessFile",
                &format!("FAIL TO CLOSE {}", self.path.display()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_temp_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn length_matches_file_size() {
        let f = make_temp_file(b"hello world");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        assert_eq!(raf.length().unwrap(), 11);
        raf.close().unwrap();
    }

    #[test]
    fn read_byte_reads_sequentially() {
        let f = make_temp_file(b"abc");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        assert_eq!(raf.read_byte().unwrap(), b'a');
        assert_eq!(raf.read_byte().unwrap(), b'b');
        assert_eq!(raf.read_byte().unwrap(), b'c');
        raf.close().unwrap();
    }

    #[test]
    fn seek_then_read_byte() {
        let f = make_temp_file(b"0123456789");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        raf.seek(5).unwrap();
        assert_eq!(raf.read_byte().unwrap(), b'5');
        raf.close().unwrap();
    }

    #[test]
    fn seek_negative_errors() {
        let f = make_temp_file(b"abc");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        let err = raf.seek(-1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        raf.close().unwrap();
    }

    #[test]
    fn read_slice_fills_buffer() {
        let f = make_temp_file(b"hello world");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        let mut buf = [0u8; 5];
        let n = raf.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        raf.close().unwrap();
    }

    #[test]
    fn read_past_eof_errors() {
        let f = make_temp_file(b"hi");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        let mut buf = [0u8; 5];
        assert!(raf.read(&mut buf).is_err());
        raf.close().unwrap();
    }

    #[test]
    fn write_byte_then_read_back() {
        let f = make_temp_file(b"aaaa");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "rw").unwrap();
        raf.write_byte(b'X').unwrap();
        raf.seek(0).unwrap();
        assert_eq!(raf.read_byte().unwrap(), b'X');
        raf.close().unwrap();
    }

    #[test]
    fn write_slice_then_read_back() {
        let f = make_temp_file(b"0000000000");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "rw").unwrap();
        raf.write(b"ABCDE").unwrap();
        raf.seek(0).unwrap();
        let mut buf = [0u8; 5];
        raf.read(&mut buf).unwrap();
        assert_eq!(&buf, b"ABCDE");
        raf.close().unwrap();
    }

    #[test]
    fn read_larger_than_buffer_size_spans_reloads() {
        let data = vec![7u8; BUFFER_SIZE + 10];
        let f = make_temp_file(&data);
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        let mut buf = vec![0u8; data.len()];
        let n = raf.read(&mut buf).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(buf, data);
        raf.close().unwrap();
    }

    #[test]
    fn close_then_operations_error() {
        let f = make_temp_file(b"abc");
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        raf.close().unwrap();
        assert!(raf.read_byte().is_err());
        assert!(raf.close().is_err());
    }

    #[test]
    fn seek_across_buffers_then_back() {
        let mut data = vec![0u8; BUFFER_SIZE * 2];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let f = make_temp_file(&data);
        let mut raf = GhidraRandomAccessFile::new(f.path(), "r").unwrap();
        raf.seek(0).unwrap();
        assert_eq!(raf.read_byte().unwrap(), data[0]);
        raf.seek(BUFFER_SIZE as i64).unwrap();
        assert_eq!(raf.read_byte().unwrap(), data[BUFFER_SIZE]);
        // swap back to the first (now "last") buffer
        raf.seek(0).unwrap();
        assert_eq!(raf.read_byte().unwrap(), data[0]);
        raf.close().unwrap();
    }
}
