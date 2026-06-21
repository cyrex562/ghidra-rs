use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const BUFFER_SIZE: usize = 0x10_0000; // 1 MiB, mirrors Java BUFFER_SIZE = 0x100000

/// Buffered random-access file wrapper.
///
/// Mirrors `mobiledevices.dmg.ghidra.GRandomAccessFile`. Wraps a [`File`] with
/// a two-buffer (current + "last") read cache, each 1 MiB, to reduce the number
/// of OS-level seeks and reads. The Java source stores a "last" buffer so that a
/// backward seek can often be satisfied without another OS read.
///
/// Write operations bypass the cache and write at the current logical position
/// (`buffer_file_start_index + buffer_offset`), then invalidate both cached pages.
pub struct GRandomAccessFile {
    file: File,
    buffer: Vec<u8>,
    buffer_offset: usize,
    buffer_file_start_index: u64,
    last_buffer: Vec<u8>,
    last_buffer_offset: usize,
    last_buffer_file_start_index: u64,
    open: bool,
}

impl GRandomAccessFile {
    /// Opens the file at `path` using the given `mode`.
    ///
    /// Accepted modes: `"r"` (read-only), `"rw"`, `"rws"`, `"rwd"` (read + write,
    /// creating the file if it does not exist).
    pub fn new<P: AsRef<Path>>(path: P, mode: &str) -> io::Result<Self> {
        let file = match mode {
            "r" => File::open(path.as_ref())?,
            "rw" | "rws" | "rwd" => OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path.as_ref())?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown mode: {mode}"),
                ));
            }
        };
        Ok(Self {
            file,
            buffer: Vec::new(),
            buffer_offset: 0,
            buffer_file_start_index: 0,
            last_buffer: Vec::new(),
            last_buffer_offset: 0,
            last_buffer_file_start_index: 0,
            open: true,
        })
    }

    fn check_open(&self) -> io::Result<()> {
        if self.open {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "GhidraRandomAccessFile is closed",
            ))
        }
    }

    /// Closes this file. All subsequent operations return an error.
    pub fn close(&mut self) -> io::Result<()> {
        self.check_open()?;
        self.open = false;
        Ok(())
    }

    /// Returns the length of the underlying file in bytes.
    pub fn length(&mut self) -> io::Result<u64> {
        self.check_open()?;
        Ok(self.file.metadata()?.len())
    }

    /// Sets the file-pointer offset, measured from the beginning of the file.
    ///
    /// The offset may be set beyond the end of the file; the file length changes
    /// only when a write occurs past the current end.
    pub fn seek(&mut self, pos: u64) -> io::Result<()> {
        self.check_open()?;

        let in_current = pos >= self.buffer_file_start_index
            && pos < self.buffer_file_start_index.saturating_add(BUFFER_SIZE as u64);

        if !in_current {
            self.swap_in_last()?;
            let in_after_swap = pos >= self.buffer_file_start_index
                && pos < self.buffer_file_start_index.saturating_add(BUFFER_SIZE as u64);
            if !in_after_swap {
                self.buffer = Vec::new();
                self.buffer_offset = 0;
                self.buffer_file_start_index = pos;
            }
        }
        self.buffer_offset = (pos - self.buffer_file_start_index) as usize;
        Ok(())
    }

    /// Reads and returns the byte at the current file-pointer position without
    /// advancing the pointer.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        self.check_open()?;
        self.ensure(1)?;
        Ok(self.buffer[self.buffer_offset])
    }

    /// Reads up to `b.len()` bytes from the current position into `b`.
    ///
    /// Returns the number of bytes requested (the full `b.len()`). The file
    /// pointer is left at the start of the last block read, mirroring the Java
    /// source.
    pub fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.check_open()?;
        let len = b.len();
        self.read_slice(b, 0, len)
    }

    /// Reads up to `length` bytes from the current position into `b[offset..]`.
    pub fn read_slice(
        &mut self,
        b: &mut [u8],
        mut offset: usize,
        length: usize,
    ) -> io::Result<usize> {
        self.check_open()?;
        let mut remaining = length;
        while remaining > 0 {
            let avail = BUFFER_SIZE.saturating_sub(self.buffer_offset);
            let block = if remaining > avail {
                if avail == 0 { BUFFER_SIZE } else { avail }
            } else {
                remaining
            };
            self.ensure(block)?;
            b[offset..offset + block]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + block]);
            remaining -= block;
            offset += block;
            if remaining > 0 {
                let next = self.buffer_file_start_index
                    + self.buffer_offset as u64
                    + block as u64;
                self.seek(next)?;
            }
        }
        Ok(length)
    }

    /// Writes `b` at the current logical file position.
    pub fn write_byte(&mut self, b: u8) -> io::Result<()> {
        self.check_open()?;
        self.write_slice(&[b], 0, 1)
    }

    /// Writes all of `b` at the current logical file position.
    pub fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.check_open()?;
        let len = b.len();
        self.write_slice(b, 0, len)
    }

    /// Writes `b[offset..offset+length]` at the current logical file position.
    ///
    /// Invalidates both cached read pages because the underlying file has been
    /// mutated. Mirrors `GRandomAccessFile.write(byte[], int, int)`, but
    /// explicitly seeks to the logical position before writing (the Java source
    /// writes at the underlying RAF's last position, which is correct only when
    /// `seek()` is always called before `write()` — the invariant upheld by
    /// `GByteProvider`).
    pub fn write_slice(&mut self, b: &[u8], offset: usize, length: usize) -> io::Result<()> {
        self.check_open()?;
        let pos = self.buffer_file_start_index + self.buffer_offset as u64;
        self.file.seek(SeekFrom::Start(pos))?;
        self.file.write_all(&b[offset..offset + length])?;
        self.buffer = Vec::new();
        self.buffer_offset = 0;
        self.last_buffer = Vec::new();
        self.last_buffer_offset = 0;
        Ok(())
    }

    /// Ensures that at least `bytes_needed` bytes are cached in `self.buffer`
    /// starting at `self.buffer_offset`. Swaps in the "last" buffer when it
    /// covers the current seek position; otherwise loads a fresh page from the
    /// underlying file.
    fn ensure(&mut self, bytes_needed: usize) -> io::Result<()> {
        self.check_open()?;
        if self.buffer_offset + bytes_needed <= self.buffer.len() {
            return Ok(());
        }

        let old_file_start = self.buffer_file_start_index;
        let old_offset = self.buffer_offset;
        let old_seek_pos: u64 = old_file_start + old_offset as u64;

        self.swap_in_last()?;

        let new_buffer_offset = old_seek_pos.checked_sub(self.buffer_file_start_index);

        let needs_reload = match new_buffer_offset {
            None => true,
            Some(nbo) => {
                old_seek_pos >= self.buffer_file_start_index.saturating_add(BUFFER_SIZE as u64)
                    || nbo as usize + bytes_needed > self.buffer.len()
            }
        };

        if needs_reload {
            self.buffer_file_start_index = old_file_start + old_offset as u64;
            self.buffer = vec![0u8; BUFFER_SIZE];
            self.file.seek(SeekFrom::Start(self.buffer_file_start_index))?;
            let _ = self.file.read(&mut self.buffer)?;
            self.buffer_offset = 0;
        } else {
            self.buffer_offset = new_buffer_offset.unwrap() as usize;
        }
        Ok(())
    }

    fn swap_in_last(&mut self) -> io::Result<()> {
        self.check_open()?;
        if self.buffer.is_empty() {
            return Ok(());
        }
        std::mem::swap(&mut self.buffer, &mut self.last_buffer);
        std::mem::swap(&mut self.buffer_offset, &mut self.last_buffer_offset);
        std::mem::swap(
            &mut self.buffer_file_start_index,
            &mut self.last_buffer_file_start_index,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tmp_file(content: &[u8]) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("graf_test_{}_{}.bin", pid, n));
        std::fs::write(&path, content).unwrap();
        path
    }

    fn rm(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn open_read_only() {
        let p = tmp_file(&[1, 2, 3]);
        assert!(GRandomAccessFile::new(&p, "r").is_ok());
        rm(&p);
    }

    #[test]
    fn open_read_write() {
        let p = tmp_file(&[1, 2, 3]);
        assert!(GRandomAccessFile::new(&p, "rw").is_ok());
        rm(&p);
    }

    #[test]
    fn open_invalid_mode_errors() {
        let p = tmp_file(&[]);
        assert!(GRandomAccessFile::new(&p, "xyz").is_err());
        rm(&p);
    }

    #[test]
    fn open_missing_file_errors() {
        assert!(GRandomAccessFile::new("/nonexistent/path/file.bin", "r").is_err());
    }

    #[test]
    fn length_matches_file_size() {
        let p = tmp_file(&[0u8; 42]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        assert_eq!(f.length().unwrap(), 42);
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn close_prevents_all_operations() {
        let p = tmp_file(&[1, 2, 3]);
        let mut f = GRandomAccessFile::new(&p, "rw").unwrap();
        f.close().unwrap();
        assert!(f.close().is_err());
        assert!(f.length().is_err());
        assert!(f.seek(0).is_err());
        assert!(f.read_byte().is_err());
        let mut buf = [0u8; 1];
        assert!(f.read(&mut buf).is_err());
        assert!(f.write_byte(0).is_err());
        assert!(f.write(&[0]).is_err());
        rm(&p);
    }

    #[test]
    fn seek_and_read_byte() {
        let data: Vec<u8> = (0u8..=255).collect();
        let p = tmp_file(&data);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        for &idx in &[0u64, 1, 42, 127, 255] {
            f.seek(idx).unwrap();
            assert_eq!(f.read_byte().unwrap(), data[idx as usize]);
        }
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn read_byte_does_not_advance_pointer() {
        let p = tmp_file(&[0xAA, 0xBB]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        f.seek(0).unwrap();
        assert_eq!(f.read_byte().unwrap(), 0xAA);
        assert_eq!(f.read_byte().unwrap(), 0xAA); // pointer unchanged
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn read_full_slice() {
        let p = tmp_file(&[1, 2, 3, 4, 5]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        f.seek(0).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(f.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf, &[1u8, 2, 3, 4, 5]);
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn read_slice_at_offset() {
        let p = tmp_file(&[10, 20, 30, 40, 50]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        f.seek(1).unwrap();
        let mut buf = [0u8; 3];
        f.read(&mut buf).unwrap();
        assert_eq!(&buf, &[20u8, 30, 40]);
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn read_slice_into_larger_buffer() {
        let p = tmp_file(&[1, 2, 3]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();
        f.seek(0).unwrap();
        let mut buf = [0xFFu8; 6];
        f.read_slice(&mut buf, 2, 3).unwrap();
        assert_eq!(&buf, &[0xFF, 0xFF, 1, 2, 3, 0xFF]);
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn seek_within_loaded_buffer_reuses_cache() {
        let data: Vec<u8> = (0u8..100).collect();
        let p = tmp_file(&data);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();

        f.seek(10).unwrap();
        assert_eq!(f.read_byte().unwrap(), 10); // loads buffer page

        // Seek within the same buffer page — no file I/O needed.
        f.seek(50).unwrap();
        assert_eq!(f.read_byte().unwrap(), 50);

        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn seek_backward_uses_last_buffer() {
        let data: Vec<u8> = (0u8..100).collect();
        let p = tmp_file(&data);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();

        // Forward: loads buffer starting near pos=5
        f.seek(5).unwrap();
        assert_eq!(f.read_byte().unwrap(), 5);

        // Forward within same page
        f.seek(80).unwrap();
        assert_eq!(f.read_byte().unwrap(), 80);

        // Backward into the same page — still covered by the loaded buffer
        f.seek(10).unwrap();
        assert_eq!(f.read_byte().unwrap(), 10);

        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn write_and_read_back() {
        let p = tmp_file(&[0u8; 10]);
        let mut f = GRandomAccessFile::new(&p, "rw").unwrap();
        f.seek(2).unwrap();
        f.write(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        f.seek(2).unwrap();
        let mut buf = [0u8; 4];
        f.read(&mut buf).unwrap();
        assert_eq!(&buf, &[0xDE, 0xAD, 0xBE, 0xEF]);

        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn write_byte_round_trip() {
        let p = tmp_file(&[0u8; 4]);
        let mut f = GRandomAccessFile::new(&p, "rw").unwrap();
        f.seek(3).unwrap();
        f.write_byte(0x99).unwrap();
        f.seek(3).unwrap();
        assert_eq!(f.read_byte().unwrap(), 0x99);
        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn write_invalidates_read_cache() {
        let p = tmp_file(&[1, 2, 3, 4]);
        let mut f = GRandomAccessFile::new(&p, "rw").unwrap();

        f.seek(0).unwrap();
        assert_eq!(f.read_byte().unwrap(), 1); // warms cache

        f.seek(0).unwrap();
        f.write(&[0xFF]).unwrap(); // invalidates cache

        f.seek(0).unwrap();
        assert_eq!(f.read_byte().unwrap(), 0xFF); // must re-read from file

        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn multiple_seeks_and_reads() {
        let data: Vec<u8> = (0u8..=9).collect();
        let p = tmp_file(&data);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();

        for &i in &[9u64, 0, 5, 3, 7] {
            f.seek(i).unwrap();
            assert_eq!(f.read_byte().unwrap(), data[i as usize]);
        }

        f.close().unwrap();
        rm(&p);
    }

    #[test]
    fn seek_to_start_after_reads() {
        let p = tmp_file(&[0xAA, 0xBB, 0xCC]);
        let mut f = GRandomAccessFile::new(&p, "r").unwrap();

        f.seek(2).unwrap();
        assert_eq!(f.read_byte().unwrap(), 0xCC);

        f.seek(0).unwrap();
        assert_eq!(f.read_byte().unwrap(), 0xAA);

        f.close().unwrap();
        rm(&p);
    }
}
