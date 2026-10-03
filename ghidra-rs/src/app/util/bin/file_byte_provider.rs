//! Port of `ghidra.app.util.bin.FileByteProvider` and
//! `ghidra.app.util.bin.ObfuscatedFileByteProvider`.
//!
//! A [`ByteProvider`] that reads its bytes from a file, via a small cache of fixed-size
//! buffers.
//!
//! Java's `ObfuscatedFileByteProvider extends FileByteProvider` only to override the two raw
//! I/O hooks (`doReadBytes`/`doWriteBytes`, which XOR every byte with a position-keyed mask)
//! and `getFile()`. Inheritance-for-reuse has no Rust translation, so the raw I/O takes a
//! private obfuscation flag and [`ObfuscatedFileByteProvider`] is a thin wrapper that enables
//! it.
//!
//! Java keeps every buffer it has read in a soft-reference map (evictable under memory
//! pressure) and additionally pins the four most recently used in an LRU map. Rust has no
//! soft references, so only the pinned LRU set is kept.
//!
//! Reads take `&self` (as [`ByteProvider`] requires) and so the open file handle and the
//! buffer cache sit behind a [`RefCell`]; this state is private to the provider.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use lru::LruCache;

use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::byte_provider::ByteProvider;
use super::obfuscated_input_stream::XOR_MASK_BYTES;

/// The size of each cached buffer. Mirrors `FileByteProvider.BUFFER_SIZE`.
pub const BUFFER_SIZE: usize = 64 * 1024;
const BUFFERS_TO_PIN: usize = 4;

/// How a [`FileByteProvider`] opens its file. Mirrors the two `java.nio.file.AccessMode`
/// values the Java class accepts (`READ` -> `"r"`, `WRITE` -> `"rw"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Open read-only.
    Read,
    /// Open read-write.
    Write,
}

struct Buffer {
    pos: u64,
    len: usize,
    bytes: Vec<u8>,
}

impl Buffer {
    fn buffer_offset(&self, file_pos: u64) -> io::Result<usize> {
        let ofs = (file_pos - self.pos) as usize;
        if ofs >= self.len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(ofs)
    }
}

struct Inner {
    raf: Option<File>,
    buffers: LruCache<u64, Buffer>,
}

/// A [`ByteProvider`] that reads from a file using a cache of buffers.
///
/// Mirrors `ghidra.app.util.bin.FileByteProvider`.
pub struct FileByteProvider {
    fsrl: Option<Fsrl>,
    file: PathBuf,
    inner: RefCell<Inner>,
    current_length: u64,
    access_mode: AccessMode,
    obfuscated: bool,
}

fn xor_mask(index: u64, buffer: &mut [u8]) {
    let mask_len = XOR_MASK_BYTES.len() as u64;
    for (i, b) in buffer.iter_mut().enumerate() {
        *b ^= XOR_MASK_BYTES[((index + i as u64) % mask_len) as usize];
    }
}

/// The raw read hook (Java's `doReadBytes`), de-obfuscating when `obfuscated`.
fn do_read_bytes(obfuscated: bool, raf: &mut File, index: u64, buffer: &mut [u8]) -> io::Result<usize> {
    raf.seek(SeekFrom::Start(index))?;
    let mut total = 0;
    while total < buffer.len() {
        match raf.read(&mut buffer[total..])? {
            0 => break,
            n => total += n,
        }
    }
    if obfuscated {
        xor_mask(index, &mut buffer[..total]);
    }
    Ok(total)
}

/// The raw write hook (Java's `doWriteBytes`), obfuscating when `obfuscated`.
fn do_write_bytes(obfuscated: bool, raf: &mut File, index: u64, buffer: &[u8]) -> io::Result<()> {
    raf.seek(SeekFrom::Start(index))?;
    if obfuscated {
        let mut tmp = buffer.to_vec();
        xor_mask(index, &mut tmp);
        raf.write_all(&tmp)
    } else {
        raf.write_all(buffer)
    }
}

impl FileByteProvider {
    /// Creates a provider over `file`, identified by `fsrl`, opened as `access_mode`.
    ///
    /// Mirrors `FileByteProvider(File, FSRL, AccessMode)`.
    ///
    /// # Errors
    /// If the file cannot be opened, or its size cannot be determined.
    pub fn new(file: &Path, fsrl: Option<Fsrl>, access_mode: AccessMode) -> io::Result<Self> {
        Self::open(file, fsrl, access_mode, false)
    }

    fn open(
        file: &Path,
        fsrl: Option<Fsrl>,
        access_mode: AccessMode,
        obfuscated: bool,
    ) -> io::Result<Self> {
        let raf = match access_mode {
            AccessMode::Read => File::open(file)?,
            AccessMode::Write => {
                OpenOptions::new().read(true).write(true).create(true).truncate(false).open(file)?
            }
        };
        let mut raf = raf;
        let current_length = Self::get_filesize(file, &mut raf)?;
        Ok(FileByteProvider {
            fsrl,
            file: file.to_path_buf(),
            inner: RefCell::new(Inner {
                raf: Some(raf),
                buffers: LruCache::new(NonZeroUsize::new(BUFFERS_TO_PIN).expect("nonzero")),
            }),
            current_length,
            access_mode,
            obfuscated,
        })
    }

    /// The access mode the file was opened with. Mirrors `getAccessMode()`.
    pub fn get_access_mode(&self) -> AccessMode {
        self.access_mode
    }

    // Some filesystems (eg. /proc, /sys) report inaccurate sizes for generated files, so the
    // last byte is read back to confirm the reported length.
    fn get_filesize(file: &Path, raf: &mut File) -> io::Result<u64> {
        let len = raf.metadata()?.len();
        if len > 0 {
            raf.seek(SeekFrom::Start(len - 1))?;
            let mut b = [0u8; 1];
            if let Ok(1) = raf.read(&mut b) {
                return Ok(len);
            }
            return Err(io::Error::other(format!(
                "Unable to determine file size: {}, reported as {len}",
                file.display()
            )));
        }
        Ok(len)
    }

    fn ensure_bounds(&self, index: u64, length: u64) -> io::Result<()> {
        if index > self.current_length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid index: {index}")));
        }
        if index + length > self.current_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unable to read past EOF: {index}, {length}"),
            ));
        }
        Ok(())
    }

    fn get_buffer_pos(index: u64) -> u64 {
        (index / BUFFER_SIZE as u64) * BUFFER_SIZE as u64
    }

    fn closed_error() -> io::Error {
        io::Error::other("FileByteProvider is closed")
    }

    /// Runs `f` against the (cached or freshly read) buffer holding `pos`.
    fn with_buffer_for<R>(&self, pos: u64, f: impl FnOnce(&Buffer) -> io::Result<R>) -> io::Result<R> {
        let buffer_pos = Self::get_buffer_pos(pos);
        if buffer_pos >= self.current_length {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let mut inner = self.inner.borrow_mut();
        if inner.buffers.get(&buffer_pos).is_none() {
            let len = (self.current_length - buffer_pos).min(BUFFER_SIZE as u64) as usize;
            let mut bytes = vec![0u8; len];
            let raf = inner.raf.as_mut().ok_or_else(Self::closed_error)?;
            let bytes_read = do_read_bytes(self.obfuscated, raf, buffer_pos, &mut bytes)?;
            inner.buffers.put(buffer_pos, Buffer { pos: buffer_pos, len: bytes_read, bytes });
        }
        let buffer = inner.buffers.get(&buffer_pos).expect("buffer just inserted");
        f(buffer)
    }

    /// Reads up to `buffer.len()` bytes starting at `index`, returning the count read.
    ///
    /// Mirrors `readBytes(long, byte[], int, int)`.
    pub fn read_bytes_into(&self, index: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.ensure_bounds(index, 0)?;
        let mut index = index;
        let mut length = (self.current_length - index).min(buffer.len() as u64) as usize;
        let mut total = 0usize;
        while length > 0 {
            let n = self.with_buffer_for(index, |fb| {
                let ofs = fb.buffer_offset(index)?;
                let n = (fb.len - ofs).min(length);
                buffer[total..total + n].copy_from_slice(&fb.bytes[ofs..ofs + n]);
                Ok(n)
            })?;
            length -= n;
            index += n as u64;
            total += n;
        }
        Ok(total)
    }

    /// Writes `buffer` at `index`, growing the file if needed.
    ///
    /// Mirrors `writeBytes(long, byte[], int, int)`: cached buffers that the write completely
    /// covers are refreshed, partially covered ones are dropped (and re-read on demand).
    ///
    /// # Errors
    /// If the provider was not opened with [`AccessMode::Write`], or the write fails.
    pub fn write_bytes(&mut self, index: u64, buffer: &[u8]) -> io::Result<()> {
        if self.access_mode != AccessMode::Write {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Not write mode"));
        }
        let obfuscated = self.obfuscated;
        let inner = self.inner.get_mut();
        let raf = inner.raf.as_mut().ok_or_else(Self::closed_error)?;
        do_write_bytes(obfuscated, raf, index, buffer)?;
        let write_end = index + buffer.len() as u64;
        self.current_length = self.current_length.max(write_end);

        let inner = self.inner.get_mut();
        let mut index = index;
        let mut offset = 0usize;
        let mut length = buffer.len();
        while length > 0 {
            let buffer_pos = Self::get_buffer_pos(index);
            let buffer_ofs = (index - buffer_pos) as usize;
            let avail = length.min(BUFFER_SIZE - buffer_ofs);
            if inner.buffers.contains(&buffer_pos) {
                if buffer_ofs == 0 && length >= BUFFER_SIZE {
                    let fb = inner.buffers.get_mut(&buffer_pos).expect("present");
                    fb.bytes.clear();
                    fb.bytes.extend_from_slice(&buffer[offset..offset + BUFFER_SIZE]);
                    fb.len = BUFFER_SIZE;
                } else {
                    inner.buffers.pop(&buffer_pos);
                }
            }
            index += avail as u64;
            offset += avail;
            length -= avail;
        }
        Ok(())
    }

    /// Writes a single byte. Mirrors `writeByte(long, byte)`.
    pub fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
        self.write_bytes(index, &[value])
    }
}

impl ByteProvider for FileByteProvider {
    fn get_file(&self) -> Option<PathBuf> {
        Some(self.file.clone())
    }

    fn get_name(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.name(),
            None => self.file.file_name().map(|n| n.to_string_lossy().into_owned()),
        }
    }

    fn get_absolute_path(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.path().map(str::to_string),
            None => std::path::absolute(&self.file)
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
        }
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }

    fn length(&self) -> u64 {
        self.current_length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.current_length
    }

    fn close(&mut self) -> io::Result<()> {
        let inner = self.inner.get_mut();
        inner.raf = None;
        inner.buffers.clear();
        Ok(())
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.ensure_bounds(index, 1)?;
        self.with_buffer_for(index, |fb| {
            let ofs = fb.buffer_offset(index)?;
            Ok(fb.bytes[ofs])
        })
    }

    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.ensure_bounds(index, length)?;
        if length > i32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Read length 0x{length:x} exceeds Integer.MAX_VALUE (0x{:x})",
                    i32::MAX
                ),
            ));
        }
        let mut result = vec![0u8; length as usize];
        let n = self.read_bytes_into(index, &mut result)?;
        if n != length as usize {
            return Err(io::Error::other(format!("Unable to read {length} bytes at {index}")));
        }
        Ok(result)
    }
}

/// A [`FileByteProvider`] over a file whose contents are XOR-obfuscated on disk (the format the
/// filesystem cache writes, to keep virus scanners from interfering with cached files).
///
/// Mirrors `ghidra.app.util.bin.ObfuscatedFileByteProvider`.
pub struct ObfuscatedFileByteProvider(FileByteProvider);

impl ObfuscatedFileByteProvider {
    /// Creates a provider over the obfuscated `file`. Mirrors
    /// `ObfuscatedFileByteProvider(File, FSRL, AccessMode)`.
    ///
    /// # Errors
    /// If the file cannot be opened.
    pub fn new(file: &Path, fsrl: Option<Fsrl>, access_mode: AccessMode) -> io::Result<Self> {
        FileByteProvider::open(file, fsrl, access_mode, true).map(ObfuscatedFileByteProvider)
    }

    /// See [`FileByteProvider::write_bytes`]; the bytes are obfuscated on the way to disk.
    pub fn write_bytes(&mut self, index: u64, buffer: &[u8]) -> io::Result<()> {
        self.0.write_bytes(index, buffer)
    }

    /// See [`FileByteProvider::read_bytes_into`].
    pub fn read_bytes_into(&self, index: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read_bytes_into(index, buffer)
    }
}

impl ByteProvider for ObfuscatedFileByteProvider {
    /// Always `None`: the obfuscated file isn't readable as-is.
    fn get_file(&self) -> Option<PathBuf> {
        None
    }
    fn get_name(&self) -> Option<String> {
        self.0.get_name()
    }
    fn get_absolute_path(&self) -> Option<String> {
        self.0.get_absolute_path()
    }
    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.0.get_fsrl()
    }
    fn length(&self) -> u64 {
        self.0.length()
    }
    fn is_valid_index(&self, index: u64) -> bool {
        self.0.is_valid_index(index)
    }
    fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.0.read_byte(index)
    }
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.0.read_bytes(index, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::obfuscated_output_stream::ObfuscatedOutputStream;

    fn temp_path(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        (dir, p)
    }

    #[test]
    fn reads_across_buffer_boundaries() {
        let (_d, p) = temp_path("f.bin");
        let data: Vec<u8> = (0..(BUFFER_SIZE * 2 + 100)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let bp = FileByteProvider::new(&p, None, AccessMode::Read).unwrap();
        assert_eq!(bp.length(), data.len() as u64);
        let start = BUFFER_SIZE as u64 - 10;
        assert_eq!(bp.read_bytes(start, 30).unwrap(), data[start as usize..start as usize + 30]);
        assert_eq!(bp.read_byte(BUFFER_SIZE as u64 * 2 + 99).unwrap(), data[BUFFER_SIZE * 2 + 99]);
        assert!(bp.read_byte(data.len() as u64).is_err());
        assert!(bp.read_bytes(data.len() as u64 - 1, 2).is_err());
        assert_eq!(bp.get_name().as_deref(), Some("f.bin"));
        assert_eq!(bp.get_file(), Some(p.clone()));
    }

    #[test]
    fn write_mode_extends_file_and_refreshes_cache() {
        let (_d, p) = temp_path("w.bin");
        std::fs::write(&p, [1u8, 2, 3]).unwrap();
        let mut bp = FileByteProvider::new(&p, None, AccessMode::Write).unwrap();
        assert_eq!(bp.read_byte(1).unwrap(), 2); // caches buffer 0
        bp.write_bytes(2, &[9, 9]).unwrap();
        assert_eq!(bp.length(), 4);
        assert_eq!(bp.read_bytes(0, 4).unwrap(), vec![1, 2, 9, 9]);
        bp.close().unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), vec![1, 2, 9, 9]);

        let mut ro = FileByteProvider::new(&p, None, AccessMode::Read).unwrap();
        assert!(ro.write_byte(0, 1).is_err());
    }

    #[test]
    fn obfuscated_provider_round_trips_obfuscated_stream() {
        let (_d, p) = temp_path("o.bin");
        let plain: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        {
            let mut os = ObfuscatedOutputStream::new(std::fs::File::create(&p).unwrap());
            os.write_all(&plain).unwrap();
            os.flush().unwrap();
        }
        assert_ne!(std::fs::read(&p).unwrap(), plain, "on-disk bytes are obfuscated");
        let fsrl = Fsrl::from_string("cache:///abc").unwrap();
        let bp = ObfuscatedFileByteProvider::new(&p, Some(fsrl), AccessMode::Read).unwrap();
        assert_eq!(bp.read_bytes(0, 300).unwrap(), plain);
        assert_eq!(bp.read_byte(129).unwrap(), plain[129]);
        assert!(bp.get_file().is_none());
        assert_eq!(bp.get_name().as_deref(), Some("abc"));
    }
}
