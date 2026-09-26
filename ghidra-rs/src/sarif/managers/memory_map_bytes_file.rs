//! Port of `sarif.managers.MemoryMapBytesFile`.
//!
//! Streams the contents of program memory address ranges out to a sidecar
//! `<fileName>.bytes` file, tracking the running byte offset of each write so
//! callers can record where a given range landed in the file.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::Memory;

/// Size, in bytes, of the buffer used to stream memory into the bytes file.
const BUFSIZE: usize = 32 * 1024;

/// Writes program memory contents to a `<fileName>.bytes` file on disk.
///
/// Corresponds to `sarif.managers.MemoryMapBytesFile`.
pub struct MemoryMapBytesFile<'a> {
    os: BufWriter<File>,
    file_name: String,
    bytes_written: i32,
    memory: &'a dyn Memory,
}

impl<'a> MemoryMapBytesFile<'a> {
    /// Creates the `<fileName>.bytes` file (overwriting it if it already
    /// exists) and prepares to stream `memory` contents into it.
    pub fn new(memory: &'a dyn Memory, file_name: &str) -> io::Result<Self> {
        let path_string = format!("{file_name}.bytes");
        let path = Path::new(&path_string);
        let base_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        let file = File::create(path)?;
        Ok(Self {
            os: BufWriter::new(file),
            file_name: base_name,
            bytes_written: 0,
            memory,
        })
    }

    /// Flushes any buffered writes to disk.
    pub fn close(&mut self) -> io::Result<()> {
        self.os.flush()
    }

    /// Returns the base name (no directory components) of the bytes file.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the number of bytes written to the file so far.
    pub fn offset(&self) -> i32 {
        self.bytes_written
    }

    /// Streams the bytes covered by `range` from memory into the file.
    pub fn write_bytes(&mut self, range: &AddressRange) -> io::Result<()> {
        let mut size = range.length();
        let mut buf = vec![0u8; size.min(BUFSIZE as u64) as usize];
        let mut addr: Address = range.min_address().clone();
        let mut n: i64 = 0;
        while size > 0 {
            addr = addr
                .add_no_wrap(n)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let read = self.memory.get_bytes(&addr, &mut buf);
            self.os.write_all(&buf[..read])?;
            self.bytes_written += read as i32;
            size -= read as u64;
            n = read as i64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_base(label: &str) -> String {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "memory_map_bytes_file_test_{}_{}_{}",
            std::process::id(),
            label,
            id
        ));
        path.to_string_lossy().into_owned()
    }

    struct FakeMemory {
        base: Address,
        data: Vec<u8>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.base);
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.base) as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only fake"))
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn new_appends_bytes_extension_and_strips_directory() {
        let memory = FakeMemory { base: addr(0), data: vec![] };
        let base = tmp_base("filename");

        let file = MemoryMapBytesFile::new(&memory, &base).unwrap();

        assert_eq!(file.file_name(), format!("{}.bytes", Path::new(&base).file_name().unwrap().to_string_lossy()));
        assert_eq!(file.offset(), 0);

        std::fs::remove_file(format!("{base}.bytes")).unwrap();
    }

    #[test]
    fn new_overwrites_existing_file() {
        let memory = FakeMemory { base: addr(0), data: vec![] };
        let base = tmp_base("overwrite");
        std::fs::write(format!("{base}.bytes"), b"stale contents").unwrap();

        let mut file = MemoryMapBytesFile::new(&memory, &base).unwrap();
        file.close().unwrap();

        let contents = std::fs::read(format!("{base}.bytes")).unwrap();
        assert!(contents.is_empty());

        std::fs::remove_file(format!("{base}.bytes")).unwrap();
    }

    #[test]
    fn write_bytes_streams_range_contents_and_tracks_offset() {
        let data: Vec<u8> = (0..10u8).collect();
        let memory = FakeMemory { base: addr(0x1000), data: data.clone() };
        let base = tmp_base("write");
        let mut file = MemoryMapBytesFile::new(&memory, &base).unwrap();

        let range = AddressRange::new(addr(0x1000), addr(0x1009));
        file.write_bytes(&range).unwrap();
        file.close().unwrap();

        assert_eq!(file.offset(), 10);
        let contents = std::fs::read(format!("{base}.bytes")).unwrap();
        assert_eq!(contents, data);

        std::fs::remove_file(format!("{base}.bytes")).unwrap();
    }

    #[test]
    fn write_bytes_accumulates_across_multiple_calls() {
        let data: Vec<u8> = (0..6u8).collect();
        let memory = FakeMemory { base: addr(0x2000), data: data.clone() };
        let base = tmp_base("multi");
        let mut file = MemoryMapBytesFile::new(&memory, &base).unwrap();

        let first = AddressRange::new(addr(0x2000), addr(0x2002));
        let second = AddressRange::new(addr(0x2003), addr(0x2005));
        file.write_bytes(&first).unwrap();
        file.write_bytes(&second).unwrap();
        file.close().unwrap();

        assert_eq!(file.offset(), 6);
        let contents = std::fs::read(format!("{base}.bytes")).unwrap();
        assert_eq!(contents, data);

        std::fs::remove_file(format!("{base}.bytes")).unwrap();
    }

    #[test]
    fn write_bytes_chunks_ranges_larger_than_bufsize() {
        let data = vec![7u8; BUFSIZE + 100];
        let memory = FakeMemory { base: addr(0x3000), data: data.clone() };
        let base = tmp_base("chunked");
        let mut file = MemoryMapBytesFile::new(&memory, &base).unwrap();

        let range = AddressRange::from_start_len(addr(0x3000), data.len() as u64).unwrap();
        file.write_bytes(&range).unwrap();
        file.close().unwrap();

        assert_eq!(file.offset() as usize, data.len());
        let contents = std::fs::read(format!("{base}.bytes")).unwrap();
        assert_eq!(contents, data);

        std::fs::remove_file(format!("{base}.bytes")).unwrap();
    }
}
