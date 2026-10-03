//! Port of `ghidra.framework.store.local.ItemDeserializer`.
//!
//! Facilitates the reading of a compressed data stream contained within a "packed" file, as
//! written by [`output_item`](crate::framework::store::local::item_serializer::output_item). A
//! packed file contains a small meta-data header (item name, content type, file type, data
//! length) ahead of a zip-compressed content stream; that meta-data becomes available immediately
//! after construction, and [`ItemDeserializer::save_item`] extracts the compressed content.

use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use crate::framework::store::local::item_serializer::{
    FORMAT_VERSION, IO_BUFFER_SIZE, MAGIC_NUMBER, ZIP_ENTRY_NAME,
};
use crate::generic::jar::ResourceFile;
use crate::util::exception::IOCancelledException;
use crate::util::task::TaskMonitor;
use crate::util::MonitoredInputStream;

/// Java `ObjectOutputStream`/`ObjectInputStream` stream header: magic followed by version. Must
/// match the constants of the same name in
/// [`item_serializer`](crate::framework::store::local::item_serializer).
const STREAM_MAGIC: u16 = 0xACED;
const STREAM_VERSION: u16 = 0x0005;
const TC_BLOCKDATA: u8 = 0x77;
const TC_BLOCKDATALONG: u8 = 0x7A;

/// Facilitates the reading of a compressed data stream contained within a "packed" file.
///
/// Mirrors `ghidra.framework.store.local.ItemDeserializer`.
pub struct ItemDeserializer {
    reader: Option<BufReader<Box<dyn Read>>>,
    item_name: String,
    content_type: Option<String>,
    file_type: i32,
    length: i64,
    saved: bool,
}

impl ItemDeserializer {
    /// Constructor. Mirrors `ItemDeserializer(File packedFile)`, which delegates to the
    /// `ResourceFile` constructor below.
    ///
    /// # Errors
    /// Returns an `io::Error` if the file could not be opened, or its header could not be parsed
    /// (not a packed file, wrong format version, or corrupt/truncated header).
    pub fn new(packed_file: impl AsRef<Path>) -> io::Result<Self> {
        Self::from_resource_file(&ResourceFile::new(packed_file.as_ref().to_path_buf()))
    }

    /// Constructor. Mirrors `ItemDeserializer(ResourceFile packedFile)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if the file could not be opened, or its header could not be parsed
    /// (not a packed file, wrong format version, or corrupt/truncated header).
    pub fn from_resource_file(packed_file: &ResourceFile) -> io::Result<Self> {
        let mut reader = BufReader::new(packed_file.get_input_stream()?);
        let (item_name, content_type, file_type, length) = read_header(&mut reader)?;
        Ok(Self {
            reader: Some(reader),
            item_name,
            content_type,
            file_type,
            length,
            saved: false,
        })
    }

    /// Close the packed-file input stream and free resources. Safe to call more than once.
    pub fn dispose(&mut self) {
        self.reader = None;
    }

    /// Returns the packed item name.
    pub fn get_item_name(&self) -> &str {
        &self.item_name
    }

    /// Returns the packed content type.
    pub fn get_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Returns the packed file type.
    pub fn get_file_type(&self) -> i32 {
        self.file_type
    }

    /// Returns the unpacked data length.
    pub fn get_length(&self) -> i64 {
        self.length
    }

    /// Save the item to the specified output stream. This method may only be invoked once.
    ///
    /// # Errors
    /// Returns an `io::Error` if this has already been called, the file has already been
    /// [`dispose`](Self::dispose)d, the zip content entry is missing/misnamed, `monitor` reports
    /// cancellation (surfaced as an `io::Error` wrapping [`IOCancelledException`], matching
    /// [`crate::util::MonitoredInputStream`]'s own convention), or another IO error occurs.
    pub fn save_item(&mut self, out: &mut dyn Write, monitor: Option<&dyn TaskMonitor>) -> io::Result<()> {
        if self.saved {
            return Err(io::Error::new(io::ErrorKind::Other, "Already saved"));
        }
        self.saved = true;

        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "stream already disposed"))?;

        let mut entry = zip::read::read_zipfile_from_stream(reader)?
            .filter(|e| e.name() == ZIP_ENTRY_NAME)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Data error"))?;

        // Cap output at `length` bytes, mirroring the Java loop's explicit length-tracking (which
        // stops once `len` reaches zero, regardless of how much more data the zip entry stream
        // might otherwise yield).
        let capped: Box<dyn Read> = Box::new((&mut entry).take(self.length as u64));
        let mut source: Box<dyn Read> = match monitor {
            Some(m) => {
                m.initialize(self.length);
                Box::new(MonitoredInputStream::new(capped, m))
            }
            None => capped,
        };

        let mut buffer = vec![0u8; IO_BUFFER_SIZE];
        loop {
            let n = source.read(&mut buffer).map_err(|e| {
                if is_io_cancelled(&e) {
                    io::Error::new(io::ErrorKind::Other, IOCancelledException::new())
                } else {
                    e
                }
            })?;
            if n == 0 {
                break;
            }
            out.write_all(&buffer[..n])?;
        }
        Ok(())
    }
}

impl Drop for ItemDeserializer {
    /// Mirrors the Java class's `finalize()` safety net, which calls `dispose()`.
    fn drop(&mut self) {
        self.dispose();
    }
}

fn is_io_cancelled(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|e| e.downcast_ref::<IOCancelledException>().is_some())
}

/// Reads the meta-data header written by
/// [`output_item`](crate::framework::store::local::item_serializer::output_item), returning
/// `(item_name, content_type, file_type, length)`.
fn read_header(r: &mut impl Read) -> io::Result<(String, Option<String>, i32, i64)> {
    let bad_data = || io::Error::new(io::ErrorKind::InvalidData, "Invalid data");

    let mut u16buf = [0u8; 2];
    r.read_exact(&mut u16buf)?;
    if u16::from_be_bytes(u16buf) != STREAM_MAGIC {
        return Err(bad_data());
    }
    r.read_exact(&mut u16buf)?;
    if u16::from_be_bytes(u16buf) != STREAM_VERSION {
        return Err(bad_data());
    }

    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    match tag[0] {
        TC_BLOCKDATA => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)?;
        }
        TC_BLOCKDATALONG => {
            let mut len = [0u8; 4];
            r.read_exact(&mut len)?;
        }
        _ => return Err(bad_data()),
    }

    let mut i64buf = [0u8; 8];
    r.read_exact(&mut i64buf)?;
    if i64::from_be_bytes(i64buf) != MAGIC_NUMBER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid data"));
    }

    let mut i32buf = [0u8; 4];
    r.read_exact(&mut i32buf)?;
    if i32::from_be_bytes(i32buf) != FORMAT_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported data format"));
    }

    let item_name = read_modified_utf8(r)?;
    let content_type_raw = read_modified_utf8(r)?;
    let content_type = if content_type_raw.is_empty() { None } else { Some(content_type_raw) };

    r.read_exact(&mut i32buf)?;
    let file_type = i32::from_be_bytes(i32buf);

    r.read_exact(&mut i64buf)?;
    let length = i64::from_be_bytes(i64buf);

    Ok((item_name, content_type, file_type, length))
}

/// Decodes a string written the way Java's `DataOutput.writeUTF` encodes one: a 2-byte
/// big-endian length prefix followed by "modified UTF-8" bytes. Pairs with `write_modified_utf8`
/// in [`item_serializer`](crate::framework::store::local::item_serializer).
fn read_modified_utf8(r: &mut impl Read) -> io::Result<String> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "Invalid item data");

    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;

    let mut units: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let b0 = buf[i];
        if b0 & 0x80 == 0 {
            units.push(b0 as u16);
            i += 1;
        } else if b0 & 0xE0 == 0xC0 {
            let b1 = *buf.get(i + 1).ok_or_else(bad)?;
            units.push((((b0 & 0x1F) as u16) << 6) | ((b1 & 0x3F) as u16));
            i += 2;
        } else if b0 & 0xF0 == 0xE0 {
            let b1 = *buf.get(i + 1).ok_or_else(bad)?;
            let b2 = *buf.get(i + 2).ok_or_else(bad)?;
            units.push((((b0 & 0x0F) as u16) << 12) | (((b1 & 0x3F) as u16) << 6) | ((b2 & 0x3F) as u16));
            i += 3;
        } else {
            return Err(bad());
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::store::local::item_serializer::output_item;
    use crate::util::task::DummyMonitor;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("item_deserializer_test_{}_{}_{}", std::process::id(), label, id));
        path
    }

    fn write_packed(path: &Path, name: &str, content_type: Option<&str>, file_type: i32, data: &[u8]) {
        let mut content = Cursor::new(data.to_vec());
        output_item(name, content_type, file_type, data.len() as i64, &mut content, path, None).unwrap();
    }

    #[test]
    fn round_trips_metadata_and_content() {
        let path = tmp_path("roundtrip");
        write_packed(&path, "myItem", Some("Program"), 7, b"hello packed world");

        let mut d = ItemDeserializer::new(&path).unwrap();
        assert_eq!(d.get_item_name(), "myItem");
        assert_eq!(d.get_content_type(), Some("Program"));
        assert_eq!(d.get_file_type(), 7);
        assert_eq!(d.get_length(), 18);

        let mut out = Vec::new();
        d.save_item(&mut out, None).unwrap();
        assert_eq!(out, b"hello packed world");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn none_content_type_round_trips_as_none() {
        let path = tmp_path("no_content_type");
        write_packed(&path, "item", None, 0, b"abc");

        let d = ItemDeserializer::new(&path).unwrap();
        assert_eq!(d.get_content_type(), None);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn save_item_with_monitor_reports_progress_and_completes() {
        let path = tmp_path("monitor");
        let data = vec![7u8; 5000];
        write_packed(&path, "item", Some("type"), 1, &data);

        let mut d = ItemDeserializer::new(&path).unwrap();
        let monitor = DummyMonitor;
        let mut out = Vec::new();
        d.save_item(&mut out, Some(&monitor)).unwrap();
        assert_eq!(out, data);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn save_item_twice_fails() {
        let path = tmp_path("twice");
        write_packed(&path, "item", None, 0, b"data");

        let mut d = ItemDeserializer::new(&path).unwrap();
        let mut out = Vec::new();
        d.save_item(&mut out, None).unwrap();
        let err = d.save_item(&mut out, None).err().unwrap();
        assert!(err.to_string().contains("Already saved"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn non_packed_file_fails_to_construct() {
        let path = tmp_path("not_packed");
        std::fs::write(&path, b"just some random bytes, not a packed file").unwrap();

        let err = ItemDeserializer::new(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dispose_is_idempotent_and_prevents_further_use() {
        let path = tmp_path("dispose");
        write_packed(&path, "item", None, 0, b"data");

        let mut d = ItemDeserializer::new(&path).unwrap();
        d.dispose();
        d.dispose();

        let mut out = Vec::new();
        let err = d.save_item(&mut out, None).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn length_caps_output_even_if_more_data_is_available() {
        // Directly construct a packed file whose declared length is shorter than the zip entry's
        // actual content, then confirm `save_item` only emits `length` bytes -- mirroring the
        // Java loop's explicit `len`-tracking rather than reading until EOF.
        let path = tmp_path("length_cap");
        let full_data = b"0123456789";
        let declared_len = 4i64;
        let mut content = Cursor::new(full_data.to_vec());
        output_item("item", None, 0, full_data.len() as i64, &mut content, &path, None).unwrap();

        // Patch the header's declared length field in place. This is only possible because we
        // know the exact header layout produced by `output_item`/`read_header`.
        let mut bytes = std::fs::read(&path).unwrap();
        // Reconstruct where the length field lives by re-parsing the header from a cursor.
        let mut cursor = Cursor::new(bytes.clone());
        read_header(&mut cursor).unwrap();
        let length_field_start = cursor.position() as usize - 8;
        bytes[length_field_start..length_field_start + 8].copy_from_slice(&declared_len.to_be_bytes());
        std::fs::write(&path, &bytes).unwrap();

        let mut d = ItemDeserializer::new(&path).unwrap();
        assert_eq!(d.get_length(), declared_len);
        let mut out = Vec::new();
        d.save_item(&mut out, None).unwrap();
        assert_eq!(out, &full_data[..4]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn from_resource_file_matches_path_constructor() {
        let path = tmp_path("resource_file");
        write_packed(&path, "item", Some("t"), 2, b"xyz");

        let rf = ResourceFile::new(path.clone());
        let d = ItemDeserializer::from_resource_file(&rf).unwrap();
        assert_eq!(d.get_item_name(), "item");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_file_fails_to_open() {
        let path = tmp_path("missing");
        let err = ItemDeserializer::new(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}

