//! Port of `ghidra.framework.store.local.ItemSerializer`.
//!
//! Facilitates the compressing and writing of a data stream to a "packed" file, and the
//! detection of such files. The resulting packed file contains the following meta-data,
//! written ahead of a zip-compressed content stream:
//! - Item name
//! - Content type
//! - File type
//! - Data length

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use thiserror::Error;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::util::big_endian_data_converter::INSTANCE as BIG_ENDIAN;
use crate::util::exception::{CancelledException, IOCancelledException};
use crate::util::task::TaskMonitor;
use crate::util::{DataConverter, MonitoredOutputStream};

/// Offset, in bytes, at which [`MAGIC_NUMBER`] appears within a packed file.
///
/// The header written ahead of the zip content mimics the byte layout produced by Java's
/// `ObjectOutputStream` when `outputItem` writes `MAGIC_NUMBER`/`FORMAT_VERSION`/name/type
/// fields as primitive data: a 4-byte stream header followed by a 2-byte block-data tag and
/// length, landing the magic number's first byte at offset 6. This offset (and the original
/// Java `MAGIC_NUMBER_POS` constant it mirrors) assumes that header block stays under 256
/// bytes, which holds for the item/content-type name lengths used in practice.
const MAGIC_NUMBER_POS: usize = 6;
const MAGIC_NUMBER_SIZE: usize = 8;

/// Magic number written at the start of every packed file's meta-data block.
pub(crate) const MAGIC_NUMBER: i64 = 0x2e30_2126_34e9_2c20;
/// Version of the packed-file meta-data layout produced by [`output_item`].
pub(crate) const FORMAT_VERSION: i32 = 1;
/// Name of the zip entry holding the item's compressed content.
pub(crate) const ZIP_ENTRY_NAME: &str = "FOLDER_ITEM";
/// Buffer size used when copying content into (or out of) a packed file.
pub(crate) const IO_BUFFER_SIZE: usize = 32 * 1024;

/// Java `ObjectOutputStream` stream header: magic followed by version.
const STREAM_MAGIC: u16 = 0xACED;
const STREAM_VERSION: u16 = 0x0005;
/// Java `ObjectOutputStream` block-data tags, used depending on whether the block fits in a
/// single unsigned byte length prefix.
const TC_BLOCKDATA: u8 = 0x77;
const TC_BLOCKDATALONG: u8 = 0x7A;

/// Errors that can occur while writing a packed file via [`output_item`].
///
/// Combines the checked exceptions declared on `ItemSerializer.outputItem`
/// (`CancelledException`, `IOException`).
#[derive(Error, Debug)]
pub enum OutputItemError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Read and compress data from the specified content stream and write to a packed file along
/// with additional meta-data.
///
/// - `item_name`: item name
/// - `content_type`: content type
/// - `file_type`: file type
/// - `length`: content length to be read
/// - `content`: content input stream
/// - `packed_file`: output packed file to be created
/// - `monitor`: task monitor, if progress reporting/cancellation support is desired
///
/// # Errors
///
/// Returns [`OutputItemError::Cancelled`] if the operation is cancelled via `monitor`, or
/// [`OutputItemError::Io`] if an I/O error occurs (including a mismatch between `length` and
/// the number of bytes actually read from `content`). On any error the partially-written
/// `packed_file` is removed, mirroring the Java implementation's cleanup in its `finally` block.
pub fn output_item(
    item_name: &str,
    content_type: Option<&str>,
    file_type: i32,
    length: i64,
    content: &mut dyn Read,
    packed_file: impl AsRef<Path>,
    monitor: Option<&dyn TaskMonitor>,
) -> Result<(), OutputItemError> {
    let packed_file = packed_file.as_ref();
    match write_packed_file(item_name, content_type, file_type, length, content, packed_file, monitor) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(packed_file);
            if is_io_cancelled(&e) {
                Err(OutputItemError::Cancelled(CancelledException::default()))
            } else {
                Err(OutputItemError::Io(e))
            }
        }
    }
}

fn write_packed_file(
    item_name: &str,
    content_type: Option<&str>,
    file_type: i32,
    length: i64,
    content: &mut dyn Read,
    packed_file: &Path,
    monitor: Option<&dyn TaskMonitor>,
) -> io::Result<()> {
    let mut header = Vec::with_capacity(64);
    write_object_stream_header(&mut header, item_name, content_type, file_type, length)?;

    let mut file = File::create(packed_file)?;
    file.write_all(&header)?;

    let mut zip_out = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip_out.start_file(ZIP_ENTRY_NAME, options)?;

    let mut length_written: i64 = 0;
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];

    {
        let mut item_out = match monitor {
            Some(m) => {
                m.initialize(length);
                ItemOut::Monitored(MonitoredOutputStream::new(&mut zip_out, m))
            }
            None => ItemOut::Plain(&mut zip_out),
        };

        loop {
            let cnt = content.read(&mut buffer)?;
            if cnt == 0 {
                break;
            }
            item_out.write_all(&buffer[..cnt])?;
            length_written += cnt as i64;
        }

        if length_written != length {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Did not write all content - written length is {length_written}, expected {length}.\n\tItem: {item_name} in packed file: {}",
                    packed_file.display()
                ),
            ));
        }
        item_out.flush()?;
    }

    zip_out.finish()?;
    Ok(())
}

/// A `Write` target that either writes straight through to `W` or reports progress/checks
/// cancellation via a [`MonitoredOutputStream`] wrapping it, matching `outputItem`'s
/// conditional wrapping of its `ZipOutputStream` when a `TaskMonitor` is supplied.
enum ItemOut<'a, W: Write> {
    Plain(&'a mut W),
    Monitored(MonitoredOutputStream<'a, &'a mut W>),
}

impl<'a, W: Write> Write for ItemOut<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ItemOut::Plain(w) => w.write(buf),
            ItemOut::Monitored(m) => m.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ItemOut::Plain(w) => w.flush(),
            ItemOut::Monitored(m) => m.flush(),
        }
    }
}

/// Returns true if `err` wraps an [`IOCancelledException`], as raised by
/// [`MonitoredOutputStream`] when its monitor has been cancelled.
fn is_io_cancelled(err: &io::Error) -> bool {
    err.get_ref()
        .is_some_and(|e| e.downcast_ref::<IOCancelledException>().is_some())
}

/// Writes the meta-data header (item name, content type, file type, length) in the byte
/// layout Java's `ObjectOutputStream` produces for a sequence of `writeLong`/`writeInt`/
/// `writeUTF` calls followed by a single `flush()` - a 4-byte stream header, a block-data tag
/// and length, then the concatenated primitive/UTF fields.
fn write_object_stream_header(
    buf: &mut Vec<u8>,
    item_name: &str,
    content_type: Option<&str>,
    file_type: i32,
    length: i64,
) -> io::Result<()> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&MAGIC_NUMBER.to_be_bytes());
    payload.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    write_modified_utf8(&mut payload, item_name)?;
    write_modified_utf8(&mut payload, content_type.unwrap_or(""))?;
    payload.extend_from_slice(&file_type.to_be_bytes());
    payload.extend_from_slice(&length.to_be_bytes());

    buf.extend_from_slice(&STREAM_MAGIC.to_be_bytes());
    buf.extend_from_slice(&STREAM_VERSION.to_be_bytes());
    if payload.len() <= 0xFF {
        buf.push(TC_BLOCKDATA);
        buf.push(payload.len() as u8);
    } else {
        buf.push(TC_BLOCKDATALONG);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    }
    buf.extend_from_slice(&payload);
    Ok(())
}

/// Encodes `s` the way Java's `DataOutput.writeUTF` does: a 2-byte big-endian length prefix
/// followed by the string's UTF-16 code units re-encoded as modified UTF-8 (each code unit,
/// including lone surrogates, is encoded independently rather than combining surrogate pairs
/// into 4-byte UTF-8 sequences).
fn write_modified_utf8(buf: &mut Vec<u8>, s: &str) -> io::Result<()> {
    let mut len: usize = 0;
    for unit in s.encode_utf16() {
        len += modified_utf8_unit_len(unit);
    }
    if len > 0xFFFF {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "encoded string too long"));
    }

    buf.extend_from_slice(&(len as u16).to_be_bytes());
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007F => buf.push(unit as u8),
            0 | 0x0080..=0x07FF => {
                buf.push(0xC0 | ((unit >> 6) as u8 & 0x1F));
                buf.push(0x80 | (unit as u8 & 0x3F));
            }
            _ => {
                buf.push(0xE0 | ((unit >> 12) as u8 & 0x0F));
                buf.push(0x80 | ((unit >> 6) as u8 & 0x3F));
                buf.push(0x80 | (unit as u8 & 0x3F));
            }
        }
    }
    Ok(())
}

fn modified_utf8_unit_len(unit: u16) -> usize {
    match unit {
        0x0001..=0x007F => 1,
        0 | 0x0080..=0x07FF => 2,
        _ => 3,
    }
}

/// A simple utility method to determine if the given file is a packed file as created by
/// [`output_item`].
///
/// # Errors
///
/// Returns an error if there is a problem reading the given file.
pub fn is_packed_file(file: impl AsRef<Path>) -> io::Result<bool> {
    let opened = File::open(file.as_ref())?;
    let mut reader = BufReader::new(opened);
    is_packed_file_reader(&mut reader)
}

/// A convenience method for checking if the bytes read from `input` represent a packed file.
///
/// Note: this does not close `input`.
///
/// # Errors
///
/// Returns an error if there is a problem reading from `input`.
pub fn is_packed_file_reader(input: &mut dyn Read) -> io::Result<bool> {
    // Mirrors the original's unchecked `InputStream.skip`/single `read` call: on a short
    // stream, fewer bytes than requested are read and the comparison below simply fails
    // rather than erroring.
    let mut skip_buf = [0u8; MAGIC_NUMBER_POS];
    let _ = input.read(&mut skip_buf)?;
    let mut magic_bytes = [0u8; MAGIC_NUMBER_SIZE];
    let _ = input.read(&mut magic_bytes)?;
    let magic = BIG_ENDIAN.get_long(&magic_bytes);
    Ok(magic == MAGIC_NUMBER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("item_serializer_test_{}_{}_{}", std::process::id(), label, id));
        path
    }

    #[test]
    fn output_item_round_trips_through_is_packed_file() {
        let path = tmp_path("roundtrip");
        let data = b"hello packed world".to_vec();
        let mut content = Cursor::new(data.clone());

        output_item(
            "myItem",
            Some("Program"),
            7,
            data.len() as i64,
            &mut content,
            &path,
            None,
        )
        .unwrap();

        assert!(is_packed_file(&path).unwrap());

        let file = File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut entry = archive.by_name(ZIP_ENTRY_NAME).unwrap();
        let mut out = Vec::new();
        entry.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn output_item_with_none_content_type_round_trips() {
        let path = tmp_path("no_content_type");
        let data = b"abc".to_vec();
        let mut content = Cursor::new(data.clone());

        output_item("item", None, 0, data.len() as i64, &mut content, &path, None).unwrap();
        assert!(is_packed_file(&path).unwrap());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn output_item_with_monitor_initializes_and_completes() {
        let path = tmp_path("monitor");
        let data = vec![0u8; 5000];
        let mut content = Cursor::new(data.clone());
        let monitor = DummyMonitor;

        output_item(
            "item",
            Some("type"),
            1,
            data.len() as i64,
            &mut content,
            &path,
            Some(&monitor),
        )
        .unwrap();

        assert!(is_packed_file(&path).unwrap());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn output_item_length_mismatch_errs_and_removes_file() {
        let path = tmp_path("mismatch");
        let mut content = Cursor::new(b"short".to_vec());

        let result = output_item("item", None, 0, 100, &mut content, &path, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OutputItemError::Io(_)));
        assert!(!path.exists());
    }

    #[test]
    fn is_packed_file_false_for_non_packed_file() {
        let path = tmp_path("not_packed");
        std::fs::write(&path, b"just some random bytes, not a packed file").unwrap();

        assert!(!is_packed_file(&path).unwrap());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn is_packed_file_false_for_short_file() {
        let path = tmp_path("too_short");
        std::fs::write(&path, b"tiny").unwrap();

        assert!(!is_packed_file(&path).unwrap());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn is_packed_file_reader_does_not_consume_more_than_needed() {
        let data = b"hello packed world".to_vec();
        let path = tmp_path("reader");
        let mut content = Cursor::new(data.clone());
        output_item("item", Some("type"), 0, data.len() as i64, &mut content, &path, None).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let mut cursor = Cursor::new(bytes);
        assert!(is_packed_file_reader(&mut cursor).unwrap());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn write_modified_utf8_encodes_length_prefix_and_ascii() {
        let mut buf = Vec::new();
        write_modified_utf8(&mut buf, "hi").unwrap();
        assert_eq!(buf, vec![0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn write_modified_utf8_encodes_non_ascii() {
        let mut buf = Vec::new();
        write_modified_utf8(&mut buf, "\u{0}").unwrap();
        // NUL is encoded as the two-byte sequence 0xC0 0x80 in modified UTF-8.
        assert_eq!(buf, vec![0x00, 0x02, 0xC0, 0x80]);
    }

    #[test]
    fn write_object_stream_header_places_magic_at_documented_offset() {
        let mut buf = Vec::new();
        write_object_stream_header(&mut buf, "name", Some("type"), 3, 42).unwrap();

        assert_eq!(&buf[0..4], &[0xAC, 0xED, 0x00, 0x05]);
        assert_eq!(buf[4], TC_BLOCKDATA);
        let magic_bytes = &buf[MAGIC_NUMBER_POS..MAGIC_NUMBER_POS + MAGIC_NUMBER_SIZE];
        assert_eq!(BIG_ENDIAN.get_long(magic_bytes), MAGIC_NUMBER);
    }
}
