//! Rust port of `ghidra.file.formats.ios.fileset.MachoFileSetExtractor`.
//!
//! # Shape
//!
//! The Java class has no fields and only two static methods, so it ports to a plain module of a
//! `pub const` and free functions rather than a field-less struct: Rust doesn't need a class to
//! hang statics off of (shape rule R7-statics-holder).
//!
//! # Unported dependencies
//!
//! `extract_file_set_entry` bottoms out in
//! [`ExtractedMacho`](crate::file::seam_stubs::ExtractedMacho), whose `pack` degrades to
//! footer-only output until [`MachHeader::get_all_segments`](crate::file::seam_stubs::MachHeader)
//! reports real segments -- see that stub's docs. `extract_segment` needs no unported
//! dependencies: `MachHeader::create` and `SegmentCommand::create` (also added to
//! `crate::file::seam_stubs` alongside this port) are pure byte-layout helpers with no forward
//! references, so it is fully functional today.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::file::seam_stubs::{ByteArrayProvider, ExtractedMacho, MachHeader, SegmentCommand};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::macho::mach_constants::MH_MAGIC_64;
use crate::format::macho::mach_exception::MachException;
use crate::util::task::TaskMonitor;

/// A footer that gets appended to the end of every extracted component so Ghidra can identify
/// them and treat them special when imported.
///
/// Mirrors `FOOTER_V1`.
pub const FOOTER_V1: &[u8] = b"Ghidra Mach-O file set extraction v1";

/// Gets a [`ByteProvider`] that contains a Mach-O file set entry. The Mach-O's header will be
/// altered to account for its segment bytes being packed down.
///
/// `fsrl_path` mirrors the Java signature but is unused: [`ByteArrayProvider`] (this crate's stub
/// for Java's `ByteArrayProvider`) doesn't carry an FSRL identity yet.
///
/// Mirrors `extractFileSetEntry(ByteProvider, long, FSRL, TaskMonitor)`.
pub fn extract_file_set_entry(
    provider: Rc<RefCell<dyn ByteProvider>>,
    provider_offset: i64,
    _fsrl_path: &str,
    monitor: &dyn TaskMonitor,
) -> io::Result<Box<dyn ByteProvider>> {
    let mut header = MachHeader::new(Rc::clone(&provider), provider_offset);
    header.parse().map_err(mach_err)?;

    let mut extracted_macho = ExtractedMacho::new(Rc::clone(&provider), header, FOOTER_V1);
    extracted_macho.pack(monitor)?;
    Ok(Box::new(extracted_macho.get_byte_provider()))
}

/// Gets a [`ByteProvider`] that contains a single segment from a Mach-O file set.
///
/// `fsrl_path` and `monitor` mirror the Java signature but are unused: Java's `extractSegment`
/// never inspects `monitor` either, and [`ByteArrayProvider`] doesn't carry an FSRL identity yet.
///
/// Mirrors `extractSegment(ByteProvider, SegmentCommand, FSRL, TaskMonitor)`.
pub fn extract_segment(
    provider: Rc<RefCell<dyn ByteProvider>>,
    segment: &SegmentCommand,
    _fsrl_path: &str,
    _monitor: &dyn TaskMonitor,
) -> io::Result<Box<dyn ByteProvider>> {
    let magic = MH_MAGIC_64;
    let all_segments_size = SegmentCommand::size(magic).map_err(mach_err)?;

    // Mach-O Header
    let header = MachHeader::create(
        magic,
        0x100000c,
        0x8000_0002u32 as i32,
        6,
        1,
        all_segments_size,
        0x4210_0085u32 as i32,
        0,
    )
    .map_err(mach_err)?;

    // Segment command
    let segment_command_bytes = SegmentCommand::create(
        magic,
        segment.segment_name(),
        segment.vm_address(),
        segment.vm_size(),
        header.len() as i64 + all_segments_size as i64,
        segment.file_size(),
        segment.max_protection(),
        segment.init_protection(),
        segment.flags(),
    )
    .map_err(mach_err)?;

    // Segment data
    let segment_data_bytes =
        provider.borrow_mut().read_bytes(segment.file_offset() as u64, segment.file_size() as usize)?;

    // Combine pieces
    let mut result = Vec::with_capacity(
        header.len() + segment_command_bytes.len() + segment_data_bytes.len() + FOOTER_V1.len(),
    );
    result.extend_from_slice(&header);
    result.extend_from_slice(&segment_command_bytes);
    result.extend_from_slice(&segment_data_bytes);

    // Add footer
    result.extend_from_slice(FOOTER_V1);

    Ok(Box::new(ByteArrayProvider::new(result)))
}

fn mach_err(e: MachException) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryByteProvider {
        bytes: Vec<u8>,
    }

    impl ByteProvider for MemoryByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    fn provider_of(bytes: Vec<u8>) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(MemoryByteProvider { bytes }))
    }

    #[test]
    fn footer_v1_matches_java_constant() {
        assert_eq!(FOOTER_V1, "Ghidra Mach-O file set extraction v1".as_bytes());
    }

    #[test]
    fn extract_file_set_entry_rejects_invalid_magic() {
        let provider = provider_of(vec![0u8; 64]);
        let monitor = crate::util::task::DummyMonitor;
        let err = match extract_file_set_entry(provider, 0, "test.entry", &monitor) {
            Ok(_) => panic!("all-zero bytes are not a valid Mach-O magic"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn extract_file_set_entry_appends_footer_when_no_segments() {
        // MH_MAGIC_64, big-endian on-disk bytes: MachHeader::parse only validates the magic
        // (segment parsing is not ported yet, see module docs), so packing degrades to just the
        // footer.
        let mut bytes: Vec<u8> = vec![0xfe, 0xed, 0xfa, 0xcf];
        bytes.resize(32, 0);
        let provider = provider_of(bytes);
        let monitor = crate::util::task::DummyMonitor;
        let mut result =
            extract_file_set_entry(provider, 0, "test.entry", &monitor).expect("valid magic should pack");
        let len = result.length().unwrap() as usize;
        let extracted = result.read_bytes(0, len).unwrap();
        assert_eq!(extracted, FOOTER_V1);
    }

    #[test]
    fn extract_segment_builds_header_plus_segment_plus_data_plus_footer() {
        let segment_data = vec![0xAAu8; 16];
        let provider = provider_of(segment_data.clone());
        let segment = SegmentCommand::full("__TEXT", 0x1000, 0x1000, 0, 16, 7, 5, 0);
        let monitor = crate::util::task::DummyMonitor;

        let mut result = extract_segment(provider, &segment, "test.segment", &monitor)
            .expect("extract_segment should succeed");
        let len = result.length().unwrap() as usize;
        let bytes = result.read_bytes(0, len).unwrap();

        // Mach-O header (0x20) + segment command (0x48) + 16 bytes of segment data + footer.
        assert_eq!(len, 0x20 + 0x48 + 16 + FOOTER_V1.len());
        assert!(bytes.ends_with(FOOTER_V1));
        // Segment data lands right after the header + segment command, before the footer.
        let data_start = 0x20 + 0x48;
        assert_eq!(&bytes[data_start..data_start + 16], segment_data.as_slice());
        // Mach-O magic at the very start.
        assert_eq!(&bytes[0..4], &MH_MAGIC_64.to_le_bytes());
    }
}
