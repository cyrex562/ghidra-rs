//! Port of `ghidra.file.formats.ios.fileset.MachoFileSetExtractor`.
//!
//! Extracts the components of a Mach-O file set (a kernel collection). The Java class holds only
//! a static constant and two static methods, so per the shape rules it is a plain module.

use std::rc::Rc;

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::file::formats::ios::extracted_macho::{ExtractError, ExtractedMacho};
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::mach_constants::MH_MAGIC_64;
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::util::task::TaskMonitor;

/// A footer that gets appended to the end of every extracted component so Ghidra can identify
/// them and treat them special when imported. Java: `FOOTER_V1`.
pub const FOOTER_V1: &[u8] = b"Ghidra Mach-O file set extraction v1";

/// Why an extraction failed (Java: `IOException`, `MachException`, `CancelledException`).
#[derive(Debug, thiserror::Error)]
pub enum FileSetExtractError {
    #[error(transparent)]
    Extract(#[from] ExtractError),
    #[error(transparent)]
    Mach(#[from] MachException),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Java `extractFileSetEntry(ByteProvider, long, FSRL, TaskMonitor)`: the file set entry whose
/// Mach-O header is at `provider_offset`, with its segments packed down and its header altered
/// to match.
pub fn extract_file_set_entry(
    provider: &Rc<dyn ByteProvider>,
    provider_offset: i64,
    fsrl: Option<Fsrl>,
    monitor: &dyn TaskMonitor,
) -> Result<ByteArrayProvider, FileSetExtractError> {
    let mut header =
        MachHeader::with_start_index_relative(Rc::clone(provider), provider_offset as u64, false)?;
    header.parse()?;
    let mut extracted = ExtractedMacho::new(Rc::clone(provider), provider_offset, header, FOOTER_V1, monitor);
    extracted.pack()?;
    Ok(extracted.get_byte_provider(fsrl))
}

/// Java `extractSegment(ByteProvider, SegmentCommand, FSRL, TaskMonitor)`: wraps a single
/// segment in a minimal 64-bit Mach-O (one `LC_SEGMENT_64`, no sections).
pub fn extract_segment(
    provider: &dyn ByteProvider,
    segment: &SegmentCommand,
    fsrl: Option<Fsrl>,
    _monitor: &dyn TaskMonitor,
) -> Result<ByteArrayProvider, FileSetExtractError> {
    let magic = MH_MAGIC_64;
    let all_segments_size = SegmentCommand::size(magic)?;

    // Mach-O Header
    let header = MachHeader::create(
        magic,
        0x100000c,
        0x80000002u32 as i32,
        6,
        1,
        all_segments_size,
        0x42100085,
        0,
    )?;

    // Segment command
    let segment_command_bytes = SegmentCommand::create(
        magic,
        segment.get_segment_name(),
        segment.get_vm_address(),
        segment.get_vm_size(),
        (header.len() as i32 + all_segments_size) as i64,
        segment.get_file_size(),
        segment.get_max_protection(),
        segment.get_init_protection(),
        segment.get_flags(),
    )?;

    // Segment data
    let segment_data_bytes =
        provider.read_bytes(segment.get_file_offset() as u64, segment.get_file_size() as u64)?;

    // Combine pieces, then add the footer.
    let mut result = Vec::with_capacity(
        header.len() + all_segments_size as usize + segment_data_bytes.len() + FOOTER_V1.len(),
    );
    result.extend_from_slice(&header);
    result.extend_from_slice(&segment_command_bytes);
    result.extend_from_slice(&segment_data_bytes);
    result.extend_from_slice(FOOTER_V1);
    Ok(ByteArrayProvider::with_fsrl(result, fsrl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::formats::ios::extracted_macho::test_support::write_macho;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::util::task::DummyMonitor;

    #[test]
    fn extract_file_set_entry_packs_entry_at_offset() {
        let mut b = Bytes::new(true);
        write_macho(&mut b, 0x1000, 0xffff_fe00_0000_0000, 0x3000, "_kmod_start");
        let p = provider(b.buf);
        let out = extract_file_set_entry(&p, 0x1000, None, &DummyMonitor).unwrap();
        let bytes = out.read_bytes(0, out.length()).unwrap();
        assert!(bytes.ends_with(FOOTER_V1));
        let mut h = MachHeader::new(provider(bytes)).unwrap();
        h.parse().unwrap();
        assert_eq!(h.get_segment("__TEXT").unwrap().get_file_offset(), 0);
        assert_eq!(h.get_segment("__LINKEDIT").unwrap().get_file_offset(), 0x1000);
    }

    #[test]
    fn extract_file_set_entry_rejects_non_macho() {
        let p = provider(vec![0u8; 0x100]);
        assert!(matches!(
            extract_file_set_entry(&p, 0, None, &DummyMonitor),
            Err(FileSetExtractError::Mach(_))
        ));
    }

    #[test]
    fn extract_segment_wraps_one_segment() {
        let mut b = Bytes::new(true);
        write_macho(&mut b, 0, 0x4000, 0x2000, "_x");
        let bytes = b.buf;
        let p = provider(bytes.clone());
        let mut h = MachHeader::new(Rc::clone(&p)).unwrap();
        h.parse().unwrap();
        let text = h.get_segment("__TEXT").unwrap();
        let out = extract_segment(p.as_ref(), text, None, &DummyMonitor).unwrap();
        let out_bytes = out.read_bytes(0, out.length()).unwrap();
        assert_eq!(out_bytes.len(), 32 + 72 + 0x1000 + FOOTER_V1.len());
        assert_eq!(&out_bytes[32 + 72..32 + 72 + 0x1000], &bytes[..0x1000]);

        let mut wrapped = MachHeader::new(provider(out_bytes)).unwrap();
        assert_eq!(wrapped.get_cpu_type(), 0x100000c);
        assert_eq!(wrapped.get_file_type(), 6);
        wrapped.parse().unwrap();
        let seg = wrapped.get_segment("__TEXT").unwrap();
        assert_eq!(seg.get_vm_address(), 0x4000);
        assert_eq!(seg.get_file_offset(), 32 + 72);
        assert_eq!(seg.get_file_size(), 0x1000);
    }
}
