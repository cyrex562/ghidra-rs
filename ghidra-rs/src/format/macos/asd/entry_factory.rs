//! Port of `ghidra.app.util.bin.format.macos.asd.EntryFactory`.
//!
//! Java's `EntryFactory` is a final class holding a single static method; per
//! `scripts/shape_rules.py` (R7) it becomes this module's free function.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::macos::asd::entry_descriptor::EntryDescriptor;
use crate::format::macos::asd::entry_descriptor_id::ENTRY_RESOURCE_FORK;
use crate::format::macos::rm::resource_header::ResourceHeader;

/// Parses the entry `descriptor` describes, reading from `descriptor.get_offset()`. The reader's
/// position is restored afterwards, whether or not parsing succeeds.
///
/// Returns `Ok(None)` for every entry kind other than a resource fork, which is the only kind
/// Java's `EntryFactory.getEntry` understands (Java returns `null` there, and types the result as
/// `Object`).
///
/// Port of `EntryFactory.getEntry(BinaryReader, EntryDescriptor)`.
pub fn get_entry(
    reader: &mut dyn BinaryReader,
    descriptor: &EntryDescriptor,
) -> io::Result<Option<ResourceHeader>> {
    let old_index = reader.get_pointer_index();
    reader.set_pointer_index(descriptor.get_offset() as i64 as u64);
    let result = if descriptor.get_entry_id() as u32 == ENTRY_RESOURCE_FORK {
        ResourceHeader::new(reader, descriptor.clone()).map(Some)
    } else {
        Ok(None)
    };
    reader.set_pointer_index(old_index);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::asd::entry_descriptor_id::ENTRY_DATA_FORK;
    use crate::format::macos::test_support::{Image, VecReader};

    #[test]
    fn non_resource_fork_yields_none_without_moving_reader() {
        let mut reader = VecReader::new(vec![0; 8]);
        reader.set_pointer_index(3);
        let d = EntryDescriptor::new(ENTRY_DATA_FORK as i32, 0, 8);
        assert!(get_entry(&mut reader, &d).unwrap().is_none());
        assert_eq!(reader.get_pointer_index(), 3);
    }

    #[test]
    fn resource_fork_is_parsed_at_descriptor_offset() {
        let mut img = Image::default();
        img.pad_to(4);
        // Header at 4: map at fork+0x10 = 0x14.
        img.u32(0x80).u32(0x10).u32(0x20).u32(0x1e);
        img.u32(0x80).u32(0x10).u32(0x20).u32(0x1e);
        img.u32(0).u16(0).u16(0).u16(0x1c).u16(0x1e).u16(0xffff);
        let mut reader = VecReader::new(img.0);
        reader.set_pointer_index(1);
        let d = EntryDescriptor::new(ENTRY_RESOURCE_FORK as i32, 4, 0x2e);

        let header = get_entry(&mut reader, &d).unwrap().expect("resource header");
        assert_eq!(reader.get_pointer_index(), 1);
        assert_eq!(header.get_resource_data_offset(), 0x80);
        assert_eq!(header.get_resource_data_length(), 0x20);
        assert_eq!(header.get_map().unwrap().get_map_start_index(), 0x14);
    }

    #[test]
    fn errors_still_restore_reader_position() {
        // Resource fork at 0 but only 4 bytes: the header read fails.
        let mut reader = VecReader::new(vec![0; 4]);
        reader.set_pointer_index(2);
        let d = EntryDescriptor::new(ENTRY_RESOURCE_FORK as i32, 0, 4);
        assert!(get_entry(&mut reader, &d).is_err());
        assert_eq!(reader.get_pointer_index(), 2);
    }
}
