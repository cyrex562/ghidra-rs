//! Port of `ghidra.app.util.bin.format.macos.rm.ResourceTypeFactory`.
//!
//! Java's `ResourceTypeFactory` is a final class holding a single static method; per
//! `scripts/shape_rules.py` (R7) it becomes this module's free function.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::macos::asd::entry::Entry;
use crate::format::macos::cfm::c_frag_resource::CFragResource;
use crate::format::macos::rm::resource_header::ResourceHeader;
use crate::format::macos::rm::resource_type::ResourceType;
use crate::format::macos::rm::resource_types::TYPE_CFRG;

/// Parses the resource object for `resource_type`, if its type is one this crate understands.
/// The reader's position is restored afterwards, whether or not parsing succeeds.
///
/// Only `'cfrg'` is understood: its first resource's data (past the 4-byte length prefix) is read
/// as a [`CFragResource`]. Every other type yields `Ok(None)` (Java returns `null`, and types the
/// result as `Object`).
///
/// Port of `ResourceTypeFactory.getResourceObject(BinaryReader, ResourceHeader, ResourceType)`.
///
/// # Errors
///
/// Besides read errors, a `'cfrg'` type with an empty reference list is reported as
/// [`io::ErrorKind::InvalidData`] (Java's `List.get(0)` throws `IndexOutOfBoundsException`).
pub fn get_resource_object(
    reader: &mut dyn BinaryReader,
    header: &ResourceHeader,
    resource_type: &ResourceType,
) -> io::Result<Option<CFragResource>> {
    if resource_type.get_type() as u32 != TYPE_CFRG {
        return Ok(None);
    }
    let reference_list_entry = resource_type.get_reference_list().first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "'cfrg' resource type has no resources")
    })?;

    let old_index = reader.get_pointer_index();
    // Java sums these as `int`s before widening to the reader's `long` index.
    let data_start = header
        .get_resource_data_offset()
        .wrapping_add(header.get_entry_descriptor().get_offset())
        .wrapping_add(reference_list_entry.get_data_offset())
        .wrapping_add(4);
    reader.set_pointer_index(i64::from(data_start) as u64);
    let result = CFragResource::new(reader).map(Some);
    reader.set_pointer_index(old_index);
    result
}

#[cfg(test)]
mod tests {
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::macos::asd::entry_descriptor::EntryDescriptor;
    use crate::format::macos::asd::entry_descriptor_id::ENTRY_RESOURCE_FORK;
    use crate::format::macos::cfm::c_frag_usage::CFragUsage;
    use crate::format::macos::rm::resource_header::ResourceHeader;
    use crate::format::macos::test_support::{cfrg_fork_fixture, VecReader};

    #[test]
    fn cfrg_type_parses_the_fragment_resource() {
        // The fork sits at file offset 8, so the data position also adds the descriptor offset.
        let mut reader = VecReader::new(cfrg_fork_fixture(8));
        reader.set_pointer_index(8);
        let header =
            ResourceHeader::new(&mut reader, EntryDescriptor::new(ENTRY_RESOURCE_FORK as i32, 8, 0))
                .unwrap();

        let types = header.get_map().unwrap().get_resource_type_list();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].get_type_as_string(), "cfrg");
        let cfrg = types[0].get_resource_object().expect("cfrg resource");
        assert_eq!(cfrg.get_version(), 1);
        assert_eq!(cfrg.get_member_count(), 1);
        let member = &cfrg.get_members()[0];
        assert_eq!(member.get_architecture(), "pwpc");
        assert_eq!(member.get_usage(), CFragUsage::KApplicationCFrag);
        assert_eq!(member.get_name(), "App");
    }

    #[test]
    fn cfrg_type_without_resources_is_an_error() {
        let mut bytes = cfrg_fork_fixture(0);
        // numberOfResources - 1 = -1: an empty reference list.
        let type_entry = 0x90 + 4;
        bytes[type_entry..type_entry + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        let mut reader = VecReader::new(bytes);
        let err = ResourceHeader::new(&mut reader, EntryDescriptor::new(2, 0, 0)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
