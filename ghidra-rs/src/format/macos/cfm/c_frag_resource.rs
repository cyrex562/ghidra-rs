//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragResource`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::cfm::c_frag_resource_member::CFragResourceMember;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The contents of a `'cfrg'` (code fragment) resource: a header followed by one
/// [`CFragResourceMember`] per code fragment.
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragResource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFragResource {
    reserved_a: i32,
    reserved_b: i32,
    version: i32,
    reserved_c: i32,
    reserved_d: i32,
    reserved_e: i32,
    reserved_f: i32,
    member_count: i32,
    members: Vec<CFragResourceMember>,
}

impl CFragResource {
    /// Reads the 32-byte header and then `memberCount` members, each starting `memberSize` bytes
    /// after the previous one. The reader is left just past the last member's declared size.
    ///
    /// Port of the `CFragResource(BinaryReader)` constructor. The on-disk order of the reserved
    /// words is A, B, version, D, E, F, C, as in Java.
    ///
    /// # Errors
    ///
    /// Read errors, member errors, and [`io::ErrorKind::InvalidData`] "Reserved fields contain
    /// invalid value(s)." when any reserved word is non-zero.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let reserved_a = reader.read_next_int()?;
        let reserved_b = reader.read_next_int()?;
        let version = reader.read_next_int()?;
        let reserved_d = reader.read_next_int()?;
        let reserved_e = reader.read_next_int()?;
        let reserved_f = reader.read_next_int()?;
        let reserved_c = reader.read_next_int()?;
        let member_count = reader.read_next_int()?;

        if [reserved_a, reserved_b, reserved_c, reserved_d, reserved_e, reserved_f]
            .iter()
            .any(|&r| r != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Reserved fields contain invalid value(s).",
            ));
        }

        let mut members = Vec::new();
        for _ in 0..member_count {
            let old_index = reader.get_pointer_index();
            let member = CFragResourceMember::new(reader)?;
            let next = old_index as i64 + i64::from(member.get_member_size());
            reader.set_pointer_index(next as u64);
            members.push(member);
        }

        Ok(Self {
            reserved_a,
            reserved_b,
            version,
            reserved_c,
            reserved_d,
            reserved_e,
            reserved_f,
            member_count,
            members,
        })
    }

    /// Returns the resource format version.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Returns the declared number of members.
    pub fn get_member_count(&self) -> i32 {
        self.member_count
    }

    /// Returns the parsed members.
    pub fn get_members(&self) -> &[CFragResourceMember] {
        &self.members
    }
}

impl StructConverter for CFragResource {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: one DWORD per
    /// `int` field in declaration order (the `_members` list is skipped for its underscore).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("CFragResource", 0);
        for field in [
            "reservedA",
            "reservedB",
            "version",
            "reservedC",
            "reservedD",
            "reservedE",
            "reservedF",
            "memberCount",
        ] {
            s.add_with_name(PrimitiveDt::DWORD.boxed(), Some(field.to_string()), None)?;
        }
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::{cfrag_member, Image, VecReader};

    fn resource(members: &[(&str, u16)]) -> Vec<u8> {
        let mut img = Image::default();
        img.u32(0).u32(0).u32(3).u32(0).u32(0).u32(0).u32(0).u32(members.len() as u32);
        for (name, size) in members {
            let start = img.0.len();
            cfrag_member(&mut img, b"pwpc", 0, name, *size);
            img.pad_to(start + usize::from(*size));
        }
        img.0
    }

    #[test]
    fn members_are_stepped_by_their_declared_size() {
        let bytes = resource(&[("libA", 0x40), ("libB", 0x38)]);
        let len = bytes.len() as u64;
        let mut reader = VecReader::new(bytes);
        let r = CFragResource::new(&mut reader).unwrap();
        assert_eq!(r.get_version(), 3);
        assert_eq!(r.get_member_count(), 2);
        let names: Vec<_> = r.get_members().iter().map(|m| m.get_name()).collect();
        assert_eq!(names, ["libA", "libB"]);
        assert_eq!(reader.get_pointer_index(), len);
        assert_eq!(len, 32 + 0x40 + 0x38);
    }

    #[test]
    fn non_zero_reserved_word_is_rejected() {
        let mut bytes = resource(&[]);
        bytes[27] = 1; // reservedC, the seventh word
        let err = CFragResource::new(&mut VecReader::new(bytes)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn to_data_type_is_eight_dwords() {
        let r = CFragResource::new(&mut VecReader::new(resource(&[]))).unwrap();
        let dt = r.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragResource");
        assert_eq!(dt.get_length(), 32);
    }
}
