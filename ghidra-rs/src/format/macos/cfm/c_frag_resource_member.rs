//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragResourceMember`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::cfm::c_frag_locator_kind::CFragLocatorKind;
use crate::format::macos::cfm::c_frag_usage::CFragUsage;
use crate::format::macos::cfm::c_frag_usage1_union::CFragUsage1Union;
use crate::format::macos::cfm::c_frag_usage2_union::CFragUsage2Union;
use crate::format::macos::cfm::c_frag_where1_union::CFragWhere1Union;
use crate::format::macos::cfm::c_frag_where2_union::CFragWhere2Union;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// Port of `CFragResourceMember.kNullCFragVersion`.
pub const K_NULL_CFRAG_VERSION: i32 = 0;
/// Port of `CFragResourceMember.kWildcardCFragVersion`.
pub const K_WILDCARD_CFRAG_VERSION: i32 = -1;

/// One member of a `'cfrg'` resource: describes a single code fragment (its architecture,
/// versions, usage, where its container lives, and its name).
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragResourceMember`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFragResourceMember {
    architecture: String,
    /// Must be zero.
    reserved_a: i16,
    /// Must be zero.
    reserved_b: i8,
    update_level: i8,
    current_version: i32,
    old_def_version: i32,
    u_usage1: CFragUsage1Union,
    u_usage2: CFragUsage2Union,
    usage: CFragUsage,
    where_: CFragLocatorKind,
    offset: i32,
    length: i32,
    u_where1: CFragWhere1Union,
    u_where2: CFragWhere2Union,
    extension_count: i16,
    /// Total size in bytes.
    member_size: i16,
    name: String,
}

impl CFragResourceMember {
    /// Reads one member at the reader's current position.
    ///
    /// Port of the `CFragResourceMember(BinaryReader)` constructor.
    ///
    /// # Errors
    ///
    /// Read errors, an out-of-range usage or locator byte (Java indexes `values()` and throws
    /// `ArrayIndexOutOfBoundsException`; see [`CFragUsage::get`]), and
    /// [`io::ErrorKind::InvalidData`] "Reserved fields contain invalid value(s)." when either
    /// reserved field is non-zero (checked after the whole member is read, as in Java).
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let architecture = reader.read_next_ascii_string_fixed(4)?;
        let reserved_a = reader.read_next_short()?;
        let reserved_b = reader.read_next_byte()? as i8;
        let update_level = reader.read_next_byte()? as i8;
        let current_version = reader.read_next_int()?;
        let old_def_version = reader.read_next_int()?;
        let u_usage1 = CFragUsage1Union::new(reader)?;
        let u_usage2 = CFragUsage2Union::new(reader)?;
        let usage = CFragUsage::get(reader)?;
        let where_ = CFragLocatorKind::get(reader)?;
        let offset = reader.read_next_int()?;
        let length = reader.read_next_int()?;
        let u_where1 = CFragWhere1Union::new(reader)?;
        let u_where2 = CFragWhere2Union::new(reader)?;
        let extension_count = reader.read_next_short()?;
        let member_size = reader.read_next_short()?;

        let name_length = usize::from(reader.read_next_byte()?);
        let name = reader.read_next_ascii_string_fixed(name_length)?;

        if reserved_a != 0 || reserved_b != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Reserved fields contain invalid value(s).",
            ));
        }

        Ok(Self {
            architecture,
            reserved_a,
            reserved_b,
            update_level,
            current_version,
            old_def_version,
            u_usage1,
            u_usage2,
            usage,
            where_,
            offset,
            length,
            u_where1,
            u_where2,
            extension_count,
            member_size,
            name,
        })
    }

    /// Returns the four-character architecture code (e.g. `"pwpc"`).
    pub fn get_architecture(&self) -> &str {
        &self.architecture
    }

    /// Returns the update level.
    pub fn get_update_level(&self) -> i8 {
        self.update_level
    }

    /// Returns the current version.
    pub fn get_current_version(&self) -> i32 {
        self.current_version
    }

    /// Returns the oldest definition version this fragment is compatible with.
    pub fn get_old_def_version(&self) -> i32 {
        self.old_def_version
    }

    /// Returns the first usage-dependent union.
    pub fn get_u_usage1(&self) -> &CFragUsage1Union {
        &self.u_usage1
    }

    /// Returns the second usage-dependent union.
    pub fn get_u_usage2(&self) -> &CFragUsage2Union {
        &self.u_usage2
    }

    /// Returns the fragment usage.
    pub fn get_usage(&self) -> CFragUsage {
        self.usage
    }

    /// Returns where the fragment's container is located.
    ///
    /// Port of `getWhere()`.
    pub fn get_where(&self) -> CFragLocatorKind {
        self.where_
    }

    /// Returns the container offset.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Returns the container length.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Returns the first locator-dependent union.
    pub fn get_u_where1(&self) -> &CFragWhere1Union {
        &self.u_where1
    }

    /// Returns the second locator-dependent union.
    pub fn get_u_where2(&self) -> &CFragWhere2Union {
        &self.u_where2
    }

    /// Returns the extension count.
    pub fn get_extension_count(&self) -> i32 {
        i32::from(self.extension_count)
    }

    /// Returns the total size of this member in bytes.
    pub fn get_member_size(&self) -> i32 {
        i32::from(self.member_size)
    }

    /// Returns the fragment's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

/// The Java `Enum.toString()` of a CFM enum constant (`kApplicationCFrag`, ...): this crate's
/// variant names are those identifiers with the leading `k` upper-cased.
fn java_constant_name(variant: impl std::fmt::Debug) -> String {
    let debug = format!("{variant:?}");
    let mut chars = debug.chars();
    chars
        .next()
        .map(|first| first.to_ascii_lowercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

impl StructConverter for CFragResourceMember {
    /// Port of `toDataType()`. The component list is Java's verbatim, including where it differs
    /// from the on-disk layout (it omits the unions and declares `extensionCount`/`memberSize` as
    /// DWORDs).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let name = |s: &str| Some(s.to_string());
        let mut s = StructureDataTypeImpl::new("CFragResourceMember", 0);
        s.add_with_length_and_name(PrimitiveDt::STRING.boxed(), 4, name("architecture"), None)?;
        s.add_with_name(PrimitiveDt::WORD.boxed(), name("reservedA"), None)?;
        s.add_with_name(PrimitiveDt::BYTE.boxed(), name("reservedB"), None)?;
        s.add_with_name(PrimitiveDt::BYTE.boxed(), name("updateLevel"), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("currentVersion"), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("oldDefVersion"), None)?;
        s.add_with_name(
            PrimitiveDt::DWORD.boxed(),
            name("usage"),
            Some(java_constant_name(self.usage)),
        )?;
        s.add_with_name(
            PrimitiveDt::DWORD.boxed(),
            name("where"),
            Some(java_constant_name(self.where_)),
        )?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("offset"), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("length"), None)?;
        s.add_with_name(PrimitiveDt::BYTE.boxed(), name("reservedC"), None)?;
        s.add_with_name(PrimitiveDt::BYTE.boxed(), name("reservedD"), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("extensionCount"), None)?;
        s.add_with_name(PrimitiveDt::DWORD.boxed(), name("memberSize"), None)?;
        s.add_with_length_and_name(
            PrimitiveDt::PASCAL_STRING255.boxed(),
            self.name.len() as i32 + 1,
            name("name"),
            None,
        )?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::{cfrag_member, Image, VecReader};

    fn member_bytes(usage: u8, name: &str) -> Vec<u8> {
        let mut img = Image::default();
        cfrag_member(&mut img, b"m68k", usage, name, 0x40);
        img.0
    }

    #[test]
    fn reads_every_field() {
        let bytes = member_bytes(2, "Plugin");
        let len = bytes.len() as u64;
        let mut reader = VecReader::new(bytes);
        let m = CFragResourceMember::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), len);
        assert_eq!(len, 43 + 6);
        assert_eq!(m.get_architecture(), "m68k");
        assert_eq!(m.get_update_level(), 5);
        assert_eq!(m.get_current_version(), 2);
        assert_eq!(m.get_old_def_version(), 1);
        assert_eq!(m.get_u_usage1().get_app_stack_size(), 0x1000);
        assert_eq!(m.get_u_usage2().get_application_subdirectory_id(), 0);
        assert_eq!(m.get_usage(), CFragUsage::KDropInAdditionCFrag);
        assert_eq!(m.get_where(), CFragLocatorKind::KDataForkCFragLocator);
        assert_eq!(m.get_offset(), 0x200);
        assert_eq!(m.get_length(), 0x300);
        assert_eq!(m.get_u_where1().get_space_id(), 0);
        assert_eq!(m.get_u_where2().get_reserved(), 0);
        assert_eq!(m.get_extension_count(), 0);
        assert_eq!(m.get_member_size(), 0x40);
        assert_eq!(m.get_name(), "Plugin");
    }

    #[test]
    fn non_zero_reserved_field_is_rejected() {
        let mut bytes = member_bytes(1, "A");
        bytes[6] = 1; // reservedB
        let err = CFragResourceMember::new(&mut VecReader::new(bytes)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "Reserved fields contain invalid value(s).");
    }

    #[test]
    fn out_of_range_usage_is_an_error() {
        assert!(CFragResourceMember::new(&mut VecReader::new(member_bytes(9, "A"))).is_err());
    }

    #[test]
    fn to_data_type_mirrors_javas_component_list() {
        let m = CFragResourceMember::new(&mut VecReader::new(member_bytes(1, "App"))).unwrap();
        let dt = m.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragResourceMember");
        // 4+2+1+1 + 4*6 + 1+1 + 4+4 + ("App".len() + 1)
        assert_eq!(dt.get_length(), 8 + 24 + 2 + 8 + 4);
    }

    #[test]
    fn java_constant_names_match_enum_identifiers() {
        assert_eq!(java_constant_name(CFragUsage::KApplicationCFrag), "kApplicationCFrag");
        assert_eq!(
            java_constant_name(CFragLocatorKind::KCFBundleCFragLocator),
            "kCFBundleCFragLocator"
        );
    }
}
