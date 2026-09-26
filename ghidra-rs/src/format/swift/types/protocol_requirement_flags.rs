//! Port of `ghidra.app.util.bin.format.swift.types.ProtocolRequirementFlags`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::{
    SwiftTypeMetadataStructure, SwiftTypeMetadataStructureBase, CATEGORY_PATH,
};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

use super::method_descriptor_flags::{add_bit_field, BoolDt, DWordDt};
use super::protocol_requirement_kind::ProtocolRequirementKind;

/// Swift `ProtocolRequirementFlags` structure.
///
/// Port of `ghidra.app.util.bin.format.swift.types.ProtocolRequirementFlags`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone)]
pub struct ProtocolRequirementFlags {
    base: SwiftTypeMetadataStructureBase,
    flags: i32,
}

impl ProtocolRequirementFlags {
    /// The size (in bytes) of a `ProtocolRequirementFlags` structure.
    pub const SIZE: i32 = 4;

    /// Creates a new `ProtocolRequirementFlags` from a reader positioned at the start of the
    /// structure.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let base = SwiftTypeMetadataStructureBase::new(reader.get_pointer_index() as i64);
        let flags = reader.read_next_int()?;
        Ok(ProtocolRequirementFlags { base, flags })
    }

    /// Returns the base "address" of this structure.
    pub fn get_base(&self) -> i64 {
        self.base.get_base()
    }

    /// Returns the raw flags.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Returns the [`ProtocolRequirementKind`] (low 4 bits), or `None` (Java `null`) if unknown.
    pub fn get_kind(&self) -> Option<ProtocolRequirementKind> {
        ProtocolRequirementKind::value_of(self.flags & 0x0f)
    }

    /// Returns whether or not the protocol requirement is instance.
    pub fn is_instance(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    /// Returns whether or not the protocol requirement is async (Java: `isAnsyc()`).
    pub fn is_async(&self) -> bool {
        (self.flags & 0x20) != 0
    }

    /// Returns the extra discriminator (upper 16 bits; Java: `getExtraDescriminator()`).
    pub fn get_extra_descriminator(&self) -> i32 {
        (self.flags >> 16) & 0xffff
    }
}

impl SwiftTypeMetadataStructure for ProtocolRequirementFlags {
    fn get_structure_name(&self) -> String {
        "ProtocolRequirementFlags".to_string()
    }

    fn get_description(&self) -> String {
        "protocol requirements flags".to_string()
    }
}

impl StructConverter for ProtocolRequirementFlags {
    /// Java: `toDataType()`. Unlike `MethodDescriptorFlags`, Java builds the `kind` field from
    /// `getKind().toDataType()`, which throws `NullPointerException` when the kind bits are
    /// unknown; that case is reported here as an `InvalidData` I/O error.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let kind = self.get_kind().ok_or_else(|| {
            ToDataTypeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown ProtocolRequirementKind value {}", self.flags & 0x0f),
            ))
        })?;
        let mut struct_ = StructureDataTypeImpl::new_in_category(
            CATEGORY_PATH.clone(),
            self.get_structure_name(),
            Self::SIZE,
        );
        struct_.set_packing_enabled(true);
        add_bit_field(&mut struct_, kind.to_data_type()?, 4, "kind")?;
        add_bit_field(&mut struct_, Box::new(BoolDt), 1, "IsInstance")?;
        add_bit_field(&mut struct_, Box::new(BoolDt), 1, "IsAsync")?;
        add_bit_field(&mut struct_, Box::new(DWordDt), 10, "reserved")?;
        add_bit_field(&mut struct_, Box::new(DWordDt), 16, "ExtraDescriminator")?;
        Ok(Box::new(struct_))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_reader::VecReader;
    use super::*;

    fn parse(flags: u32) -> ProtocolRequirementFlags {
        let mut reader = VecReader::new(flags.to_le_bytes().to_vec(), 0);
        let f = ProtocolRequirementFlags::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 4);
        f
    }

    #[test]
    fn decodes_kind_and_bits() {
        let f = parse(0x0000_0018);
        assert_eq!(f.get_base(), 0);
        assert_eq!(f.get_kind(), Some(ProtocolRequirementKind::AssociatedConformanceAccessFunction));
        assert!(f.is_instance());
        assert!(!f.is_async());

        let f = parse(0x0000_0021);
        assert_eq!(f.get_kind(), Some(ProtocolRequirementKind::Method));
        assert!(!f.is_instance());
        assert!(f.is_async());
        // 0x40 is not an async bit here, unlike MethodDescriptorFlags.
        assert!(!parse(0x40).is_async());
    }

    #[test]
    fn unknown_kind_is_none_and_to_data_type_errors() {
        let f = parse(0x0000_0009);
        assert_eq!(f.get_kind(), None);
        assert!(f.to_data_type().is_err());
    }

    #[test]
    fn extra_descriminator_is_upper_16_bits_unsigned() {
        assert_eq!(parse(0x8001_0000).get_extra_descriminator(), 0x8001);
    }

    #[test]
    fn names_and_description() {
        let f = parse(0);
        assert_eq!(f.get_structure_name(), "ProtocolRequirementFlags");
        assert_eq!(f.get_description(), "protocol requirements flags");
    }

    #[test]
    fn to_data_type_builds_packed_bitfield_struct() {
        let dt = parse(0x11).to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ProtocolRequirementFlags");
        assert_eq!(dt.get_length(), 4);
        let names: Vec<_> = dt
            .as_composite()
            .expect("structure")
            .get_components()
            .iter()
            .map(|c| c.get_field_name().unwrap())
            .collect();
        assert_eq!(names, ["kind", "IsInstance", "IsAsync", "reserved", "ExtraDescriminator"]);
    }
}
