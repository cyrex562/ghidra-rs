//! Port of `ghidra.app.util.bin.format.swift.types.MethodDescriptorFlags`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::{
    SwiftTypeMetadataStructure, SwiftTypeMetadataStructureBase, CATEGORY_PATH,
};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

use super::method_descriptor_kind::MethodDescriptorKind;

/// Stand-in for `StructConverter.BOOL` (`BooleanDataType.dataType`), whose concrete singleton this
/// crate has not ported yet (see `struct_converter.rs`; same approach as the local `DWordDt`
/// stand-ins in `cram_fs_inode.rs`/`dex_header.rs`). Java's `BooleanDataType` extends
/// `AbstractUnsignedIntegerDataType`, so it is an unsigned 1-byte integer type -- the property the
/// bitfield base-type check observes.
pub(super) struct BoolDt;

impl DataType for BoolDt {
    fn get_name(&self) -> String {
        "bool".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }

    fn is_integer_type(&self) -> bool {
        true
    }
}

/// Stand-in for `StructConverter.DWORD` (`DWordDataType.dataType`); see [`BoolDt`]. An unsigned
/// 4-byte integer type.
pub(super) struct DWordDt;

impl DataType for DWordDt {
    fn get_name(&self) -> String {
        "dword".to_string()
    }

    fn get_length(&self) -> i32 {
        4
    }

    fn is_integer_type(&self) -> bool {
        true
    }
}

/// Adds a bitfield to `struct_`, mapping Java's `InvalidDataTypeException` to the
/// `IOException` that `toDataType()` rethrows it as.
pub(super) fn add_bit_field(
    struct_: &mut StructureDataTypeImpl,
    base: Box<dyn DataType>,
    bit_size: i32,
    name: &str,
) -> Result<(), ToDataTypeError> {
    struct_
        .add_bit_field(base, bit_size, Some(name.to_string()), None)
        .map(|_| ())
        .map_err(|e| ToDataTypeError::Io(io::Error::other(e)))
}

/// Swift `MethodDescriptorFlags` structure.
///
/// Port of `ghidra.app.util.bin.format.swift.types.MethodDescriptorFlags`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone)]
pub struct MethodDescriptorFlags {
    base: SwiftTypeMetadataStructureBase,
    flags: i32,
}

impl MethodDescriptorFlags {
    /// The size (in bytes) of a `MethodDescriptorFlags` structure.
    pub const SIZE: i32 = 4;

    /// Creates a new `MethodDescriptorFlags` from a reader positioned at the start of the
    /// structure.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let base = SwiftTypeMetadataStructureBase::new(reader.get_pointer_index() as i64);
        let flags = reader.read_next_int()?;
        Ok(MethodDescriptorFlags { base, flags })
    }

    /// Returns the base "address" of this structure.
    pub fn get_base(&self) -> i64 {
        self.base.get_base()
    }

    /// Returns the raw flags.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Returns the [`MethodDescriptorKind`] (low 4 bits), or `None` (Java `null`) if unknown.
    pub fn get_kind(&self) -> Option<MethodDescriptorKind> {
        MethodDescriptorKind::value_of(self.flags & 0x0f)
    }

    /// Returns whether or not the method is an instance method.
    pub fn is_instance(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    /// Returns whether or not the method is dynamic.
    pub fn is_dynamic(&self) -> bool {
        (self.flags & 0x20) != 0
    }

    /// Returns whether or not the method is async (Java: `isAnsyc()`).
    pub fn is_async(&self) -> bool {
        (self.flags & 0x40) != 0
    }

    /// Returns the extra discriminator (upper 16 bits; Java: `getExtraDescriminator()`).
    pub fn get_extra_descriminator(&self) -> i32 {
        (self.flags >> 16) & 0xffff
    }
}

impl SwiftTypeMetadataStructure for MethodDescriptorFlags {
    fn get_structure_name(&self) -> String {
        "MethodDescriptorFlags".to_string()
    }

    fn get_description(&self) -> String {
        "method descriptor flags".to_string()
    }
}

impl StructConverter for MethodDescriptorFlags {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut struct_ = StructureDataTypeImpl::new_in_category(
            CATEGORY_PATH.clone(),
            self.get_structure_name(),
            Self::SIZE,
        );
        struct_.set_packing_enabled(true);
        add_bit_field(&mut struct_, MethodDescriptorKind::VALUES[0].to_data_type()?, 4, "kind")?;
        add_bit_field(&mut struct_, Box::new(BoolDt), 1, "IsInstance")?;
        add_bit_field(&mut struct_, Box::new(BoolDt), 1, "IsDynamic")?;
        add_bit_field(&mut struct_, Box::new(BoolDt), 1, "IsAsync")?;
        add_bit_field(&mut struct_, Box::new(DWordDt), 9, "reserved")?;
        add_bit_field(&mut struct_, Box::new(DWordDt), 16, "ExtraDescriminator")?;
        Ok(Box::new(struct_))
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_reader::VecReader;
    use super::*;

    fn parse(flags: u32) -> MethodDescriptorFlags {
        let mut bytes = vec![0xAA, 0xBB];
        bytes.extend_from_slice(&flags.to_le_bytes());
        let mut reader = VecReader::new(bytes, 2);
        let f = MethodDescriptorFlags::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 6);
        f
    }

    #[test]
    fn reads_flags_and_records_base() {
        let f = parse(0x1234_0012);
        assert_eq!(f.get_base(), 2);
        assert_eq!(f.get_flags(), 0x1234_0012);
    }

    #[test]
    fn decodes_kind_and_bits() {
        let f = parse(0x0000_0013);
        assert_eq!(f.get_kind(), Some(MethodDescriptorKind::Setter));
        assert!(f.is_instance());
        assert!(!f.is_dynamic());
        assert!(!f.is_async());

        let f = parse(0x0000_0060);
        assert_eq!(f.get_kind(), Some(MethodDescriptorKind::Method));
        assert!(!f.is_instance());
        assert!(f.is_dynamic());
        assert!(f.is_async());
    }

    #[test]
    fn unknown_kind_is_none() {
        assert_eq!(parse(0x0000_000f).get_kind(), None);
        assert_eq!(parse(0x0000_0006).get_kind(), None);
    }

    #[test]
    fn extra_descriminator_is_upper_16_bits_unsigned() {
        assert_eq!(parse(0xFFFF_0000).get_extra_descriminator(), 0xffff);
        assert_eq!(parse(0xABCD_007F).get_extra_descriminator(), 0xABCD);
    }

    #[test]
    fn short_read_is_error() {
        let mut reader = VecReader::new(vec![1, 2, 3], 0);
        assert!(MethodDescriptorFlags::new(&mut reader).is_err());
    }

    #[test]
    fn names_and_description() {
        let f = parse(0);
        assert_eq!(f.get_structure_name(), "MethodDescriptorFlags");
        assert_eq!(f.get_description(), "method descriptor flags");
    }

    #[test]
    fn to_data_type_builds_packed_bitfield_struct() {
        let dt = parse(0).to_data_type().unwrap();
        assert_eq!(dt.get_name(), "MethodDescriptorFlags");
        assert_eq!(dt.get_length(), 4);
        let comp = dt.as_composite().expect("structure");
        let names: Vec<_> = comp
            .get_components()
            .iter()
            .map(|c| {
                assert!(c.is_bit_field_component());
                c.get_field_name().unwrap()
            })
            .collect();
        assert_eq!(
            names,
            ["kind", "IsInstance", "IsDynamic", "IsAsync", "reserved", "ExtraDescriminator"]
        );
    }
}
