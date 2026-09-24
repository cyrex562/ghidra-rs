//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragWhere1Union`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The first locator-dependent union of a CFM fragment resource member: the space ID.
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragWhere1Union`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFragWhere1Union {
    space_id: i32,
}

impl CFragWhere1Union {
    /// Reads the 4-byte union.
    ///
    /// Port of the `CFragWhere1Union(BinaryReader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(Self { space_id: reader.read_next_int()? })
    }

    /// Returns the space ID.
    pub fn get_space_id(&self) -> i32 {
        self.space_id
    }
}

impl StructConverter for CFragWhere1Union {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: a single
    /// `spaceID` component.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("CFragWhere1Union", 0);
        s.add_with_name(PrimitiveDt::DWORD.boxed(), Some("spaceID".to_string()), None)?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;

    #[test]
    fn reads_big_endian_value_and_converts_to_data_type() {
        let mut reader = VecReader::new(vec![1, 2, 3, 4]);
        let u = CFragWhere1Union::new(&mut reader).unwrap();
        assert_eq!(u.get_space_id(), 0x0102_0304);
        assert_eq!(reader.get_pointer_index(), 4);
        let dt = u.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragWhere1Union");
        assert_eq!(dt.get_length(), 4);
    }

    #[test]
    fn short_input_is_an_error() {
        assert!(CFragWhere1Union::new(&mut VecReader::new(vec![1])).is_err());
    }
}
