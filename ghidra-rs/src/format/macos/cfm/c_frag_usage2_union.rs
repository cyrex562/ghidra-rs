//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragUsage2Union`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// Port of `kNoAppSubFolder`.
pub const K_NO_APP_SUB_FOLDER: i16 = 0;

/// The second usage-dependent union of a CFM fragment resource member: the application
/// subdirectory ID.
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragUsage2Union`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFragUsage2Union {
    app_subdir_id: i16,
}

impl CFragUsage2Union {
    /// Reads the 2-byte union.
    ///
    /// Port of the `CFragUsage2Union(BinaryReader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(Self { app_subdir_id: reader.read_next_short()? })
    }

    /// Returns the application subdirectory ID.
    pub fn get_application_subdirectory_id(&self) -> i16 {
        self.app_subdir_id
    }
}

impl StructConverter for CFragUsage2Union {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: a single
    /// `appSubdirID` component.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("CFragUsage2Union", 0);
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("appSubdirID".to_string()), None)?;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;

    #[test]
    fn reads_big_endian_value_and_converts_to_data_type() {
        let mut reader = VecReader::new(vec![1, 2]);
        let u = CFragUsage2Union::new(&mut reader).unwrap();
        assert_eq!(u.get_application_subdirectory_id(), 0x0102);
        assert_eq!(reader.get_pointer_index(), 2);
        let dt = u.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragUsage2Union");
        assert_eq!(dt.get_length(), 2);
    }

    #[test]
    fn short_input_is_an_error() {
        assert!(CFragUsage2Union::new(&mut VecReader::new(vec![1])).is_err());
    }
}
