//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragWhere2Union`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// The second locator-dependent union of a CFM fragment resource member (reserved).
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragWhere2Union`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFragWhere2Union {
    reserved: i16,
}

impl CFragWhere2Union {
    /// Reads the 2-byte union.
    ///
    /// Port of the `CFragWhere2Union(BinaryReader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(Self { reserved: reader.read_next_short()? })
    }

    /// Returns the reserved value.
    pub fn get_reserved(&self) -> i16 {
        self.reserved
    }
}

impl StructConverter for CFragWhere2Union {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: a single
    /// `reserved` component.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("CFragWhere2Union", 0);
        s.add_with_name(PrimitiveDt::WORD.boxed(), Some("reserved".to_string()), None)?;
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
        let u = CFragWhere2Union::new(&mut reader).unwrap();
        assert_eq!(u.get_reserved(), 0x0102);
        assert_eq!(reader.get_pointer_index(), 2);
        let dt = u.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragWhere2Union");
        assert_eq!(dt.get_length(), 2);
    }

    #[test]
    fn short_input_is_an_error() {
        assert!(CFragWhere2Union::new(&mut VecReader::new(vec![1])).is_err());
    }
}
