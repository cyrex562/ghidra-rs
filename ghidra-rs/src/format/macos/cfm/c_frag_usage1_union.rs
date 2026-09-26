//! Port of `ghidra.app.util.bin.format.macos.cfm.CFragUsage1Union`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// Port of `kDefaultStackSize`.
pub const K_DEFAULT_STACK_SIZE: i32 = 0;

/// If the fragment is an application, `appStackSize` indicates the application stack size.
/// Typically `appStackSize` has the value [`K_DEFAULT_STACK_SIZE`].
///
/// Port of `ghidra.app.util.bin.format.macos.cfm.CFragUsage1Union`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFragUsage1Union {
    app_stack_size: i32,
}

impl CFragUsage1Union {
    /// Reads the 4-byte union.
    ///
    /// Port of the `CFragUsage1Union(BinaryReader)` constructor.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(Self { app_stack_size: reader.read_next_int()? })
    }

    /// Returns the application stack size.
    pub fn get_app_stack_size(&self) -> i32 {
        self.app_stack_size
    }
}

impl StructConverter for CFragUsage1Union {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: a single
    /// `appStackSize` component.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("CFragUsage1Union", 0);
        s.add_with_name(PrimitiveDt::DWORD.boxed(), Some("appStackSize".to_string()), None)?;
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
        let u = CFragUsage1Union::new(&mut reader).unwrap();
        assert_eq!(u.get_app_stack_size(), 0x0102_0304);
        assert_eq!(reader.get_pointer_index(), 4);
        let dt = u.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CFragUsage1Union");
        assert_eq!(dt.get_length(), 4);
    }

    #[test]
    fn short_input_is_an_error() {
        assert!(CFragUsage1Union::new(&mut VecReader::new(vec![1])).is_err());
    }
}
