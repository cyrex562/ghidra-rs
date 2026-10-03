use std::io;

use thiserror::Error;

use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::endian_settings_definition::EndianSettingsDefinition;
use crate::program::model::listing::data::Data;
use crate::util::exception::DuplicateNameException;

/// Error produced by [`StructConverter::to_data_type`], standing in for the checked exceptions
/// declared on `StructConverter.toDataType()` in Java (`DuplicateNameException`, `IOException`).
#[derive(Debug, Error)]
pub enum ToDataTypeError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Allows a type to create a structure datatype equivalent to its own members.
///
/// Port of `ghidra.app.util.bin.StructConverter`.
///
/// The Java interface also declares a set of reusable `DataType` singleton constants (`BYTE`,
/// `WORD`, `DWORD`, `QWORD`, `ASCII`, `STRING`, `UTF8`, `UTF16`, `POINTER`, `VOID`, `IBO32`,
/// `IBO64`, `BOOL`, `ULEB128`, `SLEB128`). Those are backed by concrete datatype singletons
/// (`ByteDataType`, `WordDataType`, ...) that are not yet ported, so they are omitted here;
/// implementors should reference those datatypes directly once they land.
pub trait StructConverter {
    /// Returns a structure datatype representing the contents of the implementor of this trait.
    ///
    /// For example, given a type with an `i32` field and an `f64` field, the return value should
    /// be a structure datatype with two components: an INT and a DOUBLE. The structure should
    /// contain field names and, if possible, field comments.
    ///
    /// Port of `StructConverter.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError>;
}

/// Recursively sets `data` and its components to big/little endian.
///
/// Port of `StructConverter.setEndian(Data, boolean)`.
pub fn set_endian(data: &mut dyn Data, big_endian: bool) {
    for i in 0..data.get_num_components() {
        let Some(mut component) = data.get_component(i) else {
            continue;
        };
        let settings = component.get_data_type().get_settings_definitions();
        for def in &settings {
            if def.get_storage_key() == EndianSettingsDefinition::DEF.get_storage_key() {
                EndianSettingsDefinition::DEF.set_big_endian(component.as_mut(), big_endian);
            }
        }
        set_endian(component.as_mut(), big_endian);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockConverter;

    impl StructConverter for MockConverter {
        fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable() {
        let converter: Box<dyn StructConverter> = Box::new(MockConverter);
        assert!(converter.to_data_type().is_ok());
    }

    #[test]
    fn to_data_type_error_wraps_duplicate_name_exception() {
        let err: ToDataTypeError = DuplicateNameException::default().into();
        assert!(matches!(err, ToDataTypeError::Duplicate(_)));
    }

    #[test]
    fn to_data_type_error_wraps_io_error() {
        let err: ToDataTypeError = io::Error::from(io::ErrorKind::UnexpectedEof).into();
        assert!(matches!(err, ToDataTypeError::Io(_)));
    }
}
