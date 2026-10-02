//! Crate-internal helper for the ELF `toDataType()` ports (no Java counterpart).
//!
//! The ELF header classes all build their structures the same way:
//!
//! ```java
//! StructureDataType struct = new StructureDataType(new CategoryPath("/ELF"), name, 0);
//! struct.add(DWORD, "field", null);
//! ```
//!
//! [`ElfStruct`] spells that once over the real [`StructureDataType`].

use std::io;

use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::dword_data_type::DWordDataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;
use crate::program::model::data::qword_data_type::QWordDataType;
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::data::word_data_type::WordDataType;

/// The `/ELF` data type category every ELF structure lives in.
pub(crate) fn elf_category() -> CategoryPath {
    CategoryPath::parse("/ELF").expect("\"/ELF\" is a valid category path")
}

pub(crate) fn byte() -> Box<dyn DataType> {
    Box::new(ByteDataType::new(None))
}

pub(crate) fn word() -> Box<dyn DataType> {
    Box::new(WordDataType::new(None))
}

pub(crate) fn dword() -> Box<dyn DataType> {
    Box::new(DWordDataType::new(None))
}

pub(crate) fn qword() -> Box<dyn DataType> {
    Box::new(QWordDataType::new(None))
}

pub(crate) fn string() -> Box<dyn DataType> {
    Box::new(StringDataType::new(None))
}

/// `new ArrayDataType(elem, count, elementLength)`.
pub(crate) fn array(
    elem: Box<dyn DataType>,
    count: i32,
    element_length: i32,
) -> Result<Box<dyn DataType>, ToDataTypeError> {
    ArrayDataType::with_element_length(elem, count, element_length)
        .map(|a| Box::new(a) as Box<dyn DataType>)
        .map_err(invalid)
}

/// `new EnumDataType(new CategoryPath("/ELF"), name, size)` populated with `values`.
pub(crate) fn enum_type<'a>(
    name: &str,
    size: i32,
    values: impl Iterator<Item = (&'a str, i64)>,
) -> Box<dyn DataType> {
    let mut e = EnumDataType::new_in_category(elf_category(), name, size);
    for (n, v) in values {
        Enum::add(&mut e, n, v);
    }
    Box::new(e)
}

pub(crate) fn invalid(message: String) -> ToDataTypeError {
    ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// A `StructureDataType` under construction in the `/ELF` category.
pub(crate) struct ElfStruct {
    inner: StructureDataType,
}

impl ElfStruct {
    /// Java: `new StructureDataType(new CategoryPath("/ELF"), name, 0)`.
    pub(crate) fn new(name: &str) -> Self {
        ElfStruct { inner: StructureDataType::new_in_category(elf_category(), name, 0) }
    }

    /// Java: `struct.add(dt, name, null)`.
    pub(crate) fn add(&mut self, dt: Box<dyn DataType>, name: &str) -> Result<(), ToDataTypeError> {
        Composite::add_with_name(&mut self.inner, dt, Some(name.to_string()), None)
            .map(|_| ())
            .map_err(invalid)
    }

    /// Java: `struct.add(dt, length, name, null)`.
    pub(crate) fn add_len(
        &mut self,
        dt: Box<dyn DataType>,
        length: i32,
        name: &str,
    ) -> Result<(), ToDataTypeError> {
        Composite::add_with_length_and_name(&mut self.inner, dt, length, Some(name.to_string()), None)
            .map(|_| ())
            .map_err(invalid)
    }

    /// The structure's current length in bytes.
    pub(crate) fn length(&self) -> i32 {
        DataType::get_length(&self.inner)
    }

    pub(crate) fn into_structure(self) -> StructureDataType {
        self.inner
    }

    pub(crate) fn finish(self) -> Box<dyn DataType> {
        Box::new(self.inner)
    }
}
