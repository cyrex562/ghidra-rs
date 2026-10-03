//! Crate-internal helper for the Mach-O `toDataType()` ports.
//!
//! Nearly every Mach-O structure's Java `toDataType()` has the same shape:
//!
//! ```java
//! StructureDataType struct = new StructureDataType("name", 0);
//! struct.add(DWORD, "field", null);
//! ...
//! struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
//! return struct;
//! ```
//!
//! [`MachStruct`] is a thin wrapper around the real
//! [`StructureDataType`] that spells those steps once. It has no Java counterpart.

use std::io;

use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::dword_data_type::DWordDataType;
use crate::program::model::data::qword_data_type::QWordDataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::data::signed_leb128_data_type::SignedLeb128DataType;
use crate::program::model::data::unsigned_leb128_data_type::UnsignedLeb128DataType;
use crate::program::model::data::word_data_type::WordDataType;

/// Java's `StructConverter.BYTE`.
pub(crate) fn byte() -> Box<dyn DataType> {
    Box::new(ByteDataType::new(None))
}

/// Java's `StructConverter.WORD`.
pub(crate) fn word() -> Box<dyn DataType> {
    Box::new(WordDataType::new(None))
}

/// Java's `StructConverter.DWORD`.
pub(crate) fn dword() -> Box<dyn DataType> {
    Box::new(DWordDataType::new(None))
}

/// Java's `StructConverter.QWORD`.
pub(crate) fn qword() -> Box<dyn DataType> {
    Box::new(QWordDataType::new(None))
}

/// Java's `new ArrayDataType(elem, count, elem.getLength())`.
pub(crate) fn array(elem: Box<dyn DataType>, count: i32) -> Result<Box<dyn DataType>, ToDataTypeError> {
    let len = elem.get_length();
    ArrayDataType::with_element_length(elem, count, len)
        .map(|a| Box::new(a) as Box<dyn DataType>)
        .map_err(invalid)
}

/// Java's `new StringDataType()` / `StructConverter.STRING` (`StringDataType.dataType`), the
/// fixed-length string used for the 16-byte `char[]` name fields (`segname`, `sectname`, ...).
pub(crate) fn fixed_string() -> Result<Box<dyn DataType>, ToDataTypeError> {
    Ok(Box::new(StringDataType::new(None)))
}

/// Java's `StructConverter.ULEB128` (`UnsignedLeb128DataType.dataType`).
pub(crate) fn uleb128() -> Result<Box<dyn DataType>, ToDataTypeError> {
    Ok(Box::new(UnsignedLeb128DataType::new(None)))
}

/// Java's `StructConverter.SLEB128` (`SignedLeb128DataType.dataType`).
pub(crate) fn sleb128() -> Result<Box<dyn DataType>, ToDataTypeError> {
    Ok(Box::new(SignedLeb128DataType::new(None)))
}

/// Java's `new ArrayDataType(elem, count, elementLength)` with an explicit element length (only
/// meaningful for dynamic element types).
pub(crate) fn array_with_element_length(
    elem: Box<dyn DataType>,
    count: i32,
    element_length: i32,
) -> Result<Box<dyn DataType>, ToDataTypeError> {
    ArrayDataType::with_element_length(elem, count, element_length)
        .map(|a| Box::new(a) as Box<dyn DataType>)
        .map_err(invalid)
}

/// Java's `StructConverter.ASCII` (`CharDataType.dataType`).
pub(crate) fn ascii() -> Result<Box<dyn DataType>, ToDataTypeError> {
    Ok(Box::new(CharDataType::new(None)))
}

fn invalid(message: String) -> ToDataTypeError {
    ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// A `StructureDataType` under construction, destined for the `/MachO` category.
pub(crate) struct MachStruct {
    inner: StructureDataType,
}

impl MachStruct {
    /// Java: `new StructureDataType(name, 0)`.
    pub(crate) fn new(name: impl Into<String>) -> Self {
        MachStruct { inner: StructureDataType::new(name, 0) }
    }

    /// Java: `struct.add(dt, name, comment)`.
    pub(crate) fn add(
        &mut self,
        dt: Box<dyn DataType>,
        name: &str,
        comment: Option<&str>,
    ) -> Result<&mut Self, ToDataTypeError> {
        Composite::add_with_name(
            &mut self.inner,
            dt,
            Some(name.to_string()),
            comment.map(str::to_string),
        )
        .map_err(invalid)?;
        Ok(self)
    }

    /// Java: `struct.add(dt, length, name, comment)`.
    pub(crate) fn add_len(
        &mut self,
        dt: Box<dyn DataType>,
        length: i32,
        name: &str,
        comment: Option<&str>,
    ) -> Result<&mut Self, ToDataTypeError> {
        Composite::add_with_length_and_name(
            &mut self.inner,
            dt,
            length,
            Some(name.to_string()),
            comment.map(str::to_string),
        )
        .map_err(invalid)?;
        Ok(self)
    }

    /// Java: `struct.add(DWORD, name, null)`.
    pub(crate) fn dword(&mut self, name: &str) -> Result<&mut Self, ToDataTypeError> {
        self.add(dword(), name, None)
    }

    /// Java: `struct.add(QWORD, name, null)`.
    pub(crate) fn qword(&mut self, name: &str) -> Result<&mut Self, ToDataTypeError> {
        self.add(qword(), name, None)
    }

    /// Java: `struct.add(WORD, name, null)`.
    pub(crate) fn word(&mut self, name: &str) -> Result<&mut Self, ToDataTypeError> {
        self.add(word(), name, None)
    }

    /// Java: `struct.add(BYTE, name, null)`.
    pub(crate) fn byte(&mut self, name: &str) -> Result<&mut Self, ToDataTypeError> {
        self.add(byte(), name, None)
    }

    /// Java: `struct.insertBitFieldAt(byteOffset, byteWidth, bitOffset, base, bitSize, name,
    /// comment)`. `Err` carries Java's `InvalidDataTypeException` message.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_bit_field_at(
        &mut self,
        byte_offset: i32,
        byte_width: i32,
        bit_offset: i32,
        base: Box<dyn DataType>,
        bit_size: i32,
        name: &str,
        comment: &str,
    ) -> Result<(), String> {
        Structure::insert_bit_field_at(
            &mut self.inner,
            byte_offset,
            byte_width,
            bit_offset,
            base,
            bit_size,
            Some(name.to_string()),
            Some(comment.to_string()),
        )
        .map(|_| ())
    }

    /// The structure's current length in bytes.
    pub(crate) fn len(&self) -> i32 {
        self.inner.get_length()
    }

    /// The structure as built, without setting the `/MachO` category path (for the few Java
    /// `toDataType()`s that omit `setCategoryPath`).
    pub(crate) fn into_structure(self) -> StructureDataType {
        self.inner
    }

    /// Java: `struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY)); return
    /// struct;`.
    pub(crate) fn finish_structure(mut self) -> Result<StructureDataType, ToDataTypeError> {
        let path = CategoryPath::parse(DATA_TYPE_CATEGORY).map_err(invalid)?;
        self.inner.set_category_path(path)?;
        Ok(self.inner)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Helpers for inspecting the structures the Mach-O `toDataType()` ports build.

    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::structure_data_type::StructureDataType;

    /// `(field name, offset, length)` for each component of a structure built by
    /// [`super::MachStruct`].
    pub(crate) fn fields(s: &StructureDataType) -> Vec<(String, i32, i32)> {
        (0..Composite::get_num_components(s))
            .map(|i| {
                let c = Composite::get_component(s, i).unwrap();
                (c.get_field_name().unwrap_or_default(), c.get_offset(), c.get_length())
            })
            .collect()
    }

    /// Just the field names of [`fields`].
    pub(crate) fn names(s: &StructureDataType) -> Vec<String> {
        fields(s).into_iter().map(|f| f.0).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fields;
    use super::*;
    use crate::program::model::data::data_type::DataType;

    #[test]
    fn builds_dword_qword_struct_in_macho_category() {
        let mut s = MachStruct::new("thing");
        s.dword("a").unwrap().qword("b").unwrap();
        let dt = s.finish_structure().unwrap();
        assert_eq!(dt.get_name(), "thing");
        assert_eq!(dt.get_length(), 12);
        assert_eq!(dt.get_category_path().to_string(), "/MachO");
        assert_eq!(
            fields(&dt),
            vec![("a".to_string(), 0, 4), ("b".to_string(), 4, 8)]
        );
    }
}
