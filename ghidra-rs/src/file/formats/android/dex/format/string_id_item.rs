use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::file::seam_stubs::StringDataItem;

/// Represents a string ID item in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.StringIDItem`.
///
/// See: https://source.android.com/devices/tech/dalvik/dex-format#string-item
#[derive(Debug, Clone)]
pub struct StringIDItem {
    string_data_offset: i32,
    string_data_item: StringDataItem,
}

impl StringIDItem {
    /// Creates a new `StringIDItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let string_data_offset = reader.read_next_int()?;

        let string_data_item = match Self::create_string_data_item(
            string_data_offset,
            reader,
            dex_header,
        ) {
            Ok(item) => item,
            Err(_) => {
                let invalid_string = format!("Invalid_String_0x{:x}", string_data_offset);
                StringDataItem::new(invalid_string)
            }
        };

        Ok(Self {
            string_data_offset,
            string_data_item,
        })
    }

    /// NOTE: For CDEX files, this value is relative to DataOffset in DexHeader
    pub fn get_string_data_offset(&self) -> i32 {
        self.string_data_offset
    }

    pub fn get_string_data_item(&self) -> &StringDataItem {
        &self.string_data_item
    }

    fn create_string_data_item(
        string_data_offset: i32,
        reader: &mut BinaryReader,
        _dex_header: &DexHeader,
    ) -> io::Result<StringDataItem> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(string_data_offset as u64);

        let item = StringDataItem::new("placeholder".to_string());

        reader.set_pointer_index(old_index);

        Ok(item)
    }
}

impl StructConverter for StringIDItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "StringIDItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_id_item_basic() {
        let mut reader = BinaryReader::from_bytes(vec![0x10, 0x00, 0x00, 0x00], true);
        let dex_header = DexHeader::minimal_for_tests();

        let result = StringIDItem::new(&mut reader, &dex_header);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.get_string_data_offset(), 0x10);
    }

    #[test]
    fn test_string_id_item_multiple() {
        let mut reader = BinaryReader::from_bytes(vec![
            0x20, 0x00, 0x00, 0x00,
            0x30, 0x00, 0x00, 0x00,
        ], true);
        let dex_header = DexHeader::minimal_for_tests();

        let item1 = StringIDItem::new(&mut reader, &dex_header);
        assert!(item1.is_ok());
        assert_eq!(item1.unwrap().get_string_data_offset(), 0x20);

        let item2 = StringIDItem::new(&mut reader, &dex_header);
        assert!(item2.is_ok());
        assert_eq!(item2.unwrap().get_string_data_offset(), 0x30);
    }
}
