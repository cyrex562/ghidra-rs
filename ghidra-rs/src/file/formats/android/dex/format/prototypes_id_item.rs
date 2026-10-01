use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::file::seam_stubs::{DexUtil, TypeList};

/// Represents a method prototype (shorty, return type, parameter types) in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.PrototypesIDItem`.
///
/// See: https://source.android.com/docs/core/runtime/dex-format#proto-id-item
#[derive(Debug, Clone)]
pub struct PrototypesIDItem {
    shorty_index: i32,
    return_type_index: i32,
    parameters_offset: i32,
    parameters: Option<TypeList>,
}

impl PrototypesIDItem {
    /// Creates a new `PrototypesIDItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let shorty_index = reader.read_next_int()?;
        let return_type_index = reader.read_next_int()?;
        let parameters_offset = reader.read_next_int()?;

        let mut parameters = None;
        if parameters_offset > 0 {
            let old_index = reader.get_pointer_index();
            // starting in Android 12, CDEX files are incomplete
            let adjusted_parameters_offset = DexUtil::adjust_offset(parameters_offset, dex_header);
            if reader.is_valid_index(adjusted_parameters_offset as u64) {
                reader.set_pointer_index(adjusted_parameters_offset as u64);
                // Note: We would create a TypeList here, but it's a stub.
                // Once TypeList is ported, this should instantiate it.
                parameters = Some(TypeList);
            }
            reader.set_pointer_index(old_index);
        }

        Ok(Self {
            shorty_index,
            return_type_index,
            parameters_offset,
            parameters,
        })
    }

    pub fn get_shorty_index(&self) -> i32 {
        self.shorty_index
    }

    pub fn get_return_type_index(&self) -> i32 {
        self.return_type_index
    }

    /// NOTE: For CDEX files, this value is relative to `DataOffset` in `DexHeader`.
    pub fn get_parameters_offset(&self) -> i32 {
        self.parameters_offset
    }

    pub fn get_parameters(&self) -> Option<&TypeList> {
        self.parameters.as_ref()
    }
}

impl StructConverter for PrototypesIDItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        // Would call StructConverterUtil.toDataType(PrototypesIDItem.class), then set the
        // category path to "/dex". Since StructConverterUtil is a stub, we return an error.
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "PrototypesIDItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_zero_offset() {
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // shorty_index = 0
            0x00, 0x00, 0x00, 0x00, // return_type_index = 0
            0x00, 0x00, 0x00, 0x00, // parameters_offset = 0
        ];
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = PrototypesIDItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_shorty_index(), 0);
        assert_eq!(item.get_return_type_index(), 0);
        assert_eq!(item.get_parameters_offset(), 0);
        assert!(item.get_parameters().is_none());
    }

    #[test]
    fn new_with_nonzero_offset() {
        let bytes = vec![
            0x07, 0x00, 0x00, 0x00, // shorty_index = 7
            0x02, 0x00, 0x00, 0x00, // return_type_index = 2
            0x0c, 0x00, 0x00, 0x00, // parameters_offset = 12 (points at trailing byte below)
            0xff, // byte at the parameters offset, so it is a valid index
        ];
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = PrototypesIDItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_shorty_index(), 7);
        assert_eq!(item.get_return_type_index(), 2);
        assert_eq!(item.get_parameters_offset(), 12);
        assert!(item.get_parameters().is_some());
        // the pointer index is restored to just past the fixed-size header after the excursion
        assert_eq!(reader.get_pointer_index(), 12);
    }
}
