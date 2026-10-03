use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::file::seam_stubs::{AnnotationSetItem, DexUtil};
use std::io;

/// Represents a field annotation in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.FieldAnnotationsItem`.
///
/// See: https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file_structs.h
#[derive(Debug, Clone)]
pub struct FieldAnnotationsItem {
    field_index: i32,
    annotations_offset: i32,
    annotation_set_item: Option<AnnotationSetItem>,
}

impl FieldAnnotationsItem {
    /// Creates a new `FieldAnnotationsItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let field_index = reader.read_next_int()?;
        let annotations_offset = reader.read_next_int()?;

        let annotation_set_item = if annotations_offset > 0 {
            // Clone the reader at the adjusted offset
            let adjusted_offset = DexUtil::adjust_offset(annotations_offset, dex_header);
            let _cloned_reader = reader.clone_at(adjusted_offset as u64);
            // Note: We would create an AnnotationSetItem here, but it's a stub.
            // Once AnnotationSetItem is ported, this should instantiate it.
            // For now, we create an empty stub to satisfy the type.
            Some(AnnotationSetItem)
        } else {
            None
        };

        Ok(Self {
            field_index,
            annotations_offset,
            annotation_set_item,
        })
    }

    pub fn get_field_index(&self) -> i32 {
        self.field_index
    }

    pub fn get_annotations_offset(&self) -> i32 {
        self.annotations_offset
    }

    pub fn get_annotation_set_item(&self) -> Option<&AnnotationSetItem> {
        self.annotation_set_item.as_ref()
    }
}

impl StructConverter for FieldAnnotationsItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        // Would call StructConverterUtil.toDataType(FieldAnnotationsItem.class)
        // and set category path. Since StructConverterUtil is a stub, we return an error.
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "FieldAnnotationsItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn new_with_zero_offset() {
        let bytes = vec![
            0x05, 0x00, 0x00, 0x00, // field_index = 5
            0x00, 0x00, 0x00, 0x00, // annotations_offset = 0
        ];
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = FieldAnnotationsItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_field_index(), 5);
        assert_eq!(item.get_annotations_offset(), 0);
        assert!(item.get_annotation_set_item().is_none());
    }

    #[test]
    fn new_with_nonzero_offset() {
        let bytes = vec![
            0x0a, 0x00, 0x00, 0x00, // field_index = 10
            0x20, 0x00, 0x00, 0x00, // annotations_offset = 32
        ];
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = FieldAnnotationsItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_field_index(), 10);
        assert_eq!(item.get_annotations_offset(), 32);
    }
}
