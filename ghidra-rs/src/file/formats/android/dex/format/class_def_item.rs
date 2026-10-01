use std::fmt::Write as _;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::access_flags::AccessFlags;
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::file::seam_stubs::{
    AnnotationsDirectoryItem, ClassDataItem, DexUtil, EncodedArrayItem, TypeList,
};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Represents a class definition in DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.ClassDefItem`.
///
/// See: https://source.android.com/docs/core/runtime/dex-format#class-def-item
#[derive(Debug, Clone)]
pub struct ClassDefItem {
    class_index: i32,
    access_flags: i32,
    super_class_index: i32,
    interfaces_offset: i32,
    source_file_index: i32,
    annotations_offset: i32,
    class_data_offset: i32,
    static_values_offset: i32,

    interfaces: Option<TypeList>,
    annotations_directory_item: Option<AnnotationsDirectoryItem>,
    class_data_item: Option<ClassDataItem>,
    static_values: Option<EncodedArrayItem>,
}

impl ClassDefItem {
    /// Creates a new `ClassDefItem` by reading from a `BinaryReader`.
    ///
    /// # Arguments
    /// * `reader` - The `BinaryReader` to read from
    /// * `dex_header` - The DEX header containing file layout information
    ///
    /// # Errors
    /// Returns an I/O error if reading from the reader fails.
    pub fn new(reader: &mut BinaryReader, dex_header: &DexHeader) -> io::Result<Self> {
        let class_index = reader.read_next_int()?;
        let access_flags = reader.read_next_int()?;
        let super_class_index = reader.read_next_int()?;
        let interfaces_offset = reader.read_next_int()?;
        let source_file_index = reader.read_next_int()?;
        let annotations_offset = reader.read_next_int()?;
        let class_data_offset = reader.read_next_int()?;
        let static_values_offset = reader.read_next_int()?;

        let mut interfaces = None;
        if interfaces_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(interfaces_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create a TypeList here, but it's a stub.
                // Once TypeList is ported, this should instantiate it.
                interfaces = Some(TypeList);
            }
            reader.set_pointer_index(old_index);
        }

        let mut annotations_directory_item = None;
        if annotations_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(annotations_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create an AnnotationsDirectoryItem here, but it's a stub.
                // Once AnnotationsDirectoryItem is ported, this should instantiate it.
                annotations_directory_item = Some(AnnotationsDirectoryItem);
            }
            reader.set_pointer_index(old_index);
        }

        let mut class_data_item = None;
        if class_data_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(class_data_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create a ClassDataItem here, but it's a stub.
                // Once ClassDataItem is ported, this should instantiate it.
                class_data_item = Some(ClassDataItem);
            }
            reader.set_pointer_index(old_index);
        }

        let mut static_values = None;
        if static_values_offset > 0 {
            let old_index = reader.get_pointer_index();
            let adjusted_offset = DexUtil::adjust_offset(static_values_offset, dex_header);
            if reader.is_valid_index(adjusted_offset as u64) {
                reader.set_pointer_index(adjusted_offset as u64);
                // Note: We would create an EncodedArrayItem here, but it's a stub.
                // Once EncodedArrayItem is ported, this should instantiate it.
                static_values = Some(EncodedArrayItem);
            }
            reader.set_pointer_index(old_index);
        }

        Ok(Self {
            class_index,
            access_flags,
            super_class_index,
            interfaces_offset,
            source_file_index,
            annotations_offset,
            class_data_offset,
            static_values_offset,
            interfaces,
            annotations_directory_item,
            class_data_item,
            static_values,
        })
    }

    pub fn get_class_index(&self) -> i32 {
        self.class_index
    }

    pub fn get_access_flags(&self) -> i32 {
        self.access_flags
    }

    pub fn get_super_class_index(&self) -> i32 {
        self.super_class_index
    }

    pub fn get_interfaces_offset(&self) -> i32 {
        self.interfaces_offset
    }

    pub fn get_source_file_index(&self) -> i32 {
        self.source_file_index
    }

    /// NOTE: For CDEX files, this value is relative to `DataOffset` in `DexHeader`.
    pub fn get_annotations_offset(&self) -> i32 {
        self.annotations_offset
    }

    pub fn get_class_data_offset(&self) -> i32 {
        self.class_data_offset
    }

    pub fn get_static_values_offset(&self) -> i32 {
        self.static_values_offset
    }

    pub fn get_interfaces(&self) -> Option<&TypeList> {
        self.interfaces.as_ref()
    }

    pub fn get_annotations_directory_item(&self) -> Option<&AnnotationsDirectoryItem> {
        self.annotations_directory_item.as_ref()
    }

    pub fn get_class_data_item(&self) -> Option<&ClassDataItem> {
        self.class_data_item.as_ref()
    }

    pub fn get_static_values(&self) -> Option<&EncodedArrayItem> {
        self.static_values.as_ref()
    }

    /// Formats this class definition using `header` for name/string lookups.
    ///
    /// Mirrors `ClassDefItem.toString(DexHeader, int, TaskMonitor)`. Pass `-1` for `index` to
    /// omit the "Class Index" line.
    pub fn format(
        &self,
        header: &DexHeader,
        index: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, CancelledException> {
        let mut builder = String::new();
        if index != -1 {
            let _ = writeln!(builder, "Class Index: 0x{:x}", index);
        }
        let _ = writeln!(
            builder,
            "Class: {}",
            DexUtil::convert_type_index_to_string(header, self.get_class_index())
        );
        let _ = writeln!(
            builder,
            "Class Access Flags:\n{}",
            AccessFlags::to_string(self.get_access_flags() as u32)
        );
        let _ = writeln!(
            builder,
            "Superclass: {}",
            DexUtil::convert_type_index_to_string(header, self.get_super_class_index())
        );

        if self.get_interfaces_offset() > 0 {
            builder.push_str("Interfaces: \n");
            if let Some(interfaces) = self.get_interfaces() {
                for item in interfaces.get_items() {
                    monitor.check_cancelled()?;
                    let _ = writeln!(
                        builder,
                        "\t{}",
                        DexUtil::convert_type_index_to_string(header, item.get_type() as i32)
                    );
                }
            }
        }

        if self.get_source_file_index() > 0 {
            let _ = writeln!(
                builder,
                "Source File: {}",
                DexUtil::convert_to_string(header, self.get_source_file_index())
            );
        }

        Ok(builder)
    }
}

impl StructConverter for ClassDefItem {
    fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
        // Would call StructConverterUtil.toDataType(ClassDefItem.class), then set the category
        // path to "/dex". Since StructConverterUtil is a stub, we return an error.
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Other,
            "ClassDefItem.to_data_type requires StructConverterUtil to be ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(
        class_index: i32,
        access_flags: i32,
        super_class_index: i32,
        interfaces_offset: i32,
        source_file_index: i32,
        annotations_offset: i32,
        class_data_offset: i32,
        static_values_offset: i32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for v in [
            class_index,
            access_flags,
            super_class_index,
            interfaces_offset,
            source_file_index,
            annotations_offset,
            class_data_offset,
            static_values_offset,
        ] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn new_reads_fields_with_no_offsets() {
        let bytes = header_bytes(7, 0x1, 0, 0, 0, 0, 0, 0);
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_class_index(), 7);
        assert_eq!(item.get_access_flags(), 0x1);
        assert_eq!(item.get_super_class_index(), 0);
        assert_eq!(item.get_interfaces_offset(), 0);
        assert_eq!(item.get_source_file_index(), 0);
        assert_eq!(item.get_annotations_offset(), 0);
        assert_eq!(item.get_class_data_offset(), 0);
        assert_eq!(item.get_static_values_offset(), 0);
        assert!(item.get_interfaces().is_none());
        assert!(item.get_annotations_directory_item().is_none());
        assert!(item.get_class_data_item().is_none());
        assert!(item.get_static_values().is_none());
        // Reader position is left just past the 32-byte fixed header.
        assert_eq!(reader.get_pointer_index(), 32);
    }

    #[test]
    fn new_populates_optional_items_and_restores_pointer() {
        let mut bytes = header_bytes(1, 0, 2, 32, 5, 32, 32, 32);
        bytes.push(0); // pad so offset 32 (just past the fixed header) is a valid index
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_interfaces_offset(), 32);
        assert!(item.get_interfaces().is_some());
        assert!(item.get_annotations_directory_item().is_some());
        assert!(item.get_class_data_item().is_some());
        assert!(item.get_static_values().is_some());
        // The reader pointer is restored to just past the fixed 32-byte header after each
        // offset lookup, matching Java's try/finally save-and-restore of oldIndex.
        assert_eq!(reader.get_pointer_index(), 32);
    }

    #[test]
    fn new_skips_invalid_offset() {
        // interfacesOffset points past the end of the buffer, so no TypeList is created.
        let bytes = header_bytes(0, 0, 0, 1000, 0, 0, 0, 0);
        let mut reader = BinaryReader::from_bytes(bytes, true);
        let header = DexHeader::minimal_for_tests();

        let item = ClassDefItem::new(&mut reader, &header).unwrap();

        assert_eq!(item.get_interfaces_offset(), 1000);
        assert!(item.get_interfaces().is_none());
    }
}
