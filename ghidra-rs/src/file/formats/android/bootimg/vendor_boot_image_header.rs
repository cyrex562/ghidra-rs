use std::io;

use crate::app::util::bin::struct_converter::StructConverter;

/// Base class to represent a Vendor Boot Image header.
///
/// Port of `ghidra.file.formats.android.bootimg.VendorBootImageHeader`.
pub trait VendorBootImageHeader: StructConverter {
    /// Returns the magic string identifying the vendor boot image.
    ///
    /// # Returns
    /// The magic string
    fn get_magic(&self) -> &str;

    /// Returns the offset of the vendor ramdisk.
    ///
    /// # Returns
    /// The vendor ramdisk offset
    fn get_vendor_ramdisk_offset(&self) -> i64;

    /// Returns the size of the vendor ramdisk.
    ///
    /// # Returns
    /// The vendor ramdisk size
    fn get_vendor_ramdisk_size(&self) -> i32;

    /// Returns the offset of the device tree blob.
    ///
    /// # Returns
    /// The DTB offset
    fn get_dtb_offset(&self) -> i64;

    /// Returns the size of the device tree blob.
    ///
    /// # Returns
    /// The DTB size
    fn get_dtb_size(&self) -> i32;

    /// Returns the number of nested vendor ramdisks.
    ///
    /// Default implementation returns 1.
    ///
    /// # Returns
    /// The nested vendor ramdisk count
    fn get_nested_vendor_ramdisk_count(&self) -> i64 {
        1
    }

    /// Returns the offset of the nested vendor ramdisk at the specified index.
    ///
    /// Default implementation returns [`get_vendor_ramdisk_offset`](Self::get_vendor_ramdisk_offset).
    ///
    /// # Arguments
    /// * `index` - The nested vendor ramdisk index
    ///
    /// # Returns
    /// The nested vendor ramdisk offset at the specified index, or an I/O error
    fn get_nested_vendor_ramdisk_offset(&self, _index: i32) -> io::Result<i64> {
        Ok(self.get_vendor_ramdisk_offset())
    }

    /// Returns the size of the nested vendor ramdisk at the specified index.
    ///
    /// Default implementation returns [`get_vendor_ramdisk_size`](Self::get_vendor_ramdisk_size).
    ///
    /// # Arguments
    /// * `index` - The nested vendor ramdisk index
    ///
    /// # Returns
    /// The nested vendor ramdisk size at the specified index, or an I/O error
    fn get_nested_vendor_ramdisk_size(&self, _index: i32) -> io::Result<i32> {
        Ok(self.get_vendor_ramdisk_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockVendorBootImageHeader {
        magic: String,
        vendor_ramdisk_offset: i64,
        vendor_ramdisk_size: i32,
        dtb_offset: i64,
        dtb_size: i32,
    }

    impl MockVendorBootImageHeader {
        fn new(
            magic: &str,
            vendor_ramdisk_offset: i64,
            vendor_ramdisk_size: i32,
            dtb_offset: i64,
            dtb_size: i32,
        ) -> Self {
            Self {
                magic: magic.to_string(),
                vendor_ramdisk_offset,
                vendor_ramdisk_size,
                dtb_offset,
                dtb_size,
            }
        }
    }

    impl StructConverter for MockVendorBootImageHeader {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl VendorBootImageHeader for MockVendorBootImageHeader {
        fn get_magic(&self) -> &str {
            &self.magic
        }

        fn get_vendor_ramdisk_offset(&self) -> i64 {
            self.vendor_ramdisk_offset
        }

        fn get_vendor_ramdisk_size(&self) -> i32 {
            self.vendor_ramdisk_size
        }

        fn get_dtb_offset(&self) -> i64 {
            self.dtb_offset
        }

        fn get_dtb_size(&self) -> i32 {
            self.dtb_size
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable() {
        let header: Box<dyn VendorBootImageHeader> = Box::new(MockVendorBootImageHeader::new(
            "VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100,
        ));
        assert_eq!(header.get_magic(), "VNDRBOOT");
        assert_eq!(header.get_vendor_ramdisk_offset(), 0x1000);
        assert_eq!(header.get_vendor_ramdisk_size(), 0x200);
        assert_eq!(header.get_dtb_offset(), 0x1200);
        assert_eq!(header.get_dtb_size(), 0x100);
    }

    #[test]
    fn get_magic_returns_correct_value() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_magic(), "VNDRBOOT");
    }

    #[test]
    fn get_vendor_ramdisk_offset_returns_correct_value() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_vendor_ramdisk_offset(), 0x1000);
    }

    #[test]
    fn get_vendor_ramdisk_size_returns_correct_value() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_vendor_ramdisk_size(), 0x200);
    }

    #[test]
    fn get_dtb_offset_returns_correct_value() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_dtb_offset(), 0x1200);
    }

    #[test]
    fn get_dtb_size_returns_correct_value() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_dtb_size(), 0x100);
    }

    #[test]
    fn get_nested_vendor_ramdisk_count_default_returns_one() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_nested_vendor_ramdisk_count(), 1);
    }

    #[test]
    fn get_nested_vendor_ramdisk_offset_default_returns_vendor_ramdisk_offset() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        let result = header.get_nested_vendor_ramdisk_offset(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1000);
    }

    #[test]
    fn get_nested_vendor_ramdisk_size_default_returns_vendor_ramdisk_size() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        let result = header.get_nested_vendor_ramdisk_size(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x200);
    }

    #[test]
    fn get_nested_vendor_ramdisk_offset_with_different_indices() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        let result1 = header.get_nested_vendor_ramdisk_offset(0);
        let result2 = header.get_nested_vendor_ramdisk_offset(5);
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn get_nested_vendor_ramdisk_size_with_different_indices() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        let result1 = header.get_nested_vendor_ramdisk_size(0);
        let result2 = header.get_nested_vendor_ramdisk_size(10);
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn struct_converter_trait_is_implemented() {
        let header: Box<dyn VendorBootImageHeader> = Box::new(MockVendorBootImageHeader::new(
            "VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100,
        ));
        assert!(header.to_data_type().is_ok());
    }

    #[test]
    fn get_magic_with_empty_string() {
        let header = MockVendorBootImageHeader::new("", 0x1000, 0x200, 0x1200, 0x100);
        assert_eq!(header.get_magic(), "");
    }

    #[test]
    fn all_offsets_and_sizes_zero() {
        let header = MockVendorBootImageHeader::new("VNDRBOOT", 0, 0, 0, 0);
        assert_eq!(header.get_vendor_ramdisk_offset(), 0);
        assert_eq!(header.get_vendor_ramdisk_size(), 0);
        assert_eq!(header.get_dtb_offset(), 0);
        assert_eq!(header.get_dtb_size(), 0);
    }

    #[test]
    fn all_offsets_and_sizes_large_values() {
        let header = MockVendorBootImageHeader::new(
            "VNDRBOOT",
            0x7fffffffffffffff,
            0x7fffffff,
            0x7fffffffffffffff,
            0x7fffffff,
        );
        assert_eq!(header.get_vendor_ramdisk_offset(), 0x7fffffffffffffff);
        assert_eq!(header.get_vendor_ramdisk_size(), 0x7fffffff);
        assert_eq!(header.get_dtb_offset(), 0x7fffffffffffffff);
        assert_eq!(header.get_dtb_size(), 0x7fffffff);
    }

    #[test]
    fn multiple_instances_with_different_values() {
        let header1 = MockVendorBootImageHeader::new("VNDRBOOT", 0x1000, 0x200, 0x1200, 0x100);
        let header2 = MockVendorBootImageHeader::new("VNDRBT2", 0x2000, 0x300, 0x2200, 0x200);
        assert_ne!(header1.get_magic(), header2.get_magic());
        assert_ne!(
            header1.get_vendor_ramdisk_offset(),
            header2.get_vendor_ramdisk_offset()
        );
        assert_ne!(
            header1.get_vendor_ramdisk_size(),
            header2.get_vendor_ramdisk_size()
        );
    }
}
