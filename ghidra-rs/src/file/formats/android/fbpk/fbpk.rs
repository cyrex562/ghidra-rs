use crate::app::util::bin::struct_converter::StructConverter;
use crate::file::seam_stubs::FBPK_Partition;
use crate::program::model::address::Address;
use crate::format::seam_stubs::Program;
use crate::util::task::TaskMonitor;

/// Base interface to represent an FBPK (Facebook Package).
///
/// Port of `ghidra.file.formats.android.fbpk.FBPK`.
pub trait FBPK: StructConverter {
    /// Returns the MAGIC value.
    ///
    /// # Returns
    /// The MAGIC value
    fn get_magic(&self) -> i32;

    /// Returns the version.
    ///
    /// # Returns
    /// The version
    fn get_version(&self) -> i32;

    /// Returns the list of partitions.
    ///
    /// # Returns
    /// The list of partitions
    fn get_partitions(&self) -> Vec<Box<dyn FBPK_Partition>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockFbpkPartition;

    impl FBPK_Partition for MockFbpkPartition {
        fn get_header_size(&self) -> i32 {
            512
        }

        fn get_type(&self) -> i32 {
            1
        }

        fn get_name(&self) -> String {
            "test_partition".to_string()
        }

        fn get_data_start_offset(&self) -> i64 {
            1024
        }

        fn get_data_size(&self) -> i32 {
            2048
        }

        fn is_file(&self) -> bool {
            true
        }

        fn get_offset_to_next_partition_table(&self) -> i32 {
            4096
        }

        fn get_partition_index(&self) -> i32 {
            0
        }

        fn markup(
            &self,
            _program: &dyn Program,
            _address: &Address,
            _monitor: &dyn TaskMonitor,
            _log: &dyn crate::format::seam_stubs::MessageLog,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MockFbpk;

    impl StructConverter for MockFbpk {
        fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl FBPK for MockFbpk {
        fn get_magic(&self) -> i32 {
            0x4642504b
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_partitions(&self) -> Vec<Box<dyn FBPK_Partition>> {
            vec![Box::new(MockFbpkPartition)]
        }
    }

    #[test]
    fn fbpk_trait_is_object_safe() {
        let fbpk: Box<dyn FBPK> = Box::new(MockFbpk);
        assert_eq!(fbpk.get_magic(), 0x4642504b);
        assert_eq!(fbpk.get_version(), 1);
        assert_eq!(fbpk.get_partitions().len(), 1);
    }

    #[test]
    fn fbpk_implements_struct_converter() {
        let fbpk: Box<dyn StructConverter> = Box::new(MockFbpk);
        assert!(fbpk.to_data_type().is_ok());
    }

    #[test]
    fn fbpk_partition_methods() {
        let partition: Box<dyn FBPK_Partition> = Box::new(MockFbpkPartition);
        assert_eq!(partition.get_header_size(), 512);
        assert_eq!(partition.get_type(), 1);
        assert_eq!(partition.get_name(), "test_partition");
        assert_eq!(partition.get_data_start_offset(), 1024);
        assert_eq!(partition.get_data_size(), 2048);
        assert!(partition.is_file());
        assert_eq!(partition.get_offset_to_next_partition_table(), 4096);
        assert_eq!(partition.get_partition_index(), 0);
    }
}
