/// Describes the methods necessary to get a long and short representation, with or without a
/// metadata stream.
///
/// This is used in the token analyzer to cut down on duplication across modules.
/// Mirrors `ghidra.app.util.bin.format.pe.cli.CliRepresentable`.
pub trait CliRepresentable {
    /// Returns a long representation of this object.
    fn get_representation(&self) -> String;

    /// Returns a short representation of this object.
    fn get_short_representation(&self) -> String;

    /// Returns a long representation of this object, using the provided metadata stream for
    /// additional context.
    fn get_representation_with_stream(&self, stream: &dyn crate::format::seam_stubs::CliStreamMetadata) -> String;

    /// Returns a short representation of this object, using the provided metadata stream for
    /// additional context.
    fn get_short_representation_with_stream(&self, stream: &dyn crate::format::seam_stubs::CliStreamMetadata) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCliStreamMetadata;

    impl crate::format::seam_stubs::CliStreamMetadata for MockCliStreamMetadata {
        fn get_name(&self) -> String {
            "MockMetadata".to_string()
        }

        fn parse(&self) -> std::io::Result<bool> {
            Ok(true)
        }

        fn get_guid_stream(&self) -> Box<dyn crate::format::seam_stubs::CliStreamGuid> {
            unimplemented!()
        }

        fn get_user_strings_stream(&self) -> Box<dyn crate::format::seam_stubs::CliStreamUserStrings> {
            unimplemented!()
        }

        fn get_strings_stream(&self) -> Box<dyn crate::format::seam_stubs::CliStreamStrings> {
            unimplemented!()
        }

        fn get_blob_stream(&self) -> Box<dyn crate::format::seam_stubs::CliStreamBlob> {
            unimplemented!()
        }

        fn get_major_version(&self) -> i16 {
            1
        }

        fn get_minor_version(&self) -> i16 {
            0
        }

        fn get_sorted(&self) -> i64 {
            0
        }

        fn get_valid(&self) -> i64 {
            0
        }

        fn get_table(&self, _table_type: &crate::format::pe::cli::tables::cli_type_table::CliTypeTable) -> Box<dyn crate::format::seam_stubs::CliAbstractTable> {
            unimplemented!()
        }

        fn get_number_rows_for_table(&self, _table_type: &crate::format::pe::cli::tables::cli_type_table::CliTypeTable) -> i32 {
            0
        }

        fn get_string_index_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn get_guid_index_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn get_blob_index_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn get_table_index_data_type(&self, _table: &crate::format::pe::cli::tables::cli_type_table::CliTypeTable) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn markup(&self, _program: &dyn crate::format::seam_stubs::Program, _is_binary: bool, _monitor: &dyn crate::util::task::TaskMonitor, _log: &dyn crate::format::seam_stubs::MessageLog, _nt_header: &dyn crate::format::seam_stubs::NTHeader) -> std::io::Result<()> {
            Ok(())
        }

        fn to_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }
    }

    struct MockCliRepresentable;

    impl CliRepresentable for MockCliRepresentable {
        fn get_representation(&self) -> String {
            "MockRepresentation".to_string()
        }

        fn get_short_representation(&self) -> String {
            "MockShort".to_string()
        }

        fn get_representation_with_stream(&self, _stream: &dyn crate::format::seam_stubs::CliStreamMetadata) -> String {
            "MockRepresentationWithStream".to_string()
        }

        fn get_short_representation_with_stream(&self, _stream: &dyn crate::format::seam_stubs::CliStreamMetadata) -> String {
            "MockShortWithStream".to_string()
        }
    }

    #[test]
    fn test_cli_representable_trait_object() {
        let mock = MockCliRepresentable;
        assert_eq!(mock.get_representation(), "MockRepresentation");
        assert_eq!(mock.get_short_representation(), "MockShort");
    }

    #[test]
    fn test_cli_representable_with_stream() {
        let mock = MockCliRepresentable;
        let stream = MockCliStreamMetadata;
        assert_eq!(mock.get_representation_with_stream(&stream), "MockRepresentationWithStream");
        assert_eq!(mock.get_short_representation_with_stream(&stream), "MockShortWithStream");
    }
}
