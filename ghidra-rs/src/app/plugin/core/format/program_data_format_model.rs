use super::DataFormatModel;
use crate::program::model::listing::program::Program;
use std::sync::Arc;

/// Interface that defines a method for setting a program.
///
/// Implementers of this trait can work with a [`Program`] that may be updated at runtime.
///
/// Port of `ghidra.app.plugin.core.format.ProgramDataFormatModel`.
pub trait ProgramDataFormatModel: DataFormatModel {
    /// Update the consumer's program with the new program.
    /// # Arguments
    /// * `program` - the program to set, or `None` to clear the program
    fn set_program(&mut self, program: Option<Arc<dyn Program>>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::ByteViewerConfigOptions;
    use crate::app::plugin::core::format::{ByteBlock, ByteBlockAccessException};
    use crate::framework::seam_stubs::HelpLocation;
    use crate::util::classfinder::ExtensionPoint;

    struct StaticHelp;
    impl HelpLocation for StaticHelp {}

    struct MockByteBlock;
    impl ByteBlock for MockByteBlock {
        fn get_location_representation(&self, _index: i128) -> Result<String, ByteBlockAccessException> {
            Ok(String::new())
        }
        fn get_max_location_representation_size(&self) -> i32 {
            0
        }
        fn get_index_name(&self) -> String {
            String::new()
        }
        fn get_length(&self) -> i128 {
            0
        }
        fn get_byte(&self, _index: i128) -> Result<u8, ByteBlockAccessException> {
            Ok(0)
        }
        fn get_bytes(
            &self,
            _bytes: &mut [u8],
            _index: i128,
            _count: usize,
        ) -> Result<usize, ByteBlockAccessException> {
            Ok(0)
        }
        fn get_short(&self, _index: i128) -> Result<i16, ByteBlockAccessException> {
            Ok(0)
        }
        fn get_int(&self, _index: i128) -> Result<i32, ByteBlockAccessException> {
            Ok(0)
        }
        fn get_long(&self, _index: i128) -> Result<i64, ByteBlockAccessException> {
            Ok(0)
        }
        fn set_byte(&mut self, _index: i128, _value: u8) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }
        fn set_short(&mut self, _index: i128, _value: i16) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }
        fn set_int(&mut self, _index: i128, _value: i32) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }
        fn set_long(&mut self, _index: i128, _value: i64) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }
        fn is_editable(&self) -> bool {
            false
        }
        fn set_big_endian(&mut self, _big_endian: bool) {}
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_alignment(&self, _radix: i32) -> i32 {
            0
        }
    }

    struct TestProgramDataFormatModel {
        program: Option<Arc<dyn Program>>,
    }

    impl ExtensionPoint for TestProgramDataFormatModel {}

    impl DataFormatModel for TestProgramDataFormatModel {
        fn get_unit_byte_size(&self) -> i32 {
            1
        }

        fn get_name(&self) -> String {
            "TestFormat".to_string()
        }

        fn get_help_location(&self) -> Box<dyn HelpLocation> {
            Box::new(StaticHelp)
        }

        fn get_data_unit_symbol_size(&self) -> i32 {
            2
        }

        fn get_byte_offset(&self, _block: &dyn ByteBlock, _position: i32) -> i32 {
            0
        }

        fn get_column_position(&self, _block: &dyn ByteBlock, byte_offset: i32) -> i32 {
            byte_offset * 2
        }

        fn get_data_representation(
            &self,
            block: &dyn ByteBlock,
            index: i128,
        ) -> Result<String, ByteBlockAccessException> {
            block.get_byte(index).map(|b| format!("{:02x}", b))
        }

        fn get_unit_delimiter_size(&self) -> i32 {
            0
        }
    }

    impl ProgramDataFormatModel for TestProgramDataFormatModel {
        fn set_program(&mut self, program: Option<Arc<dyn Program>>) {
            self.program = program;
        }
    }

    #[test]
    fn set_program_accepts_none() {
        let mut model = TestProgramDataFormatModel { program: None };
        model.set_program(None);
        assert!(model.program.is_none());
    }

    #[test]
    fn set_program_stores_program_reference() {
        let mut model = TestProgramDataFormatModel { program: None };
        model.set_program(None);
        assert!(model.program.is_none());
    }
}
