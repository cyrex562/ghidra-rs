use super::{ByteBlock, ByteBlockAccessException, DataFormatModel};

/// Optional interface for `DataFormatModel`s that allows the user to modify byte values using
/// the model's representation format.
///
/// Port of `ghidra.app.plugin.core.format.MutableDataFormatModel`.
pub trait MutableDataFormatModel: DataFormatModel {
    /// Overwrite a value in a `ByteBlock`.
    ///
    /// # Arguments
    /// * `block` - block to change
    /// * `index` - byte index into the block
    /// * `pos` - the position within the unit where `c` will be the new character
    /// * `c` - new character to put at `pos`
    ///
    /// # Returns
    /// `Ok(true)` if the replacement is legal, `Ok(false)` if the replacement value would not
    /// make sense for this format (e.g. attempt to put a 'z' in a hex unit).
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be updated, or
    /// `IndexOutOfBoundsException` if index is not valid for the block.
    fn replace_value(
        &mut self,
        block: &dyn ByteBlock,
        index: i128,
        pos: i32,
        c: char,
    ) -> Result<bool, ByteBlockAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;
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

    struct MockMutableFormatModel;
    impl ExtensionPoint for MockMutableFormatModel {}
    impl DataFormatModel for MockMutableFormatModel {
        fn get_unit_byte_size(&self) -> i32 {
            1
        }
        fn get_name(&self) -> String {
            "MockFormat".to_string()
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
            _block: &dyn ByteBlock,
            _index: i128,
        ) -> Result<String, ByteBlockAccessException> {
            Ok("00".to_string())
        }
        fn get_unit_delimiter_size(&self) -> i32 {
            0
        }
    }

    impl MutableDataFormatModel for MockMutableFormatModel {
        fn replace_value(
            &mut self,
            _block: &dyn ByteBlock,
            _index: i128,
            _pos: i32,
            c: char,
        ) -> Result<bool, ByteBlockAccessException> {
            if c.is_ascii_hexdigit() {
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    #[test]
    fn replace_value_accepts_hex_digits() {
        let mut model = MockMutableFormatModel;
        let block = MockByteBlock;
        let result = model.replace_value(&block, 0, 0, 'a');
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn replace_value_rejects_non_hex_characters() {
        let mut model = MockMutableFormatModel;
        let block = MockByteBlock;
        let result = model.replace_value(&block, 0, 0, 'z');
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn replace_value_with_numeric_character() {
        let mut model = MockMutableFormatModel;
        let block = MockByteBlock;
        let result = model.replace_value(&block, 0, 0, '5');
        assert_eq!(result.unwrap(), true);
    }
}
