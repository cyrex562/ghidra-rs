use super::{ByteBlock, ByteBlockAccessException};
use crate::app::seam_stubs::ByteViewerConfigOptions;
use crate::framework::seam_stubs::HelpLocation;
use crate::util::classfinder::ExtensionPoint;

/// Interface for providing a generic way to display and edit (in various formats) memory.
///
/// NOTE: all `DataFormatModel` implementations must have a type name ending in "FormatModel".
/// If not, the class searcher will not find them.
///
/// Port of `ghidra.app.plugin.core.format.DataFormatModel`.
pub trait DataFormatModel: ExtensionPoint {
    /// Gets the number of bytes to make a unit, e.g. for 'byte' unit size = 1, for 'unicode'
    /// unit size = 2, etc.
    fn get_unit_byte_size(&self) -> i32;

    /// Gets the data format name.
    fn get_name(&self) -> String;

    /// Returns a descriptive name for this data format, used for labels / headers.
    fn get_descriptive_name(&self) -> String {
        self.get_name()
    }

    /// Gets the help location for this format.
    fn get_help_location(&self) -> Box<dyn HelpLocation>;

    /// Gets the number of characters required to display a unit. For example, an
    /// implementation for a Hex formatter may display a unit as '0xff'. The data unit size
    /// returned would be 4.
    fn get_data_unit_symbol_size(&self) -> i32;

    /// Given a character position from 0 to data unit symbol size - 1, returns a number from 0
    /// to unit byte size - 1 indicating which byte the character position was obtained from.
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: i32) -> i32;

    /// Given the byte offset into a unit, get the column position.
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: i32) -> i32;

    /// Gets the string representation at the given index in the block.
    ///
    /// # Arguments
    /// * `block` - block to change
    /// * `index` - byte index into the block
    ///
    /// # Errors
    /// Returns `Err` if the block cannot be read, or if `index` is not valid for the block.
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: i128,
    ) -> Result<String, ByteBlockAccessException>;

    /// Sets the byte viewer config options for this model. Default does nothing.
    fn set_byte_viewer_config_options(&mut self, _options: &ByteViewerConfigOptions) {
        // default do-nothing
    }

    /// Returns an error message string if the supplied `ByteViewerConfigOptions` are
    /// problematic, otherwise returns `None`.
    ///
    /// # Arguments
    /// * `candidate_options` - the candidate options to validate
    ///
    /// # Returns
    /// `None` if the candidate config options are ok, otherwise an error message.
    fn validate_byte_viewer_config_options(
        &self,
        _candidate_options: &ByteViewerConfigOptions,
    ) -> Option<String> {
        None
    }

    /// Get the number of characters separating units.
    fn get_unit_delimiter_size(&self) -> i32;

    /// Disposes of this model. Default does nothing.
    fn dispose(&mut self) {
        // do nothing by default
    }
}

/// Pads `value` on the left with `'0'` until it is `symbol_size` characters long.
///
/// Port of `DataFormatModel.pad(String, int)`.
pub fn pad(value: &str, symbol_size: i32) -> String {
    pad_with(value, symbol_size, "0")
}

/// Pads `value` on the left with `pad_char` until it is `symbol_size` characters long.
///
/// Port of `DataFormatModel.pad(String, int, String)`.
pub fn pad_with(value: &str, symbol_size: i32, pad_char: &str) -> String {
    let count = std::cmp::max(symbol_size - value.chars().count() as i32, 0) as usize;
    pad_char.repeat(count) + value
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A minimal stand-in for `HexFormatModel`: 1 byte per unit, 2 hex chars per unit, no
    /// delimiter, mirroring the shape used by the real Java implementations.
    struct HexLikeFormatModel;
    impl ExtensionPoint for HexLikeFormatModel {}
    impl DataFormatModel for HexLikeFormatModel {
        fn get_unit_byte_size(&self) -> i32 {
            1
        }
        fn get_name(&self) -> String {
            "Hex".to_string()
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
            let b = block.get_byte(index)?;
            Ok(pad(&format!("{:x}", b), 2))
        }
        fn get_unit_delimiter_size(&self) -> i32 {
            0
        }
    }

    #[test]
    fn descriptive_name_defaults_to_name() {
        let model = HexLikeFormatModel;
        assert_eq!(model.get_descriptive_name(), model.get_name());
    }

    #[test]
    fn validate_config_options_defaults_to_none() {
        let model = HexLikeFormatModel;
        let options = ByteViewerConfigOptions;
        assert_eq!(model.validate_byte_viewer_config_options(&options), None);
    }

    #[test]
    fn data_representation_matches_java_hex_formatting() {
        let model = HexLikeFormatModel;
        let block = MockByteBlock;
        assert_eq!(model.get_data_representation(&block, 0).unwrap(), "00");
    }

    #[test]
    fn pad_matches_java_default_zero_padding() {
        // DataFormatModel.pad("ff", 4) == "00ff"
        assert_eq!(pad("ff", 4), "00ff");
    }

    #[test]
    fn pad_returns_value_unchanged_when_already_long_enough() {
        assert_eq!(pad("ffff", 2), "ffff");
    }

    #[test]
    fn pad_with_uses_supplied_pad_char() {
        assert_eq!(pad_with("1", 3, "-"), "--1");
    }
}
