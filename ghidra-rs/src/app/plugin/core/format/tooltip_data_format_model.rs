use super::ByteBlock;
use super::DataFormatModel;
use crate::app::seam_stubs::ByteViewerComponent;

/// Optional interface for `DataFormatModel`s that want to provide tooltip popups.
///
/// Port of `ghidra.app.plugin.core.format.TooltipDataFormatModel`.
pub trait TooltipDataFormatModel: DataFormatModel {
    /// Gets the tooltip text for the data at the given index in the block.
    ///
    /// # Arguments
    /// * `block` - the byte block
    /// * `index` - the byte index into the block
    /// * `comp` - the ByteViewerComponent that triggered the tooltip
    fn get_tooltip(&self, block: &dyn ByteBlock, index: i128, comp: &dyn ByteViewerComponent) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::ByteViewerConfigOptions;
    use crate::framework::seam_stubs::HelpLocation;
    use crate::util::classfinder::ExtensionPoint;

    struct StaticHelp;
    impl HelpLocation for StaticHelp {}

    struct MockByteBlock;
    impl ByteBlock for MockByteBlock {
        fn get_location_representation(&self, _index: i128) -> Result<String, crate::app::plugin::core::format::ByteBlockAccessException> {
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
        fn get_byte(&self, _index: i128) -> Result<u8, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(0)
        }
        fn get_bytes(
            &self,
            _bytes: &mut [u8],
            _index: i128,
            _count: usize,
        ) -> Result<usize, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(0)
        }
        fn get_short(&self, _index: i128) -> Result<i16, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(0)
        }
        fn get_int(&self, _index: i128) -> Result<i32, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(0)
        }
        fn get_long(&self, _index: i128) -> Result<i64, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(0)
        }
        fn set_byte(&mut self, _index: i128, _value: u8) -> Result<(), crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(())
        }
        fn set_short(&mut self, _index: i128, _value: i16) -> Result<(), crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(())
        }
        fn set_int(&mut self, _index: i128, _value: i32) -> Result<(), crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok(())
        }
        fn set_long(&mut self, _index: i128, _value: i64) -> Result<(), crate::app::plugin::core::format::ByteBlockAccessException> {
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

    struct TestTooltipModel;
    impl ExtensionPoint for TestTooltipModel {}
    impl DataFormatModel for TestTooltipModel {
        fn get_unit_byte_size(&self) -> i32 {
            1
        }
        fn get_name(&self) -> String {
            "Test".to_string()
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
        ) -> Result<String, crate::app::plugin::core::format::ByteBlockAccessException> {
            Ok("00".to_string())
        }
        fn get_unit_delimiter_size(&self) -> i32 {
            0
        }
    }
    impl TooltipDataFormatModel for TestTooltipModel {
        fn get_tooltip(&self, _block: &dyn ByteBlock, _index: i128, _comp: &dyn crate::app::seam_stubs::ByteViewerComponent) -> String {
            "Test Tooltip".to_string()
        }
    }

    struct MockByteViewerComponent;
    impl crate::app::seam_stubs::ByteViewerComponent for MockByteViewerComponent {}

    #[test]
    fn tooltip_returns_expected_string() {
        let model = TestTooltipModel;
        let block = MockByteBlock;
        let comp = MockByteViewerComponent;
        assert_eq!(model.get_tooltip(&block, 0, &comp), "Test Tooltip");
    }
}
