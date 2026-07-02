use super::ByteBlockRange;

/// Defines a selection for byte blocks.
///
/// The selection is a list of disjoint ranges.
///
/// Port of `ghidra.app.plugin.core.format.ByteBlockSelection`.
#[derive(Clone, Default)]
pub struct ByteBlockSelection {
    list: Vec<ByteBlockRange>,
}

impl ByteBlockSelection {
    /// Construct a selection from a list of ranges.
    ///
    /// Corresponds to `new ByteBlockSelection(List<ByteBlockRange> ranges)` in Java.
    pub fn new(ranges: Vec<ByteBlockRange>) -> Self {
        Self { list: ranges }
    }

    /// Add a range to the selection.
    pub fn add(&mut self, range: ByteBlockRange) {
        self.list.push(range);
    }

    /// Get the number of byte block ranges in this selection.
    pub fn number_of_ranges(&self) -> usize {
        self.list.len()
    }

    /// Get the byte block range at the given index.
    pub fn range(&self, index: usize) -> &ByteBlockRange {
        &self.list[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::format::{ByteBlock, ByteBlockAccessException};
    use std::sync::Arc;

    struct MockByteBlock {
        len: i128,
    }

    impl ByteBlock for MockByteBlock {
        fn get_location_representation(
            &self,
            index: i128,
        ) -> Result<String, ByteBlockAccessException> {
            Ok(format!("0x{:x}", index))
        }

        fn get_max_location_representation_size(&self) -> i32 {
            16
        }

        fn get_index_name(&self) -> String {
            "Byte Offset".to_string()
        }

        fn get_length(&self) -> i128 {
            self.len
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

        fn set_short(
            &mut self,
            _index: i128,
            _value: i16,
        ) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_int(&mut self, _index: i128, _value: i32) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_long(&mut self, _index: i128, _value: i64) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn is_editable(&self) -> bool {
            true
        }

        fn set_big_endian(&mut self, _big_endian: bool) {}

        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_alignment(&self, _radix: i32) -> i32 {
            0
        }
    }

    fn make_range(start: i128, end: i128) -> ByteBlockRange {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        ByteBlockRange::new(block, start, end)
    }

    #[test]
    fn empty_selection_has_no_ranges() {
        let selection = ByteBlockSelection::default();
        assert_eq!(selection.number_of_ranges(), 0);
    }

    #[test]
    fn new_from_vec_preserves_ranges() {
        let ranges = vec![make_range(0, 5), make_range(6, 10)];
        let selection = ByteBlockSelection::new(ranges.clone());
        assert_eq!(selection.number_of_ranges(), 2);
        assert_eq!(selection.range(0), &ranges[0]);
        assert_eq!(selection.range(1), &ranges[1]);
    }

    #[test]
    fn add_appends_range() {
        let mut selection = ByteBlockSelection::default();
        // ByteBlockRange equality uses reference identity for the underlying block
        // (Java: `block == r.block`), so we must compare against the same range instance
        // rather than a freshly-built one that would hold a different block reference.
        let range = make_range(0, 5);
        selection.add(range.clone());
        assert_eq!(selection.number_of_ranges(), 1);
        assert_eq!(selection.range(0), &range);
    }
}
