use std::sync::Arc;

use super::ByteBlock;

/// Defines a range within a byte block.
///
/// Port of `ghidra.app.plugin.core.format.ByteBlockRange`.
#[derive(Clone)]
pub struct ByteBlockRange {
    block: Arc<dyn ByteBlock>,
    start_index: i128,
    end_index: i128,
}

impl ByteBlockRange {
    /// Constructs a new `ByteBlockRange`.
    ///
    /// Corresponds to `new ByteBlockRange(ByteBlock block, BigInteger startIndex, BigInteger
    /// endIndex)` in Java.
    pub fn new(block: Arc<dyn ByteBlock>, start_index: i128, end_index: i128) -> Self {
        Self {
            block,
            start_index,
            end_index,
        }
    }

    /// Get the byte block.
    pub fn byte_block(&self) -> &Arc<dyn ByteBlock> {
        &self.block
    }

    /// Get the start index for the range.
    pub fn start_index(&self) -> i128 {
        self.start_index
    }

    /// Get the end index (inclusive) for the range.
    pub fn end_index(&self) -> i128 {
        self.end_index
    }
}

impl std::fmt::Display for ByteBlockRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let start = self.block.get_location_representation(0).unwrap_or_default();
        write!(
            f,
            "Block at {}, startIndex=> {}, endIndex => {}",
            start, self.start_index, self.end_index
        )
    }
}

impl PartialEq for ByteBlockRange {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.block, &other.block)
            && self.start_index == other.start_index
            && self.end_index == other.end_index
    }
}

impl Eq for ByteBlockRange {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::format::ByteBlockAccessException;

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

    #[test]
    fn new_stores_all_fields() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let range = ByteBlockRange::new(Arc::clone(&block), 1, 5);
        assert!(Arc::ptr_eq(range.byte_block(), &block));
        assert_eq!(range.start_index(), 1);
        assert_eq!(range.end_index(), 5);
    }

    #[test]
    fn equals_requires_same_block_start_and_end() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let other_block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });

        let a = ByteBlockRange::new(Arc::clone(&block), 1, 5);
        let b = ByteBlockRange::new(Arc::clone(&block), 1, 5);
        let c = ByteBlockRange::new(other_block, 1, 5);
        let d = ByteBlockRange::new(Arc::clone(&block), 2, 5);
        let e = ByteBlockRange::new(Arc::clone(&block), 1, 9);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    #[test]
    fn display_matches_java_format() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let range = ByteBlockRange::new(block, 1, 5);
        assert_eq!(range.to_string(), "Block at 0x0, startIndex=> 1, endIndex => 5");
    }
}
