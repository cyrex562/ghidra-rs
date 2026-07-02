use std::sync::Arc;

use super::ByteBlock;

/// Holds a block and an offset into that block.
///
/// Port of `ghidra.app.plugin.core.format.ByteBlockInfo`.
#[derive(Clone)]
pub struct ByteBlockInfo {
    block: Arc<dyn ByteBlock>,
    offset: i128,
    column: i32,
}

impl ByteBlockInfo {
    /// Constructs a new `ByteBlockInfo` with a column of 0.
    ///
    /// Corresponds to `new ByteBlockInfo(ByteBlock block, BigInteger offset)` in Java.
    pub fn new(block: Arc<dyn ByteBlock>, offset: i128) -> Self {
        Self::with_column(block, offset, 0)
    }

    /// Constructs a new `ByteBlockInfo` with the given column.
    ///
    /// Corresponds to `new ByteBlockInfo(ByteBlock block, BigInteger offset, int column)` in Java.
    pub fn with_column(block: Arc<dyn ByteBlock>, offset: i128, column: i32) -> Self {
        Self { block, offset, column }
    }

    /// Get the block.
    pub fn block(&self) -> &Arc<dyn ByteBlock> {
        &self.block
    }

    /// Get the offset into the block.
    pub fn offset(&self) -> i128 {
        self.offset
    }

    /// The column within the UI byte field.
    pub fn column(&self) -> i32 {
        self.column
    }
}

impl std::fmt::Display for ByteBlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let start = self
            .block
            .get_location_representation(0)
            .unwrap_or_default();
        write!(
            f,
            "ByteBlockInfo: block start={}, offset={}, column={}",
            start, self.offset, self.column
        )
    }
}

impl PartialEq for ByteBlockInfo {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.block, &other.block)
            && self.offset == other.offset
            && self.column == other.column
    }
}

impl Eq for ByteBlockInfo {}

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
    fn new_defaults_column_to_zero() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let info = ByteBlockInfo::new(block, 5);
        assert_eq!(info.offset(), 5);
        assert_eq!(info.column(), 0);
    }

    #[test]
    fn with_column_stores_all_fields() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let info = ByteBlockInfo::with_column(Arc::clone(&block), 7, 3);
        assert!(Arc::ptr_eq(info.block(), &block));
        assert_eq!(info.offset(), 7);
        assert_eq!(info.column(), 3);
    }

    #[test]
    fn equals_requires_same_block_offset_and_column() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let other_block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });

        let a = ByteBlockInfo::with_column(Arc::clone(&block), 1, 2);
        let b = ByteBlockInfo::with_column(Arc::clone(&block), 1, 2);
        let c = ByteBlockInfo::with_column(other_block, 1, 2);
        let d = ByteBlockInfo::with_column(Arc::clone(&block), 9, 2);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn display_matches_java_format() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let info = ByteBlockInfo::with_column(block, 4, 1);
        assert_eq!(info.to_string(), "ByteBlockInfo: block start=0x0, offset=4, column=1");
    }
}
