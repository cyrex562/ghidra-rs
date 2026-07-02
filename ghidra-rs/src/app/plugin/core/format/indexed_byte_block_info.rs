use std::cmp::Ordering;
use std::sync::Arc;

use super::{ByteBlock, ByteBlockInfo};

/// A ByteBlockInfo with line index information for ordering.
///
/// Port of `ghidra.app.plugin.core.format.IndexedByteBlockInfo`.
#[derive(Clone, Debug)]
pub struct IndexedByteBlockInfo {
    info: ByteBlockInfo,
    line_index: i128,
}

impl IndexedByteBlockInfo {
    /// Constructs a new `IndexedByteBlockInfo`.
    ///
    /// Corresponds to `new IndexedByteBlockInfo(BigInteger lineIndex, ByteBlock block,
    /// BigInteger offset, int column)` in Java.
    pub fn new(line_index: i128, block: Arc<dyn ByteBlock>, offset: i128, column: i32) -> Self {
        Self {
            info: ByteBlockInfo::with_column(block, offset, column),
            line_index,
        }
    }

    /// Get the line index.
    pub fn line_index(&self) -> i128 {
        self.line_index
    }

    /// Get the underlying ByteBlockInfo.
    pub fn byte_block_info(&self) -> &ByteBlockInfo {
        &self.info
    }
}

impl PartialEq for IndexedByteBlockInfo {
    fn eq(&self, other: &Self) -> bool {
        self.line_index == other.line_index
            && self.info.offset() == other.info.offset()
            && self.info.column() == other.info.column()
            && Arc::ptr_eq(self.info.block(), other.info.block())
    }
}

impl Eq for IndexedByteBlockInfo {}

impl PartialOrd for IndexedByteBlockInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IndexedByteBlockInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.line_index.cmp(&other.line_index) {
            Ordering::Equal => match self.info.offset().cmp(&other.info.offset()) {
                Ordering::Equal => self.info.column().cmp(&other.info.column()),
                other_ordering => other_ordering,
            },
            line_index_ordering => line_index_ordering,
        }
    }
}

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
        let info = IndexedByteBlockInfo::new(42, Arc::clone(&block), 5, 1);
        assert_eq!(info.line_index(), 42);
        assert_eq!(info.byte_block_info().offset(), 5);
        assert_eq!(info.byte_block_info().column(), 1);
    }

    #[test]
    fn compare_by_line_index_first() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let a = IndexedByteBlockInfo::new(1, Arc::clone(&block), 10, 5);
        let b = IndexedByteBlockInfo::new(2, Arc::clone(&block), 10, 5);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn compare_by_offset_when_line_index_equal() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let a = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 2);
        let b = IndexedByteBlockInfo::new(1, Arc::clone(&block), 10, 2);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn compare_by_column_when_line_index_and_offset_equal() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let a = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 1);
        let b = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 2);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn equal_when_all_fields_match() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let a = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 2);
        let b = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 2);
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_line_index_differs() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let a = IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 2);
        let b = IndexedByteBlockInfo::new(2, Arc::clone(&block), 5, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn sorting_uses_comparison_order() {
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 10 });
        let mut items = vec![
            IndexedByteBlockInfo::new(3, Arc::clone(&block), 10, 0),
            IndexedByteBlockInfo::new(1, Arc::clone(&block), 5, 0),
            IndexedByteBlockInfo::new(2, Arc::clone(&block), 8, 0),
        ];
        items.sort();
        assert_eq!(items[0].line_index(), 1);
        assert_eq!(items[1].line_index(), 2);
        assert_eq!(items[2].line_index(), 3);
    }
}
