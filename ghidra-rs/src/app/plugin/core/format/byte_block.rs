use super::ByteBlockAccessException;

/// Provides access to blocks of bytes with methods for reading and writing values at various
/// sizes.
///
/// This trait represents a byte block with methods to access, retrieve, and update byte data.
/// Implementations must handle index bounds checking and can raise `ByteBlockAccessException`
/// for access violations.
///
/// Port of `ghidra.app.plugin.core.format.ByteBlock`.
pub trait ByteBlock {
    /// Get the location representation for the given index.
    ///
    /// # Arguments
    /// * `index` - byte index into this block
    ///
    /// # Errors
    /// Returns `Err` if the given index is not in this block (IndexOutOfBoundsException).
    fn get_location_representation(&self, index: i128) -> Result<String, ByteBlockAccessException>;

    /// Returns the number of characters of the largest index representation.
    fn get_max_location_representation_size(&self) -> i32;

    /// Return the name to be used for describing the indexes into the byte block.
    fn get_index_name(&self) -> String;

    /// Get the number of bytes in this block.
    fn get_length(&self) -> i128;

    /// Get the byte at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be read, or if the given
    /// index is not in this block.
    fn get_byte(&self, index: i128) -> Result<u8, ByteBlockAccessException>;

    /// Get bytes from given index.
    ///
    /// # Arguments
    /// * `bytes` - destination buffer
    /// * `index` - byte index
    /// * `count` - number of bytes to get
    ///
    /// # Returns
    /// The actual number of bytes copied into destination
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if error occurs.
    fn get_bytes(
        &self,
        bytes: &mut [u8],
        index: i128,
        count: usize,
    ) -> Result<usize, ByteBlockAccessException>;

    /// Returns true if this ByteBlock has byte values at the specified index.
    ///
    /// # Arguments
    /// * `index` - byte index
    ///
    /// # Returns
    /// `true` if has initialized values, `false` if no values.
    fn has_value(&self, _index: i128) -> bool {
        true
    }

    /// Get the short value at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be read, or if the given
    /// index is not in this block.
    fn get_short(&self, index: i128) -> Result<i16, ByteBlockAccessException>;

    /// Get the int value at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be read, or if the given
    /// index is not in this block.
    fn get_int(&self, index: i128) -> Result<i32, ByteBlockAccessException>;

    /// Get the long value at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be read, or if the given
    /// index is not in this block.
    fn get_long(&self, index: i128) -> Result<i64, ByteBlockAccessException>;

    /// Set the byte at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    /// * `value` - value to set
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be updated, or if the
    /// given index is not in this block.
    fn set_byte(&mut self, index: i128, value: u8) -> Result<(), ByteBlockAccessException>;

    /// Set the short at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    /// * `value` - value to set
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be updated, or if the
    /// given index is not in this block.
    fn set_short(&mut self, index: i128, value: i16) -> Result<(), ByteBlockAccessException>;

    /// Set the int at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    /// * `value` - value to set
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be updated, or if the
    /// given index is not in this block.
    fn set_int(&mut self, index: i128, value: i32) -> Result<(), ByteBlockAccessException>;

    /// Set the long at the given index.
    ///
    /// # Arguments
    /// * `index` - byte index
    /// * `value` - value to set
    ///
    /// # Errors
    /// Returns `Err(ByteBlockAccessException)` if the block cannot be updated, or if the
    /// given index is not in this block.
    fn set_long(&mut self, index: i128, value: i64) -> Result<(), ByteBlockAccessException>;

    /// Return true if this block can be modified.
    fn is_editable(&self) -> bool;

    /// Set the block according to the big_endian parameter.
    ///
    /// # Arguments
    /// * `big_endian` - true means big endian; false means little endian
    fn set_big_endian(&mut self, big_endian: bool);

    /// Return true if the block is big endian.
    ///
    /// # Returns
    /// `false` if the block is little endian
    fn is_big_endian(&self) -> bool;

    /// Returns the natural alignment (offset) for the given radix.
    ///
    /// If there is no natural alignment, it should return 0. A natural alignment only exists
    /// if there is some underlying indexing structure that isn't based at 0. For example, if
    /// the underlying structure is address based and the starting address is not 0, then the
    /// natural alignment is the address offset mod the radix (if the starting address is 10
    /// and the radix is 4, then the alignment is 2).
    ///
    /// # Arguments
    /// * `radix` - the radix for which to compute alignment
    ///
    /// # Returns
    /// The natural alignment offset, or 0 if no natural alignment exists
    fn get_alignment(&self, radix: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockByteBlock {
        data: Vec<u8>,
        editable: bool,
        big_endian: bool,
    }

    impl MockByteBlock {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                editable: true,
                big_endian: true,
            }
        }

        fn check_bounds(&self, index: i128, len: usize) -> Result<usize, ByteBlockAccessException> {
            if index < 0 || index as usize >= self.data.len() {
                return Err(ByteBlockAccessException::new(
                    "Index out of bounds",
                ));
            }
            let start = index as usize;
            let available = self.data.len() - start;
            Ok(std::cmp::min(available, len))
        }
    }

    impl ByteBlock for MockByteBlock {
        fn get_location_representation(&self, index: i128) -> Result<String, ByteBlockAccessException> {
            if index < 0 || index >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            Ok(format!("0x{:x}", index))
        }

        fn get_max_location_representation_size(&self) -> i32 {
            16
        }

        fn get_index_name(&self) -> String {
            "Byte Offset".to_string()
        }

        fn get_length(&self) -> i128 {
            self.data.len() as i128
        }

        fn get_byte(&self, index: i128) -> Result<u8, ByteBlockAccessException> {
            if index < 0 || index >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            Ok(self.data[index as usize])
        }

        fn get_bytes(
            &self,
            bytes: &mut [u8],
            index: i128,
            count: usize,
        ) -> Result<usize, ByteBlockAccessException> {
            let available = self.check_bounds(index, count)?;
            let start = index as usize;
            bytes[..available].copy_from_slice(&self.data[start..start + available]);
            Ok(available)
        }

        fn get_short(&self, index: i128) -> Result<i16, ByteBlockAccessException> {
            if index < 0 || index + 1 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = [self.data[start], self.data[start + 1]];
            Ok(if self.big_endian {
                i16::from_be_bytes(bytes)
            } else {
                i16::from_le_bytes(bytes)
            })
        }

        fn get_int(&self, index: i128) -> Result<i32, ByteBlockAccessException> {
            if index < 0 || index + 3 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = [
                self.data[start],
                self.data[start + 1],
                self.data[start + 2],
                self.data[start + 3],
            ];
            Ok(if self.big_endian {
                i32::from_be_bytes(bytes)
            } else {
                i32::from_le_bytes(bytes)
            })
        }

        fn get_long(&self, index: i128) -> Result<i64, ByteBlockAccessException> {
            if index < 0 || index + 7 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = [
                self.data[start],
                self.data[start + 1],
                self.data[start + 2],
                self.data[start + 3],
                self.data[start + 4],
                self.data[start + 5],
                self.data[start + 6],
                self.data[start + 7],
            ];
            Ok(if self.big_endian {
                i64::from_be_bytes(bytes)
            } else {
                i64::from_le_bytes(bytes)
            })
        }

        fn set_byte(&mut self, index: i128, value: u8) -> Result<(), ByteBlockAccessException> {
            if !self.editable {
                return Err(ByteBlockAccessException::new("Block is not editable"));
            }
            if index < 0 || index >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            self.data[index as usize] = value;
            Ok(())
        }

        fn set_short(&mut self, index: i128, value: i16) -> Result<(), ByteBlockAccessException> {
            if !self.editable {
                return Err(ByteBlockAccessException::new("Block is not editable"));
            }
            if index < 0 || index + 1 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = if self.big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            self.data[start] = bytes[0];
            self.data[start + 1] = bytes[1];
            Ok(())
        }

        fn set_int(&mut self, index: i128, value: i32) -> Result<(), ByteBlockAccessException> {
            if !self.editable {
                return Err(ByteBlockAccessException::new("Block is not editable"));
            }
            if index < 0 || index + 3 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = if self.big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            self.data[start..start + 4].copy_from_slice(&bytes);
            Ok(())
        }

        fn set_long(&mut self, index: i128, value: i64) -> Result<(), ByteBlockAccessException> {
            if !self.editable {
                return Err(ByteBlockAccessException::new("Block is not editable"));
            }
            if index < 0 || index + 7 >= self.data.len() as i128 {
                return Err(ByteBlockAccessException::new("Index out of bounds"));
            }
            let start = index as usize;
            let bytes = if self.big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            self.data[start..start + 8].copy_from_slice(&bytes);
            Ok(())
        }

        fn is_editable(&self) -> bool {
            self.editable
        }

        fn set_big_endian(&mut self, big_endian: bool) {
            self.big_endian = big_endian;
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_alignment(&self, _radix: i32) -> i32 {
            0
        }
    }

    #[test]
    fn test_get_byte() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(block.get_byte(0).unwrap(), 0x01);
        assert_eq!(block.get_byte(1).unwrap(), 0x02);
        assert_eq!(block.get_byte(2).unwrap(), 0x03);
    }

    #[test]
    fn test_get_byte_out_of_bounds() {
        let block = MockByteBlock::new(vec![0x01]);
        assert!(block.get_byte(-1).is_err());
        assert!(block.get_byte(1).is_err());
    }

    #[test]
    fn test_get_length() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(block.get_length(), 3);
    }

    #[test]
    fn test_get_short_big_endian() {
        let block = MockByteBlock::new(vec![0x12, 0x34]);
        let value = block.get_short(0).unwrap();
        assert_eq!(value, 0x1234i16);
    }

    #[test]
    fn test_get_short_little_endian() {
        let mut block = MockByteBlock::new(vec![0x12, 0x34]);
        block.set_big_endian(false);
        let value = block.get_short(0).unwrap();
        assert_eq!(value, 0x3412i16);
    }

    #[test]
    fn test_get_int_big_endian() {
        let block = MockByteBlock::new(vec![0x12, 0x34, 0x56, 0x78]);
        let value = block.get_int(0).unwrap();
        assert_eq!(value, 0x12345678i32);
    }

    #[test]
    fn test_get_int_little_endian() {
        let mut block = MockByteBlock::new(vec![0x12, 0x34, 0x56, 0x78]);
        block.set_big_endian(false);
        let value = block.get_int(0).unwrap();
        assert_eq!(value, 0x78563412i32);
    }

    #[test]
    fn test_get_long_big_endian() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let value = block.get_long(0).unwrap();
        assert_eq!(value, 0x0102030405060708i64);
    }

    #[test]
    fn test_get_long_little_endian() {
        let mut block = MockByteBlock::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        block.set_big_endian(false);
        let value = block.get_long(0).unwrap();
        assert_eq!(value, 0x0807060504030201i64);
    }

    #[test]
    fn test_set_byte() {
        let mut block = MockByteBlock::new(vec![0x00, 0x00, 0x00]);
        block.set_byte(1, 0xFF).unwrap();
        assert_eq!(block.get_byte(1).unwrap(), 0xFF);
    }

    #[test]
    fn test_set_byte_not_editable() {
        let mut block = MockByteBlock::new(vec![0x00]);
        block.editable = false;
        assert!(block.set_byte(0, 0xFF).is_err());
    }

    #[test]
    fn test_get_bytes() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03, 0x04]);
        let mut buf = [0u8; 2];
        let count = block.get_bytes(&mut buf, 1, 2).unwrap();
        assert_eq!(count, 2);
        assert_eq!(buf, [0x02, 0x03]);
    }

    #[test]
    fn test_get_bytes_partial() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03]);
        let mut buf = [0u8; 5];
        let count = block.get_bytes(&mut buf, 1, 5).unwrap();
        assert_eq!(count, 2);
        assert_eq!(&buf[..2], &[0x02, 0x03]);
    }

    #[test]
    fn test_is_big_endian() {
        let mut block = MockByteBlock::new(vec![]);
        assert!(block.is_big_endian());
        block.set_big_endian(false);
        assert!(!block.is_big_endian());
    }

    #[test]
    fn test_is_editable() {
        let mut block = MockByteBlock::new(vec![]);
        assert!(block.is_editable());
        block.editable = false;
        assert!(!block.is_editable());
    }

    #[test]
    fn test_has_value_default() {
        let block = MockByteBlock::new(vec![0x01, 0x02]);
        assert!(block.has_value(0));
        assert!(block.has_value(100)); // Default impl always returns true
    }

    #[test]
    fn test_get_location_representation() {
        let block = MockByteBlock::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let repr = block.get_location_representation(5).unwrap();
        assert_eq!(repr, "0x5");
    }

    #[test]
    fn test_get_location_representation_out_of_bounds() {
        let block = MockByteBlock::new(vec![0x01]);
        assert!(block.get_location_representation(10).is_err());
    }

    #[test]
    fn test_get_index_name() {
        let block = MockByteBlock::new(vec![]);
        assert_eq!(block.get_index_name(), "Byte Offset");
    }

    #[test]
    fn test_get_max_location_representation_size() {
        let block = MockByteBlock::new(vec![]);
        assert_eq!(block.get_max_location_representation_size(), 16);
    }

    #[test]
    fn test_get_alignment() {
        let block = MockByteBlock::new(vec![]);
        assert_eq!(block.get_alignment(4), 0);
        assert_eq!(block.get_alignment(8), 0);
    }
}
