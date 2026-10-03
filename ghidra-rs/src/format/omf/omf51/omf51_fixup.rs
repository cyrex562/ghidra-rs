use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

// Reference Types
pub const REF_TYPE_LOW: i32 = 0;
pub const REF_TYPE_BYTE: i32 = 1;
pub const REF_TYPE_RELATIVE: i32 = 2;
pub const REF_TYPE_HIGH: i32 = 3;
pub const REF_TYPE_WORD: i32 = 4;
pub const REF_TYPE_INBLOCK: i32 = 5;
pub const REF_TYPE_BIT: i32 = 6;
pub const REF_TYPE_CONV: i32 = 7;

// ID Block Types
pub const ID_BLOCK_SEGMENT: i32 = 0;
pub const ID_BLOCK_RELOCATABLE: i32 = 1;
pub const ID_BLOCK_EXTERNAL: i32 = 2;

/// An OMF-51 fixup entry.
///
/// Mirrors Ghidra's `Omf51Fixup` class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Omf51Fixup {
    ref_loc: u32,
    ref_type: i8,
    block_type: i8,
    block_id: u32,
    offset: u32,
}

impl Omf51Fixup {
    /// Creates a new [`Omf51Fixup`].
    ///
    /// `reader` must be positioned at the start of the fixup. `large_block_id` is `true`
    /// if the block ID is 2 bytes, `false` if it is 1 byte.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader, large_block_id: bool) -> io::Result<Self> {
        let ref_loc = reader.read_next_unsigned_short()?;
        let ref_type = reader.read_next_byte()? as i8;
        let block_type = reader.read_next_byte()? as i8;
        let block_id = if large_block_id {
            reader.read_next_unsigned_short()?
        } else {
            reader.read_next_unsigned_byte()? as u32
        };
        let offset = reader.read_next_unsigned_short()?;

        Ok(Omf51Fixup {
            ref_loc,
            ref_type,
            block_type,
            block_id,
            offset,
        })
    }

    /// Returns the reference location (REFLOC).
    pub fn ref_loc(&self) -> i32 {
        self.ref_loc as i32
    }

    /// Returns the reference type (REF TYP).
    pub fn ref_type(&self) -> i32 {
        self.ref_type as i32
    }

    /// Returns the operand block type (ID BLK).
    pub fn block_type(&self) -> i32 {
        self.block_type as i32
    }

    /// Returns the operand id (segment ID or EXT ID).
    pub fn block_id(&self) -> i32 {
        self.block_id as i32
    }

    /// Returns the operand offset.
    pub fn offset(&self) -> i32 {
        self.offset as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_small_block_id_fixup() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0x1234u16).to_le_bytes());
        data.push(REF_TYPE_BYTE as u8);
        data.push(ID_BLOCK_SEGMENT as u8);
        data.push(7u8); // small block id
        data.extend_from_slice(&(0x00ABu16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let fixup = Omf51Fixup::new(&mut r, false).unwrap();

        assert_eq!(fixup.ref_loc(), 0x1234);
        assert_eq!(fixup.ref_type(), REF_TYPE_BYTE);
        assert_eq!(fixup.block_type(), ID_BLOCK_SEGMENT);
        assert_eq!(fixup.block_id(), 7);
        assert_eq!(fixup.offset(), 0x00AB);
    }

    #[test]
    fn reads_large_block_id_fixup() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0x5678u16).to_le_bytes());
        data.push(REF_TYPE_WORD as u8);
        data.push(ID_BLOCK_EXTERNAL as u8);
        data.extend_from_slice(&(0x0102u16).to_le_bytes()); // large block id
        data.extend_from_slice(&(0xFFFFu16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let fixup = Omf51Fixup::new(&mut r, true).unwrap();

        assert_eq!(fixup.ref_loc(), 0x5678);
        assert_eq!(fixup.ref_type(), REF_TYPE_WORD);
        assert_eq!(fixup.block_type(), ID_BLOCK_EXTERNAL);
        assert_eq!(fixup.block_id(), 0x0102);
        assert_eq!(fixup.offset(), 0xFFFF);
    }

    #[test]
    fn updates_reader_position_small_block_id() {
        let mut data = Vec::new();
        data.extend_from_slice(&(1u16).to_le_bytes());
        data.push(0);
        data.push(0);
        data.push(0);
        data.extend_from_slice(&(0u16).to_le_bytes());
        data.push(99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = Omf51Fixup::new(&mut r, false).unwrap();
        // 2 (ref_loc) + 1 (ref_type) + 1 (block_type) + 1 (small block_id) + 2 (offset) = 7
        assert_eq!(r.get_pointer_index(), 7);
    }

    #[test]
    fn updates_reader_position_large_block_id() {
        let mut data = Vec::new();
        data.extend_from_slice(&(1u16).to_le_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&(0u16).to_le_bytes());
        data.extend_from_slice(&(0u16).to_le_bytes());
        data.push(99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = Omf51Fixup::new(&mut r, true).unwrap();
        // 2 (ref_loc) + 1 (ref_type) + 1 (block_type) + 2 (large block_id) + 2 (offset) = 8
        assert_eq!(r.get_pointer_index(), 8);
    }

    #[test]
    fn ref_type_and_block_type_sign_extend_like_java_byte() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0u16).to_le_bytes());
        data.push(0xFF); // -1 as a signed Java byte
        data.push(0x80); // -128 as a signed Java byte
        data.push(0);
        data.extend_from_slice(&(0u16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let fixup = Omf51Fixup::new(&mut r, false).unwrap();

        assert_eq!(fixup.ref_type(), -1);
        assert_eq!(fixup.block_type(), -128);
    }
}
