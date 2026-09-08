//! Port of the class `ghidra.program.database.mem.ByteMappingScheme`.
//!
//! Facilitates a byte mapping/decimation scheme for a byte-mapped sub-block onto an underlying
//! source memory region: a repeating N:M ratio of "mapped" bytes (visible in the mapped
//! sub-block) to "source" bytes consumed from the source memory range (mapped bytes followed by
//! skipped/non-mapped bytes). A 1:1 (or `0`-encoded) scheme is the common case and is
//! special-cased throughout to avoid the decimation arithmetic entirely.
//!
//! Java's `getBytes`/`setBytes` take a `Memory` parameter and use its `getBytes(Address, byte[])`
//! / `setBytes(Address, byte[], int, int)` overloads. This port's
//! [`Memory`](crate::program::model::mem::Memory) trait only exposes whole-slice
//! `get_bytes(&self, addr, dest: &mut [u8]) -> usize` (no exception; returns actual count read)
//! and `set_bytes(&mut self, addr, source: &[u8]) -> Result<(), MemoryAccessException>` (whole
//! slice, `&mut self`), so [`get_bytes`](ByteMappingScheme::get_bytes)/
//! [`set_bytes`](ByteMappingScheme::set_bytes) pass `&buf[off..off + len]`/`&mut buf[off..off +
//! len]` sub-slices to get the same offset/length behavior Java's array-offset overloads
//! provide, and `set_bytes` here takes `&mut dyn Memory` to satisfy that trait's `&mut self`
//! receiver (Java's `Memory` reference needs no such distinction).

use std::error::Error;
use std::fmt;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};

/// Error type aggregating the exceptions thrown by Java's `ByteMappingScheme` methods
/// (`IllegalArgumentException` for negative offsets/invalid ratios, `AddressOverflowException`
/// for address arithmetic overflow, and `MemoryAccessException` propagated from `Memory` writes).
#[derive(Debug)]
pub enum ByteMappingSchemeError {
    /// Mirrors `IllegalArgumentException`.
    IllegalArgument(String),
    /// Mirrors `AddressOverflowException`.
    AddressOverflow(AddressOverflowException),
    /// Mirrors `MemoryAccessException`, propagated from a `Memory` write.
    MemoryAccess(MemoryAccessException),
}

impl fmt::Display for ByteMappingSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalArgument(msg) => write!(f, "illegal argument: {msg}"),
            Self::AddressOverflow(err) => write!(f, "{err}"),
            Self::MemoryAccess(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ByteMappingSchemeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AddressOverflow(err) => Some(err),
            Self::MemoryAccess(err) => Some(err),
            _ => None,
        }
    }
}

impl From<AddressOverflowException> for ByteMappingSchemeError {
    fn from(err: AddressOverflowException) -> Self {
        Self::AddressOverflow(err)
    }
}

impl From<MemoryAccessException> for ByteMappingSchemeError {
    fn from(err: MemoryAccessException) -> Self {
        Self::MemoryAccess(err)
    }
}

/// Facilitates a byte mapping/decimation scheme for a mapped sub-block onto an underlying source
/// memory region. Mirrors `ghidra.program.database.mem.ByteMappingScheme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteMappingScheme {
    mapped_byte_count: i32,
    non_mapped_byte_count: i32,
    mapped_source_byte_count: i32,
}

impl ByteMappingScheme {
    /// Construct a byte mapping scheme from an encoded mapping scheme value. `0` is accepted (and
    /// means a 1:1 default mapping) for backward compatibility with pre-existing byte-mapped
    /// blocks. Mirrors the package-private `ByteMappingScheme(int)` constructor.
    pub fn from_encoded(encoded_mapping_scheme: i32) -> Result<Self, ByteMappingSchemeError> {
        if encoded_mapping_scheme == 0 {
            return Ok(Self {
                mapped_byte_count: 1,
                mapped_source_byte_count: 1,
                non_mapped_byte_count: 0,
            });
        }
        let mapped_byte_count = Self::decode_mapped_byte_count(encoded_mapping_scheme);
        let mapped_source_byte_count = Self::decode_mapped_source_byte_count(encoded_mapping_scheme);
        let non_mapped_byte_count = mapped_source_byte_count - mapped_byte_count;
        Self::validate_mapping_scheme(mapped_byte_count, mapped_source_byte_count)?;
        Ok(Self {
            mapped_byte_count,
            non_mapped_byte_count,
            mapped_source_byte_count,
        })
    }

    /// Construct a byte mapping scheme specified as a ratio of mapped bytes to source bytes.
    /// `mapped_byte_count` (1..127) must be less-than-or-equal to `mapped_source_byte_count`
    /// (1..127). Mirrors `ByteMappingScheme(int, int)`.
    pub fn new(mapped_byte_count: i32, mapped_source_byte_count: i32) -> Result<Self, ByteMappingSchemeError> {
        Self::validate_mapping_scheme(mapped_byte_count, mapped_source_byte_count)?;
        Ok(Self {
            mapped_byte_count,
            mapped_source_byte_count,
            non_mapped_byte_count: mapped_source_byte_count - mapped_byte_count,
        })
    }

    /// Construct a byte mapping scheme specified as a ratio in string form (e.g. `"2:4"`).
    /// Mirrors `ByteMappingScheme(String)`.
    pub fn from_ratio_str(mapping_scheme: &str) -> Result<Self, ByteMappingSchemeError> {
        let invalid = || ByteMappingSchemeError::IllegalArgument(format!("invalid mapping scheme: {mapping_scheme}"));
        let index = mapping_scheme.find(':').ok_or_else(invalid)?;
        let mapped_byte_count_str = &mapping_scheme[..index];
        let source_byte_count_str = &mapping_scheme[index + 1..];

        let mapped_byte_count: i32 = mapped_byte_count_str.parse().map_err(|_| invalid())?;
        let mapped_source_byte_count: i32 = source_byte_count_str.parse().map_err(|_| invalid())?;

        Self::validate_mapping_scheme(mapped_byte_count, mapped_source_byte_count)?;
        Ok(Self {
            mapped_byte_count,
            mapped_source_byte_count,
            non_mapped_byte_count: mapped_source_byte_count - mapped_byte_count,
        })
    }

    /// Get byte mapping scheme as a single 14-bit packed value for storage and reconstruction
    /// use. Mirrors the package-private `getEncodedMappingScheme()`.
    pub fn get_encoded_mapping_scheme(&self) -> i32 {
        if self.is_one_to_one_mapping() {
            // for legacy reasons continue to use 0 to indicate 1:1 default mapping
            return 0;
        }
        Self::encode_mapping_scheme(self.mapped_byte_count, self.mapped_source_byte_count)
            .expect("scheme was already validated at construction")
    }

    /// Determine if this scheme corresponds to a 1:1 byte mapping. Mirrors
    /// `isOneToOneMapping()`.
    pub const fn is_one_to_one_mapping(&self) -> bool {
        self.mapped_source_byte_count <= 1
    }

    /// Get the mapped-byte-count (left-hand value in mapping ratio). Mirrors
    /// `getMappedByteCount()`.
    pub const fn get_mapped_byte_count(&self) -> i32 {
        if self.is_one_to_one_mapping() {
            1
        }
        else {
            self.mapped_byte_count
        }
    }

    /// Get the mapped-source-byte-count (right-hand value in mapping ratio). Mirrors
    /// `getMappedSourceByteCount()`.
    pub const fn get_mapped_source_byte_count(&self) -> i32 {
        if self.is_one_to_one_mapping() {
            1
        }
        else {
            self.mapped_source_byte_count
        }
    }

    /// Calculate the mapped source address for a specified offset within the mapped sub-block.
    /// Mirrors `getMappedSourceAddress(Address, long)`.
    pub fn get_mapped_source_address(
        &self,
        mapped_source_base_address: &Address,
        offset_in_sub_block: i64,
    ) -> Result<Address, ByteMappingSchemeError> {
        if offset_in_sub_block < 0 {
            return Err(ByteMappingSchemeError::IllegalArgument("negative offset".to_string()));
        }
        let source_offset = if self.is_one_to_one_mapping() {
            offset_in_sub_block
        }
        else {
            (self.mapped_source_byte_count as i64 * (offset_in_sub_block / self.mapped_byte_count as i64))
                + (offset_in_sub_block % self.mapped_byte_count as i64)
        };
        Ok(mapped_source_base_address.add_no_wrap(source_offset)?)
    }

    /// Calculate the address within a mapped block for a specified mapped source offset. If the
    /// specified `mapped_source_offset` corresponds to a non-mapped (skipped) byte, the address
    /// returned corresponds to the previous mapped address if `skip_back` is true, or `None` (if
    /// unable to map within block limits) or the next mapped address otherwise. Mirrors the
    /// package-private `getMappedAddress(MemoryBlock, long, boolean)`.
    pub fn get_mapped_address(
        &self,
        mapped_block: &dyn MemoryBlock,
        mapped_source_offset: i64,
        skip_back: bool,
    ) -> Result<Option<Address>, ByteMappingSchemeError> {
        if mapped_source_offset < 0 {
            return Err(ByteMappingSchemeError::IllegalArgument("negative source offset".to_string()));
        }
        let mut mapped_offset = mapped_source_offset;
        if !self.is_one_to_one_mapping() {
            mapped_offset = self.mapped_byte_count as i64 * (mapped_source_offset / self.mapped_source_byte_count as i64);
            let offset_limit = mapped_block.get_size() as i64 - 1;
            let modulus = mapped_source_offset % self.mapped_source_byte_count as i64;
            if modulus < self.mapped_byte_count as i64 {
                mapped_offset += modulus;
            }
            else if !skip_back {
                mapped_offset += self.mapped_byte_count as i64;
                if mapped_offset > offset_limit {
                    return Ok(None);
                }
            }
        }
        let addr = mapped_block.get_start().add_no_wrap(mapped_offset)?;
        Ok(Some(addr))
    }

    /// Read bytes into `b[off..off+len]` from `memory` utilizing this mapping scheme, starting
    /// `offset_in_sub_block` bytes into the mapped sub-block. Returns the actual number of bytes
    /// read. Mirrors the package-private `getBytes(Memory, Address, long, byte[], int, int)`.
    #[allow(clippy::too_many_arguments)]
    pub fn get_bytes(
        &self,
        memory: &dyn Memory,
        mapped_source_base_address: &Address,
        offset_in_sub_block: i64,
        b: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, ByteMappingSchemeError> {
        if self.is_one_to_one_mapping() {
            let addr = mapped_source_base_address.add_no_wrap(offset_in_sub_block)?;
            return Ok(memory.get_bytes(&addr, &mut b[off..off + len]));
        }

        // NOTE: approach avoids incremental reading by including unmapped bytes in bulk read
        // and filters as needed based upon mapping scheme ratio
        let pattern_count = offset_in_sub_block / self.mapped_byte_count as i64;
        let partial_byte_count = (offset_in_sub_block % self.mapped_byte_count as i64) as i32;
        let mapped_offset = (self.mapped_source_byte_count as i64 * pattern_count) + partial_byte_count as i64;

        let buf_size = self.mapped_source_byte_count as usize * ((len / self.mapped_byte_count as usize) + 1);
        let mut buf = vec![0u8; buf_size];
        let src_addr = mapped_source_base_address.add_no_wrap(mapped_offset)?;
        let buf_cnt = memory.get_bytes(&src_addr, &mut buf);
        let mut buf_index = 0usize;

        let mut cnt = 0usize;
        let mut index = off;
        let mut i = self.mapped_byte_count - partial_byte_count;
        let mut skip = false;
        while buf_index < buf_cnt && cnt < len {
            if !skip {
                b[index] = buf[buf_index];
                index += 1;
                cnt += 1;
                i -= 1;
                if i == 0 {
                    skip = true;
                    i = self.non_mapped_byte_count;
                }
            }
            else {
                i -= 1;
                if i == 0 {
                    skip = false;
                    i = self.mapped_byte_count;
                }
            }
            buf_index += 1;
        }
        Ok(cnt)
    }

    /// Write `b[off..off+len]` to `memory` utilizing this mapping scheme, starting
    /// `offset_in_sub_block` bytes into the mapped sub-block. Mirrors the package-private
    /// `setBytes(Memory, Address, long, byte[], int, int)`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_bytes(
        &self,
        memory: &mut dyn Memory,
        mapped_source_base_address: &Address,
        offset_in_sub_block: i64,
        b: &[u8],
        off: usize,
        len: usize,
    ) -> Result<(), ByteMappingSchemeError> {
        if self.is_one_to_one_mapping() {
            let addr = mapped_source_base_address.add_no_wrap(offset_in_sub_block)?;
            memory.set_bytes(&addr, &b[off..off + len])?;
            return Ok(());
        }

        let pattern_count = offset_in_sub_block / self.mapped_byte_count as i64;
        let partial_byte_count = (offset_in_sub_block % self.mapped_byte_count as i64) as i32;
        let mapped_offset = (self.mapped_source_byte_count as i64 * pattern_count) + partial_byte_count as i64;

        let mut dest_addr = mapped_source_base_address.add_no_wrap(mapped_offset)?;

        let mut index = off;
        let mut cnt = 0usize;
        let mut i = self.mapped_byte_count - partial_byte_count;
        while cnt < len {
            let i_usize = i as usize;
            memory.set_bytes(&dest_addr, &b[index..index + i_usize])?;
            index += i_usize;
            cnt += i_usize;
            dest_addr = dest_addr.add_no_wrap(i as i64 + self.non_mapped_byte_count as i64)?;
            i = self.mapped_byte_count;
        }
        Ok(())
    }

    /// Validate a mapping scheme specified as a ratio of mapped bytes to source bytes. Mirrors
    /// the package-private static `validateMappingScheme(int, int)`.
    pub fn validate_mapping_scheme(
        scheme_dest_byte_count: i32,
        scheme_src_byte_count: i32,
    ) -> Result<(), ByteMappingSchemeError> {
        if scheme_dest_byte_count <= 0
            || scheme_dest_byte_count > 0x7F
            || scheme_src_byte_count <= 0
            || scheme_src_byte_count > 0x7F
            || scheme_dest_byte_count > scheme_src_byte_count
        {
            return Err(ByteMappingSchemeError::IllegalArgument(format!(
                "invalid byte mapping ratio: {scheme_dest_byte_count}:{scheme_src_byte_count}"
            )));
        }
        Ok(())
    }

    /// Get encoded mapping scheme as a single value for storage purposes: two 7-bit values
    /// corresponding to the destination and source byte counts. Mirrors the package-private
    /// static `getEncodedMappingScheme(int, int)`.
    pub fn encode_mapping_scheme(
        scheme_dest_byte_count: i32,
        scheme_src_byte_count: i32,
    ) -> Result<i32, ByteMappingSchemeError> {
        Self::validate_mapping_scheme(scheme_dest_byte_count, scheme_src_byte_count)?;
        Ok((scheme_dest_byte_count << 7) | (scheme_src_byte_count & 0x7F))
    }

    /// Extract the mapping scheme mapped-byte-count from an encoded mapping scheme value.
    /// Mirrors the package-private static `getMappedByteCount(int)`.
    fn decode_mapped_byte_count(mapping_scheme: i32) -> i32 {
        if mapping_scheme == 0 {
            1
        }
        else {
            (mapping_scheme >> 7) & 0x7F
        }
    }

    /// Extract the mapping ratio mapped-source-byte-count from an encoded mapping scheme value.
    /// Mirrors the package-private static `getMappedSourceByteCount(int)`.
    fn decode_mapped_source_byte_count(mapping_scheme: i32) -> i32 {
        if mapping_scheme == 0 {
            1
        }
        else {
            mapping_scheme & 0x7F
        }
    }
}

impl fmt::Display for ByteMappingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_one_to_one_mapping() {
            write!(f, "1:1 mapping")
        }
        else {
            write!(f, "{}:{} mapping", self.mapped_byte_count, self.mapped_source_byte_count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::{Arc, Mutex};

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Simple flat in-memory `Memory` used to exercise `get_bytes`/`set_bytes` mapping
    /// arithmetic end to end.
    struct FlatMemory {
        base: i64,
        data: Mutex<Vec<u8>>,
    }

    impl FlatMemory {
        fn new(base: i64, data: Vec<u8>) -> Self {
            Self { base, data: Mutex::new(data) }
        }
    }

    impl Memory for FlatMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let idx = (addr.offset() - self.base) as usize;
            self.data
                .lock()
                .unwrap()
                .get(idx)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let idx = (addr.offset() - self.base) as usize;
            let data = self.data.lock().unwrap();
            let available = data.len().saturating_sub(idx);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&data[idx..idx + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let idx = (addr.offset() - self.base) as usize;
            let mut data = self.data.lock().unwrap();
            if idx + source.len() > data.len() {
                return Err(MemoryAccessException::new("out of range"));
            }
            data[idx..idx + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    struct MockBlock {
        start: Address,
        size: u64,
    }

    impl MemoryBlock for MockBlock {
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            self.start.add(self.size as i64 - 1).unwrap()
        }
        fn get_size(&self) -> u64 {
            self.size
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    #[test]
    fn zero_encoded_scheme_is_one_to_one() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        assert!(scheme.is_one_to_one_mapping());
        assert_eq!(scheme.get_mapped_byte_count(), 1);
        assert_eq!(scheme.get_mapped_source_byte_count(), 1);
        assert_eq!(scheme.get_encoded_mapping_scheme(), 0);
        assert_eq!(scheme.to_string(), "1:1 mapping");
    }

    #[test]
    fn validate_rejects_bad_ratios() {
        assert!(ByteMappingScheme::new(0, 1).is_err());
        assert!(ByteMappingScheme::new(1, 0).is_err());
        assert!(ByteMappingScheme::new(3, 2).is_err());
        assert!(ByteMappingScheme::new(0x80, 1).is_err());
        assert!(ByteMappingScheme::new(1, 0x80).is_err());
        assert!(ByteMappingScheme::new(2, 4).is_ok());
    }

    #[test]
    fn encode_decode_round_trips_through_14_bit_packed_value() {
        let scheme = ByteMappingScheme::new(2, 4).unwrap();
        let encoded = scheme.get_encoded_mapping_scheme();
        assert_eq!(encoded, (2 << 7) | 4);
        let decoded = ByteMappingScheme::from_encoded(encoded).unwrap();
        assert_eq!(decoded, scheme);
    }

    #[test]
    fn from_ratio_str_parses_valid_and_rejects_invalid() {
        let scheme = ByteMappingScheme::from_ratio_str("2:4").unwrap();
        assert_eq!(scheme.get_mapped_byte_count(), 2);
        assert_eq!(scheme.get_mapped_source_byte_count(), 4);
        assert_eq!(scheme.to_string(), "2:4 mapping");

        assert!(ByteMappingScheme::from_ratio_str("nocolon").is_err());
        assert!(ByteMappingScheme::from_ratio_str("a:b").is_err());
        assert!(ByteMappingScheme::from_ratio_str("4:2").is_err());
    }

    #[test]
    fn get_mapped_source_address_one_to_one_is_identity_offset() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        let base = test_addr(0x1000);
        let addr = scheme.get_mapped_source_address(&base, 5).unwrap();
        assert_eq!(addr.offset(), 0x1005);
    }

    #[test]
    fn get_mapped_source_address_rejects_negative_offset() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        let base = test_addr(0x1000);
        let err = scheme.get_mapped_source_address(&base, -1).unwrap_err();
        assert!(matches!(err, ByteMappingSchemeError::IllegalArgument(_)));
    }

    #[test]
    fn get_mapped_source_address_applies_ratio_arithmetic() {
        // 1:2 -- every mapped byte is followed by one skipped source byte.
        let scheme = ByteMappingScheme::new(1, 2).unwrap();
        let base = test_addr(0);
        // mapped offset 0 -> source offset 0
        assert_eq!(scheme.get_mapped_source_address(&base, 0).unwrap().offset(), 0);
        // mapped offset 1 -> source offset 2 (1 full pattern of 2 skipped)
        assert_eq!(scheme.get_mapped_source_address(&base, 1).unwrap().offset(), 2);
        // mapped offset 4 -> source offset 8
        assert_eq!(scheme.get_mapped_source_address(&base, 4).unwrap().offset(), 8);

        // 2:4 -- two mapped bytes then two skipped source bytes, repeating.
        let scheme2 = ByteMappingScheme::new(2, 4).unwrap();
        assert_eq!(scheme2.get_mapped_source_address(&base, 0).unwrap().offset(), 0);
        assert_eq!(scheme2.get_mapped_source_address(&base, 1).unwrap().offset(), 1);
        assert_eq!(scheme2.get_mapped_source_address(&base, 2).unwrap().offset(), 4);
        assert_eq!(scheme2.get_mapped_source_address(&base, 3).unwrap().offset(), 5);
    }

    #[test]
    fn get_mapped_address_reverses_the_ratio_mapping() {
        let scheme = ByteMappingScheme::new(2, 4).unwrap();
        let block = MockBlock { start: test_addr(0), size: 8 };

        // source offset 0 and 1 map to mapped offset 0 and 1 (within the mapped run).
        assert_eq!(
            scheme.get_mapped_address(&block, 0, false).unwrap().unwrap().offset(),
            0
        );
        assert_eq!(
            scheme.get_mapped_address(&block, 1, false).unwrap().unwrap().offset(),
            1
        );
        // source offset 2 and 3 are skipped (non-mapped), falling in the same source pattern as
        // offsets 0/1 (source pattern width = mappedSourceByteCount = 4). With skip_back=true the
        // formula rounds down to that pattern's mapped-run start (mapped offset 0) rather than
        // to the last actual mapped byte (offset 1); skip_back=false rounds up to the next
        // pattern's mapped-run start (offset 2) instead. This matches the real
        // `ByteMappingScheme.getMappedAddress` formula verbatim -- it floors/advances by whole
        // mapped-run boundaries, not to individual mapped bytes.
        assert_eq!(
            scheme.get_mapped_address(&block, 2, true).unwrap().unwrap().offset(),
            0
        );
        assert_eq!(
            scheme.get_mapped_address(&block, 2, false).unwrap().unwrap().offset(),
            2
        );
    }

    #[test]
    fn get_mapped_address_returns_none_when_forward_skip_exceeds_block() {
        let scheme = ByteMappingScheme::new(2, 4).unwrap();
        // A tiny block whose mapped bytes end right where the next pattern would begin.
        let block = MockBlock { start: test_addr(0), size: 2 };
        // source offset 2 is the first skipped byte of the first (and only) pattern; the next
        // mapped byte would be offset 2 in the mapped block, which is out of range for a
        // 2-byte block.
        assert!(scheme.get_mapped_address(&block, 2, false).unwrap().is_none());
    }

    #[test]
    fn get_bytes_one_to_one_reads_straight_through() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        let mem = FlatMemory::new(0, vec![10, 20, 30, 40, 50]);
        let mut out = [0u8; 3];
        let n = scheme.get_bytes(&mem, &test_addr(0), 1, &mut out, 0, 3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, [20, 30, 40]);
    }

    #[test]
    fn get_bytes_applies_decimation_for_ratio_mapping() {
        // 1:2 mapping over source [0,1,2,3,4,5,6,7] should read every even-indexed byte.
        let scheme = ByteMappingScheme::new(1, 2).unwrap();
        let mem = FlatMemory::new(0, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        let mut out = [0u8; 4];
        let n = scheme.get_bytes(&mem, &test_addr(0), 0, &mut out, 0, 4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(out, [0, 2, 4, 6]);
    }

    #[test]
    fn get_bytes_applies_decimation_starting_mid_pattern() {
        // 2:4 mapping: bytes [m0 m1 skip skip] [m2 m3 skip skip] ... starting one byte into
        // the first pattern should read m1, m2, m3, m4.
        let scheme = ByteMappingScheme::new(2, 4).unwrap();
        let mem = FlatMemory::new(0, vec![10, 11, 99, 99, 12, 13, 99, 99, 14, 15, 99, 99]);
        let mut out = [0u8; 4];
        let n = scheme.get_bytes(&mem, &test_addr(0), 1, &mut out, 0, 4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(out, [11, 12, 13, 14]);
    }

    #[test]
    fn set_bytes_one_to_one_writes_straight_through() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        let mut mem = FlatMemory::new(0, vec![0; 5]);
        scheme.set_bytes(&mut mem, &test_addr(0), 1, &[9, 8, 7], 0, 3).unwrap();
        assert_eq!(*mem.data.lock().unwrap(), vec![0, 9, 8, 7, 0]);
    }

    #[test]
    fn set_bytes_applies_decimation_leaving_skipped_bytes_untouched() {
        // 1:2 mapping: writing [1,2,3,4] should land at source offsets 0,2,4,6, leaving the
        // odd (skipped) offsets at their initial sentinel value.
        let scheme = ByteMappingScheme::new(1, 2).unwrap();
        let mut mem = FlatMemory::new(0, vec![0xFF; 8]);
        scheme.set_bytes(&mut mem, &test_addr(0), 0, &[1, 2, 3, 4], 0, 4).unwrap();
        assert_eq!(
            *mem.data.lock().unwrap(),
            vec![1, 0xFF, 2, 0xFF, 3, 0xFF, 4, 0xFF]
        );
    }

    #[test]
    fn get_and_set_bytes_round_trip_through_ratio_mapping() {
        let scheme = ByteMappingScheme::new(2, 4).unwrap();
        let mut mem = FlatMemory::new(0, vec![0; 12]);
        scheme
            .set_bytes(&mut mem, &test_addr(0), 0, &[1, 2, 3, 4, 5, 6], 0, 6)
            .unwrap();
        let mut out = [0u8; 6];
        let n = scheme.get_bytes(&mem, &test_addr(0), 0, &mut out, 0, 6).unwrap();
        assert_eq!(n, 6);
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn get_mapped_source_address_overflow_is_reported() {
        let scheme = ByteMappingScheme::from_encoded(0).unwrap();
        let space = AddressSpace::new("RAM", 8, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), space.max_address().offset());
        let err = scheme.get_mapped_source_address(&addr, 1).unwrap_err();
        assert!(matches!(err, ByteMappingSchemeError::AddressOverflow(_)));
    }

    #[test]
    fn error_display_and_source_are_reasonable() {
        let err = ByteMappingSchemeError::IllegalArgument("bad".to_string());
        assert_eq!(err.to_string(), "illegal argument: bad");
        assert!(std::error::Error::source(&err).is_none());

        let overflow_err: ByteMappingSchemeError = AddressOverflowException::default().into();
        assert!(std::error::Error::source(&overflow_err).is_some());

        let mem_err: ByteMappingSchemeError = MemoryAccessException::new("nope").into();
        assert!(std::error::Error::source(&mem_err).is_some());
    }

    /// A `ByteMappingScheme` is `Send + Sync` (it holds only plain integers), matching the
    /// `SubMemoryBlock: Send + Sync` bound its byte-mapped consumer must satisfy.
    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ByteMappingScheme>();
        let _ = Arc::new(ByteMappingScheme::from_encoded(0).unwrap());
    }
}
