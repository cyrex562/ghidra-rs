pub mod address_collectors;
pub mod address_format_exception;
pub mod address_map_impl;
pub mod address_object_map;
pub mod address_out_of_bounds_exception;
pub mod address_overflow_exception;
pub mod address_range_to_address_comparator;
pub mod address_set;
pub mod address_set_collection;
pub mod address_set_mapping;
pub mod address_set_view_adapter;
pub mod factory;
pub mod immutable_address_set;
pub mod iterator;
pub mod key_range;
pub mod range;
pub mod range_splitter;
pub mod segment_mismatch_exception;

use std::fmt;
use std::sync::Arc;

pub use address_format_exception::AddressFormatException;
pub use address_map_impl::AddressMapImpl;
pub use address_object_map::AddressObjectMap;
pub use address_out_of_bounds_exception::AddressOutOfBoundsException;
pub use address_overflow_exception::AddressOverflowException;
pub use address_range_to_address_comparator::AddressRangeToAddressComparator;
pub use address_set::{AddressSet, AddressSetView};
pub use address_set_collection::{AddressSetCollection, SingleAddressSetCollection};
pub use address_set_mapping::AddressSetMapping;
pub use address_set_view_adapter::AddressSetViewAdapter;
pub use factory::{AddressFactory, DefaultAddressFactory};
pub use immutable_address_set::ImmutableAddressSet;
pub use iterator::{
    AddressIterator, AddressIteratorAdapter, AddressRangeIterator, AddressRangeIteratorAdapter,
    EmptyAddressIterator, EmptyAddressRangeIterator,
};
pub use key_range::KeyRange;
pub use range::AddressRange;
pub use range_splitter::{AddressRangeChunker, AddressRangeSplitter};
pub use segment_mismatch_exception::SegmentMismatchException;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressSpaceType {
    Constant = 0,
    Ram = 1,
    Code = 2,
    Unique = 3,
    Register = 4,
    Stack = 5,
    Join = 6,
    Other = 7,
    Symbol = 9,
    External = 10,
    Variable = 11,
    Deleted = 13,
    Unknown = 14,
    None = 15,
}

#[derive(Clone, Debug)]
pub struct AddressSpace {
    name: String,
    size: i32,      // number of address bits
    unit_size: i32, // number of data bytes at each location
    space_type: AddressSpaceType,
    _unique: i32,
    space_id: i32,
    signed: bool,
    _min_offset: i64,
    _max_offset: i64,
}

impl AddressSpace {
    pub fn new(
        name: &str,
        size: i32,
        unit_size: i32,
        space_type: AddressSpaceType,
        unique: i32,
    ) -> Arc<Self> {
        let signed =
            space_type == AddressSpaceType::Constant || space_type == AddressSpaceType::Stack;

        // incorporation of size component for space_id
        let logsize = match size {
            8 => 0,
            16 => 1,
            32 => 2,
            64 => 3,
            _ => 7,
        };

        let space_id = (unique << 7) | (logsize << 4) | (space_type as i32);

        let (min_offset, max_offset) = if space_type == AddressSpaceType::None {
            (0, 0)
        } else if size == 64 {
            // Ghidra uses signed long for offsets.
            // If signed: -2^63 to 2^63-1
            // If unsigned: 0 to 2^64-1 (but represented in signed long)
            if signed {
                (i64::MIN, i64::MAX)
            } else {
                (0, -1) // -1 as i64 is all 1s, which is MAX_UINT64
            }
        } else {
            let space_size = (unit_size as i64) << size;
            if signed {
                let max = (space_size - 1) >> 1;
                (-max - 1, max)
            } else {
                (0, space_size - 1)
            }
        };

        Arc::new(Self {
            name: name.to_string(),
            size,
            unit_size,
            space_type,
            _unique: unique,
            space_id,
            signed,
            _min_offset: min_offset,
            _max_offset: max_offset,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn size(&self) -> i32 {
        self.size
    }
    pub fn unit_size(&self) -> i32 {
        self.unit_size
    }
    pub fn space_type(&self) -> AddressSpaceType {
        self.space_type
    }
    pub fn space_id(&self) -> i32 {
        self.space_id
    }
    pub fn is_signed(&self) -> bool {
        self.signed
    }
    pub fn unique(&self) -> i32 {
        self._unique
    }

    pub fn min_offset(&self) -> i64 {
        self._min_offset
    }

    pub fn max_offset(&self) -> i64 {
        self._max_offset
    }

    pub fn min_address(self: &Arc<Self>) -> Address {
        Address::new(self.clone(), self._min_offset)
    }

    pub fn max_address(self: &Arc<Self>) -> Address {
        Address::new(self.clone(), self._max_offset)
    }

    pub fn is_memory_space(&self) -> bool {
        matches!(
            self.space_type,
            AddressSpaceType::Ram | AddressSpaceType::Code | AddressSpaceType::Other
        )
    }

    pub fn is_loaded_memory_space(&self) -> bool {
        matches!(self.space_type, AddressSpaceType::Ram | AddressSpaceType::Code)
    }

    pub fn address(self: &Arc<Self>, offset: i64) -> Address {
        Address::new(self.clone(), offset)
    }

    pub fn parse_address(
        self: &Arc<Self>,
        addr_string: &str,
        case_sensitive: bool,
    ) -> Result<Option<Address>, AddressFormatException> {
        let text = addr_string.trim();
        if text.is_empty() {
            return Err(AddressFormatException::new("Address string is empty"));
        }

        let offset_text = if let Some((space_name, offset_text)) = text.split_once(':') {
            let matches_space = if case_sensitive {
                space_name == self.name()
            } else {
                space_name.eq_ignore_ascii_case(self.name())
            };
            if !matches_space {
                return Ok(None);
            }
            offset_text
        } else {
            text
        };

        if offset_text.is_empty() {
            return Err(AddressFormatException::new("Address offset is empty"));
        }

        let unsigned_text = offset_text
            .strip_prefix("0x")
            .or_else(|| offset_text.strip_prefix("0X"))
            .unwrap_or(offset_text);
        let offset = if self.signed && unsigned_text.starts_with('-') {
            let magnitude = i64::from_str_radix(&unsigned_text[1..], 16)
                .map_err(|_| AddressFormatException::new("Invalid address offset"))?;
            -magnitude
        } else {
            i64::from_str_radix(unsigned_text, 16)
                .map_err(|_| AddressFormatException::new("Invalid address offset"))?
        };

        if !self.contains_offset(offset) {
            return Err(AddressFormatException::new("Address offset is out of bounds"));
        }
        Ok(Some(Address::new(self.clone(), offset)))
    }

    pub fn contains_offset(&self, offset: i64) -> bool {
        if self.size == 64 && !self.signed {
            return offset >= 0 || self._max_offset == -1;
        }
        self._min_offset <= offset && offset <= self._max_offset
    }

    pub fn truncate_offset(&self, offset: i64) -> i64 {
        if self.size == 64 {
            return offset;
        }
        let mask = (1i64 << self.size) - 1;
        if self.signed {
            let unsigned_val = (offset as u64) & (mask as u64);
            let bit = 1u64 << (self.size - 1);
            if (unsigned_val & bit) != 0 {
                (unsigned_val | !(mask as u64)) as i64
            } else {
                unsigned_val as i64
            }
        } else {
            offset & mask
        }
    }
}

impl PartialEq for AddressSpace {
    fn eq(&self, other: &Self) -> bool {
        self.space_id == other.space_id && self.name == other.name
    }
}

impl Eq for AddressSpace {}

impl std::hash::Hash for AddressSpace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.space_id.hash(state);
        self.name.hash(state);
    }
}

impl PartialOrd for AddressSpace {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressSpace {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space_id
            .cmp(&other.space_id)
            .then(self.name.cmp(&other.name))
    }
}

#[derive(Clone, Debug)]
pub struct Address {
    space: Arc<AddressSpace>,
    offset: i64,
}

impl Address {
    pub fn new(space: Arc<AddressSpace>, offset: i64) -> Self {
        let truncated = space.truncate_offset(offset);
        Self {
            space,
            offset: truncated,
        }
    }

    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }
    pub fn offset(&self) -> i64 {
        self.offset
    }

    pub fn add(&self, displacement: i64) -> Result<Self, AddressOverflowException> {
        let new_offset = self.offset.wrapping_add(displacement);
        Ok(Self::new(self.space.clone(), new_offset))
    }

    pub fn add_no_wrap(&self, displacement: i64) -> Result<Self, AddressOverflowException> {
        let new_offset = self
            .offset
            .checked_add(displacement)
            .ok_or_else(|| AddressOverflowException::new("Overflow"))?;
        Ok(Self::new(self.space.clone(), new_offset))
    }

    pub fn next(&self) -> Result<Self, AddressOverflowException> {
        self.add_no_wrap(1)
    }

    pub fn previous(&self) -> Result<Self, AddressOverflowException> {
        self.add_no_wrap(-1)
    }

    pub fn subtract(&self, other: &Address) -> i64 {
        if self.space() != other.space() {
            panic!("Cannot subtract addresses from different spaces");
        }
        self.offset.wrapping_sub(other.offset)
    }

    pub fn is_successor(&self, other: &Address) -> bool {
        self.space() == other.space() && self.offset == other.offset.wrapping_add(1)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:0x{:x}", self.space.name(), self.offset)
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset && self.space == other.space
    }
}

impl Eq for Address {}

impl std::hash::Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        assert_eq!(ram.name(), "RAM");
        assert_eq!(ram.size(), 32);
    }

    #[test]
    fn test_address_arithmetic() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(ram.clone(), 0x1000);
        let next = addr.add(0x10).unwrap();
        assert_eq!(next.offset(), 0x1010);

        let addr2 = Address::new(ram.clone(), 0);
        let wrap = addr2.add(-1).unwrap();
        assert_eq!(wrap.offset() as u64, 0xFFFFFFFF);
    }
}
pub use address_collectors::AddressCollectors;
