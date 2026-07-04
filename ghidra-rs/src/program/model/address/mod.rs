pub mod address_collectors;
pub mod address_format_exception;
pub mod address_iterator_test_stub;
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
pub mod global_namespace;
pub mod immutable_address_set;
pub mod iterator;
pub mod key_range;
pub mod old_generic_namespace_address;
pub mod overlay_address_space;
pub mod range;
pub mod range_splitter;
pub mod segment_mismatch_exception;
pub mod segmented_address;
pub mod special_address;

use std::fmt;
use std::sync::Arc;

pub use address_format_exception::AddressFormatException;
pub use address_iterator_test_stub::AddressIteratorTestStub;
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
pub use global_namespace::{
    GlobalNamespace, GlobalSymbol, GLOBAL_NAMESPACE_ID, GLOBAL_NAMESPACE_NAME, GLOBAL_SYMBOL_NAME,
};
pub use immutable_address_set::ImmutableAddressSet;
pub use iterator::{
    AddressIterator, AddressIteratorAdapter, AddressRangeIterator, AddressRangeIteratorAdapter,
    EmptyAddressIterator, EmptyAddressRangeIterator,
};
pub use key_range::KeyRange;
pub use old_generic_namespace_address::{
    OldGenericNamespaceAddress, OLD_MAX_NAMESPACE_ID, OLD_MIN_NAMESPACE_ID,
};
pub use overlay_address_space::{OverlayAddressSpace, OV_SEPARATOR};
pub use range::AddressRange;
pub use range_splitter::{AddressRangeChunker, AddressRangeSplitter};
pub use segment_mismatch_exception::SegmentMismatchException;
pub use segmented_address::{ProtectedAddressSpace, SegmentedAddress, SegmentedAddressSpace};
pub use special_address::SpecialAddress;

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
        matches!(
            self.space_type,
            AddressSpaceType::Ram | AddressSpaceType::Code
        )
    }

    pub fn address(self: &Arc<Self>, offset: i64) -> Address {
        Address::new(self.clone(), offset)
    }

    pub fn checked_address(
        self: &Arc<Self>,
        offset: i64,
    ) -> Result<Address, AddressOutOfBoundsException> {
        Ok(Address {
            space: self.clone(),
            offset: self.make_valid_offset(offset)?,
        })
    }

    pub fn address_from_word_offset(
        self: &Arc<Self>,
        offset: i64,
    ) -> Result<Address, AddressOutOfBoundsException> {
        self.checked_address(offset.wrapping_mul(self.unit_size as i64))
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

        let (word_text, mod_text) = offset_text
            .split_once('.')
            .map(|(word, suffix)| (word, Some(suffix)))
            .unwrap_or((offset_text, None));

        let unsigned_text = word_text
            .strip_prefix("0x")
            .or_else(|| word_text.strip_prefix("0X"))
            .unwrap_or(word_text);
        let offset = if self.signed && unsigned_text.starts_with('-') {
            let magnitude = i64::from_str_radix(&unsigned_text[1..], 16)
                .map_err(|_| AddressFormatException::new("Invalid address offset"))?;
            -magnitude
        } else {
            i64::from_str_radix(unsigned_text, 16)
                .map_err(|_| AddressFormatException::new("Invalid address offset"))?
        };
        let mut offset = offset.wrapping_mul(self.unit_size as i64);
        if let Some(mod_text) = mod_text {
            let unit_mod = mod_text
                .parse::<i64>()
                .map_err(|_| AddressFormatException::new("Invalid address offset"))?;
            if unit_mod < 0 || unit_mod >= self.unit_size as i64 {
                return Err(AddressFormatException::new(
                    "Address offset is out of bounds",
                ));
            }
            offset = offset.wrapping_add(unit_mod);
        }

        if !self.contains_offset(offset) {
            return Err(AddressFormatException::new(
                "Address offset is out of bounds",
            ));
        }
        Ok(Some(Address::new(self.clone(), offset)))
    }

    pub fn contains_offset(&self, offset: i64) -> bool {
        if self.size == 64 && !self.signed {
            return offset >= 0 || self._max_offset == -1;
        }
        self._min_offset <= offset && offset <= self._max_offset
    }

    pub fn make_valid_offset(&self, offset: i64) -> Result<i64, AddressOutOfBoundsException> {
        if self.size == 64 {
            return Ok(offset);
        }
        if self._min_offset <= offset && offset <= self._max_offset {
            return Ok(offset);
        }
        let space_size = self.space_size();
        if self.signed {
            if offset > self._max_offset && (offset as i128) < space_size {
                return Ok((offset as i128 - space_size) as i64);
            }
        } else if offset < 0 && offset >= -self._max_offset - 1 {
            return Ok((offset as i128 + space_size) as i64);
        }
        Err(AddressOutOfBoundsException::new(format!(
            "Offset must be between 0x{:x} and 0x{:x}, got 0x{:x} instead!",
            self._min_offset, self._max_offset, offset
        )))
    }

    pub fn addressable_word_offset(&self, byte_offset: i64) -> i64 {
        let mut offset = byte_offset;
        let mut negative = false;
        if self.signed && offset < 0 {
            offset = offset.wrapping_neg();
            negative = true;
        }
        let word_offset = match self.unit_size {
            1 => offset,
            2 => ((offset as u64) >> 1) as i64,
            4 => ((offset as u64) >> 2) as i64,
            8 => ((offset as u64) >> 3) as i64,
            unit => ((offset as u64) / unit as u64) as i64,
        };
        if negative {
            word_offset.wrapping_neg()
        } else {
            word_offset
        }
    }

    pub fn truncate_addressable_word_offset(&self, word_offset: i64) -> i64 {
        self.addressable_word_offset(
            self.truncate_offset(word_offset.wrapping_mul(self.unit_size as i64)),
        )
    }

    pub fn add_wrap(self: &Arc<Self>, address: &Address, displacement: i64) -> Address {
        self.check_same_space(address);
        Address {
            space: self.clone(),
            offset: self.truncate_offset(address.offset().wrapping_add(displacement)),
        }
    }

    pub fn subtract_wrap(self: &Arc<Self>, address: &Address, displacement: i64) -> Address {
        self.check_same_space(address);
        Address {
            space: self.clone(),
            offset: self.truncate_offset(address.offset().wrapping_sub(displacement)),
        }
    }

    pub fn add_no_wrap(
        self: &Arc<Self>,
        address: &Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement == 0 {
            return Ok(address.clone());
        }
        if displacement < 0 {
            return self.subtract_no_wrap(address, displacement.wrapping_neg());
        }
        self.check_same_space(address);
        if self.size != 64 && (displacement as i128) > self.space_size() {
            return Err(AddressOverflowException::new("Address Overflow in add"));
        }
        let result = address.offset().wrapping_add(displacement);
        if self.signed {
            if result < address.offset() || result > self._max_offset {
                return Err(AddressOverflowException::new("Address Overflow in add"));
            }
        } else if unsigned_gt(result, self._max_offset) || unsigned_lt(result, address.offset()) {
            return Err(AddressOverflowException::new("Address Overflow in add"));
        }
        Ok(Address {
            space: self.clone(),
            offset: result,
        })
    }

    pub fn subtract_no_wrap(
        self: &Arc<Self>,
        address: &Address,
        displacement: i64,
    ) -> Result<Address, AddressOverflowException> {
        if displacement == 0 {
            return Ok(address.clone());
        }
        if displacement < 0 {
            if displacement == i64::MIN {
                return Err(AddressOverflowException::new(
                    "Address Overflow in subtract",
                ));
            }
            return self.add_no_wrap(address, -displacement);
        }
        self.check_same_space(address);
        if self.size != 64 && (displacement as i128) > self.space_size() {
            return Err(AddressOverflowException::new(
                "Address Overflow in subtract",
            ));
        }
        let result = address.offset().wrapping_sub(displacement);
        if self.signed {
            if result < self._min_offset || result > address.offset() {
                return Err(AddressOverflowException::new(
                    "Address Overflow in subtract",
                ));
            }
        } else if unsigned_lt(address.offset(), result) {
            return Err(AddressOverflowException::new(
                "Address Overflow in subtract",
            ));
        }
        Ok(Address {
            space: self.clone(),
            offset: result,
        })
    }

    pub fn truncate_offset(&self, offset: i64) -> i64 {
        if self.size == 64 {
            return offset;
        }
        let space_size = self.space_size();
        if self._min_offset <= offset && offset <= self._max_offset {
            return offset;
        }
        if self.signed {
            let mut wrapped = (offset as i128 + self._max_offset as i128 + 1) % space_size;
            if wrapped < 0 {
                wrapped += space_size;
            }
            (wrapped - self._max_offset as i128 - 1) as i64
        } else {
            let mut wrapped = (offset as i128) % space_size;
            if wrapped < 0 {
                wrapped += space_size;
            }
            wrapped as i64
        }
    }

    fn check_same_space(&self, address: &Address) {
        if self != address.space().as_ref() {
            panic!("Address does not belong to this address space");
        }
    }

    fn space_size(&self) -> i128 {
        (self.unit_size as i128) << self.size
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

    pub fn unsigned_offset(&self) -> u64 {
        if self.offset >= 0 || !self.space.is_signed() {
            self.offset as u64
        } else if self.space.size() == 64 {
            self.offset as u64
        } else {
            (self.space.space_size() + self.offset as i128) as u64
        }
    }

    pub fn addressable_word_offset(&self) -> i64 {
        self.space.addressable_word_offset(self.offset)
    }

    pub fn add(&self, displacement: i64) -> Result<Self, AddressOverflowException> {
        self.add_no_wrap(displacement)
    }

    pub fn add_wrap(&self, displacement: i64) -> Self {
        self.space.add_wrap(self, displacement)
    }

    pub fn add_no_wrap(&self, displacement: i64) -> Result<Self, AddressOverflowException> {
        self.space.add_no_wrap(self, displacement)
    }

    pub fn subtract_wrap(&self, displacement: i64) -> Self {
        self.space.subtract_wrap(self, displacement)
    }

    pub fn subtract_no_wrap(&self, displacement: i64) -> Result<Self, AddressOverflowException> {
        self.space.subtract_no_wrap(self, displacement)
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

    pub fn same_address_space(&self, other: &Address) -> bool {
        self.space() == other.space()
    }

    pub fn is_memory_address(&self) -> bool {
        self.space.is_memory_space()
    }

    pub fn is_loaded_memory_address(&self) -> bool {
        self.space.is_loaded_memory_space()
    }

    pub fn is_stack_address(&self) -> bool {
        self.space.space_type() == AddressSpaceType::Stack
    }

    pub fn is_unique_address(&self) -> bool {
        self.space.space_type() == AddressSpaceType::Unique
    }

    pub fn is_constant_address(&self) -> bool {
        self.space.space_type() == AddressSpaceType::Constant
    }

    pub fn is_register_address(&self) -> bool {
        self.space.space_type() == AddressSpaceType::Register
    }

    pub fn is_special_address(&self) -> bool {
        self.space.space_type() == AddressSpaceType::None && self.space.size() == 0
    }

    pub fn to_string_with_prefix(&self, prefix: &str) -> String {
        if self.is_special_address() {
            return self.space.name().to_string();
        }
        format!("{}{}", prefix, self.format(false, 8))
    }

    pub fn format(&self, show_address_space: bool, min_num_digits: usize) -> String {
        if self.is_special_address() {
            return self.space.name().to_string();
        }
        let mut result = String::new();
        let mut digits = min_num_digits;
        let stack = self.is_stack_address();
        if stack {
            result.push_str("Stack[");
            digits = 1;
        } else if show_address_space {
            result.push_str(self.space.name());
            result.push(':');
        }

        let unit_size = if stack { 1 } else { self.space.unit_size() };
        let max_digits = ((self.space.size() - 1) / 4 + 1) as usize;
        let pad_size = digits.min(max_digits);
        let mut display_offset = self.offset;
        if stack {
            if display_offset < 0 {
                result.push('-');
                display_offset = display_offset.wrapping_neg();
            }
            result.push_str("0x");
        }

        let mut unit_mod = 0;
        if unit_size > 1 {
            unit_mod = display_offset.rem_euclid(unit_size as i64);
            display_offset = self.space.addressable_word_offset(display_offset);
        }

        let text = format!("{:x}", display_offset);
        for _ in 0..pad_size.saturating_sub(text.len()) {
            result.push('0');
        }
        result.push_str(&text);
        if unit_mod != 0 {
            result.push('.');
            result.push_str(&unit_mod.to_string());
        }
        if stack {
            result.push(']');
        }
        result
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_special_address() {
            return f.write_str(self.space.name());
        }
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
        let space_cmp = self.space.cmp(&other.space);
        if space_cmp != std::cmp::Ordering::Equal {
            return space_cmp;
        }
        if self.space.is_signed() {
            self.offset.cmp(&other.offset)
        } else {
            (self.offset as u64).cmp(&(other.offset as u64))
        }
    }
}

pub type GenericAddress = Address;
pub type GenericAddressSpace = AddressSpace;

fn unsigned_lt(left: i64, right: i64) -> bool {
    (left as u64) < (right as u64)
}

fn unsigned_gt(left: i64, right: i64) -> bool {
    (left as u64) > (right as u64)
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
        assert!(addr2.add(-1).is_err());
        let wrap = addr2.add_wrap(-1);
        assert_eq!(wrap.offset() as u64, 0xFFFFFFFF);
    }

    #[test]
    fn generic_address_space_parses_word_offsets() {
        let word_space = AddressSpace::new("Test3", 16, 2, AddressSpaceType::Ram, 1);

        let addr = word_space.parse_address("0x0010.1", true).unwrap().unwrap();
        assert_eq!(addr.offset(), 0x21);
        assert_eq!(addr.to_string_with_prefix("0x"), "0x0010.1");

        let addr = word_space.parse_address("0x10", true).unwrap().unwrap();
        assert_eq!(addr.offset(), 0x20);
        assert_eq!(addr.to_string_with_prefix("0x"), "0x0010");

        let addr = word_space.parse_address("0xffff.1", true).unwrap().unwrap();
        assert_eq!(addr.offset(), 0x1ffff);
        assert_eq!(addr.to_string_with_prefix("0x"), "0xffff.1");
        assert!(addr.add(1).is_err());
        assert_eq!(addr.add_wrap(1).offset(), 0);
    }

    #[test]
    fn generic_address_space_checked_offsets_match_java_bounds() {
        let ram = AddressSpace::new("Test", 8, 1, AddressSpaceType::Ram, 0);
        let register = AddressSpace::new("Register", 8, 1, AddressSpaceType::Register, 0);
        let stack = AddressSpace::new("stack", 8, 1, AddressSpaceType::Stack, 0);

        assert_eq!(ram.checked_address(5).unwrap().offset(), 5);
        assert!(ram.checked_address(257).is_err());
        assert!(ram.checked_address(-300).is_err());

        assert_eq!(register.checked_address(-5).unwrap().offset(), 0xfb);
        assert!(register.checked_address(1024).is_err());
        assert!(register.checked_address(-257).is_err());

        assert_eq!(stack.checked_address(5).unwrap().offset(), 5);
        assert_eq!(stack.checked_address(-5).unwrap().offset(), -5);
        assert!(stack.checked_address(256).is_err());
        assert!(stack.checked_address(-129).is_err());
    }

    #[test]
    fn generic_address_space_wrap_and_no_wrap_arithmetic() {
        let space = AddressSpace::new("Test", 8, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(5);

        assert_eq!(space.add_wrap(&addr, 3), space.address(8));
        assert_eq!(space.add_wrap(&addr, -4), space.address(1));
        assert_eq!(space.add_wrap(&addr, 1024), space.address(5));
        assert_eq!(space.subtract_wrap(&addr, 10), space.address(251));

        assert_eq!(space.add_no_wrap(&addr, 3).unwrap(), space.address(8));
        assert_eq!(space.subtract_no_wrap(&addr, 3).unwrap(), space.address(2));
        assert!(space.add_no_wrap(&addr, 1024).is_err());
        assert!(space.subtract_no_wrap(&addr, 1024).is_err());
        assert!(space.add_no_wrap(&space.max_address(), 1).is_err());
        assert!(space.subtract_no_wrap(&space.min_address(), 1).is_err());
    }

    #[test]
    fn generic_address_space_word_offset_and_truncation_match_java() {
        let space = AddressSpace::new("space1", 31, 2, AddressSpaceType::Ram, 0);

        assert_eq!(space.truncate_offset(0x25), 0x25);
        assert_eq!(space.truncate_offset(0x200000025), 0x25);
        assert_eq!(space.truncate_addressable_word_offset(0x15), 0x15);
        assert_eq!(space.truncate_addressable_word_offset(0x80000015), 0x15);

        let addr = Address::new(space.clone(), space.truncate_offset(0x200000025));
        assert_eq!(addr.offset(), 0x25);
        let addr = space.address_from_word_offset(0x15).unwrap();
        assert_eq!(addr.addressable_word_offset(), 0x15);
    }

    #[test]
    fn generic_address_order_uses_unsigned_offsets_for_unsigned_spaces() {
        let unsigned = AddressSpace::new("test", 64, 1, AddressSpaceType::Code, 0);
        let zero = unsigned.address(0);
        let one = unsigned.address(1);
        let large = unsigned.address(-2);
        let max = unsigned.max_address();

        assert!(zero < one);
        assert!(one < large);
        assert!(large < max);

        let signed = AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 0);
        assert!(signed.address(-2) < signed.address(0));
    }

    #[test]
    fn addressable_word_offset_matches_java_unsigned_division() {
        let sp1 = AddressSpace::new("AnotherSpace", 64, 1, AddressSpaceType::Code, 1);
        let sp2 = AddressSpace::new("AnotherSpace", 63, 2, AddressSpaceType::Code, 2);
        let sp3 = AddressSpace::new("AnotherSpace", 62, 3, AddressSpaceType::Code, 3);

        assert_eq!(sp1.addressable_word_offset(i64::MIN), i64::MIN);
        assert_eq!(sp1.addressable_word_offset(-1), -1);
        assert_eq!(sp2.addressable_word_offset(i64::MIN), 0x4000000000000000);
        assert_eq!(sp2.addressable_word_offset(-1), 0x7fffffffffffffff);
        assert_eq!(sp2.addressable_word_offset(-3), 0x7ffffffffffffffe);
        assert_eq!(
            sp3.addressable_word_offset(0xbfffffffffffffff_u64 as i64),
            0x3fffffffffffffff
        );
        assert_eq!(sp3.addressable_word_offset(3), 1);
        assert_eq!(
            sp3.addressable_word_offset(0x7fffffffffffffff),
            0x2aaaaaaaaaaaaaaa
        );
    }
}
pub use address_collectors::AddressCollectors;
