use crate::program::model::address::{
    Address, AddressFormatException, AddressOutOfBoundsException, AddressOverflowException,
    AddressSpace, AddressSpaceType,
};
use std::sync::Arc;

const REAL_MODE_SIZE: i32 = 21;
const REAL_MODE_MAX_OFFSET: i64 = 0x10ffef;
const PROTECTED_MODE_SIZE: i32 = 32;
const PROTECTED_MODE_OFFSET_SIZE: u32 = 16;

/// Intel segmented address-space mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SegmentedAddressSpace {
    space: Arc<AddressSpace>,
    mode: SegmentMode,
}

impl SegmentedAddressSpace {
    pub fn new(name: &str, unique: i32) -> Self {
        Self {
            space: AddressSpace::new(name, REAL_MODE_SIZE, 1, AddressSpaceType::Ram, unique),
            mode: SegmentMode::Real,
        }
    }

    fn protected(name: &str, unique: i32) -> Self {
        Self {
            space: AddressSpace::new(name, PROTECTED_MODE_SIZE, 1, AddressSpaceType::Ram, unique),
            mode: SegmentMode::Protected,
        }
    }

    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.space
    }

    pub fn name(&self) -> &str {
        self.space.name()
    }

    pub fn size(&self) -> i32 {
        self.space.size()
    }

    pub fn pointer_size(&self) -> i32 {
        2
    }

    pub fn max_offset(&self) -> i64 {
        match self.mode {
            SegmentMode::Real => REAL_MODE_MAX_OFFSET,
            SegmentMode::Protected => self.space.max_offset(),
        }
    }

    pub fn parse_address(
        &self,
        address: &str,
        case_sensitive: bool,
    ) -> Result<Option<SegmentedAddress>, AddressFormatException> {
        let Some((left, right)) = address.split_once(':') else {
            return self.parse_non_segmented(address).map(Some);
        };

        let matches_space = if case_sensitive {
            left == self.name()
        } else {
            left.eq_ignore_ascii_case(self.name())
        };

        if matches_space {
            if let Some((segment, offset)) = right.split_once(':') {
                return self.parse_segmented(segment, offset);
            }
            return self.parse_non_segmented(right).map(Some);
        }

        self.parse_segmented(left, right)
    }

    pub fn address(
        &self,
        flat_offset: i64,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        self.check_flat(flat_offset)?;
        Ok(SegmentedAddress::from_flat(self.clone(), flat_offset))
    }

    pub fn address_in_segment(
        &self,
        segment: u32,
        segment_offset: u32,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        if segment > 0xffff {
            return Err(AddressOutOfBoundsException::new("Segment is too large."));
        }
        if segment_offset > 0xffff {
            return Err(AddressOutOfBoundsException::new("Offset is too large."));
        }
        let flat = self.flat_offset(segment, segment_offset as i64);
        self.check_flat(flat)?;
        Ok(SegmentedAddress::new(self.clone(), segment, flat))
    }

    pub fn add(
        &self,
        address: &SegmentedAddress,
        displacement: i64,
    ) -> Result<SegmentedAddress, AddressOverflowException> {
        if displacement < 0 {
            return self.subtract(address, -displacement);
        }
        let result = address
            .offset()
            .checked_add(displacement)
            .ok_or_else(|| AddressOverflowException::new("Address Overflow in add"))?;
        if result < 0 || result > self.max_offset() {
            return Err(AddressOverflowException::new("Address Overflow in add"));
        }
        Ok(self
            .address_in_preferred_segment(result, address.segment())
            .unwrap_or_else(|| SegmentedAddress::from_flat(self.clone(), result)))
    }

    pub fn subtract(
        &self,
        address: &SegmentedAddress,
        displacement: i64,
    ) -> Result<SegmentedAddress, AddressOverflowException> {
        if displacement < 0 {
            return self.add(address, -displacement);
        }
        let result = address
            .offset()
            .checked_sub(displacement)
            .ok_or_else(|| AddressOverflowException::new("Address Overflow in subtract"))?;
        if result < 0 || result > self.max_offset() {
            return Err(AddressOverflowException::new(
                "Address Overflow in subtract",
            ));
        }
        Ok(self
            .address_in_preferred_segment(result, address.segment())
            .unwrap_or_else(|| SegmentedAddress::from_flat(self.clone(), result)))
    }

    pub fn is_successor(&self, before: &SegmentedAddress, after: &SegmentedAddress) -> bool {
        before.offset().checked_add(1) == Some(after.offset())
    }

    pub fn next_open_segment(&self, address: &SegmentedAddress) -> u32 {
        match self.mode {
            SegmentMode::Real => ((address.offset() >> 4) + 1) as u32,
            SegmentMode::Protected => {
                ((self.default_segment_from_flat(address.offset()) + 8) & 0xfff8) as u32
            }
        }
    }

    fn parse_non_segmented(
        &self,
        offset: &str,
    ) -> Result<SegmentedAddress, AddressFormatException> {
        let flat = parse_hex(offset).map_err(|_| {
            AddressFormatException::new(format!("Cannot parse ({offset}) as a number."))
        })?;
        self.address(flat)
            .map_err(|error| AddressFormatException::new(error.to_string()))
    }

    fn parse_segmented(
        &self,
        segment: &str,
        offset: &str,
    ) -> Result<Option<SegmentedAddress>, AddressFormatException> {
        let Ok(segment) = parse_hex(segment) else {
            return Ok(None);
        };
        let offset = parse_hex(offset).map_err(|_| {
            AddressFormatException::new(format!("Cannot parse ({segment:x}:{offset}) as a number."))
        })?;
        self.address_in_segment(segment as u32, offset as u32)
            .map(Some)
            .map_err(|error| AddressFormatException::new(error.to_string()))
    }

    fn address_in_preferred_segment(
        &self,
        flat: i64,
        preferred_segment: u32,
    ) -> Option<SegmentedAddress> {
        match self.mode {
            SegmentMode::Real => {
                let segment_base = (preferred_segment as i64) << 4;
                if segment_base <= flat {
                    let offset = flat - segment_base;
                    if offset <= 0xffff {
                        return Some(SegmentedAddress::new(self.clone(), preferred_segment, flat));
                    }
                }
                None
            }
            SegmentMode::Protected => None,
        }
    }

    fn flat_offset(&self, segment: u32, offset: i64) -> i64 {
        match self.mode {
            SegmentMode::Real => ((segment as i64) << 4) + offset,
            SegmentMode::Protected => ((segment as i64) << PROTECTED_MODE_OFFSET_SIZE) + offset,
        }
    }

    fn default_segment_from_flat(&self, flat: i64) -> i64 {
        match self.mode {
            SegmentMode::Real => {
                if flat > 0xfffff {
                    0xffff
                } else {
                    (flat >> 4) & 0xf000
                }
            }
            SegmentMode::Protected => flat >> PROTECTED_MODE_OFFSET_SIZE,
        }
    }

    fn default_offset_from_flat(&self, flat: i64) -> i64 {
        match self.mode {
            SegmentMode::Real => {
                if flat > 0xfffff {
                    flat - 0xffff0
                } else {
                    flat & 0xffff
                }
            }
            SegmentMode::Protected => flat & 0xffff,
        }
    }

    fn offset_from_flat(&self, flat: i64, segment: u32) -> i64 {
        match self.mode {
            SegmentMode::Real => flat - ((segment as i64) << 4),
            SegmentMode::Protected => flat & 0xffff,
        }
    }

    fn check_flat(&self, flat: i64) -> Result<(), AddressOutOfBoundsException> {
        if (0..=self.max_offset()).contains(&flat) {
            Ok(())
        } else {
            Err(AddressOutOfBoundsException::new("Offset is out of bounds."))
        }
    }
}

/// Intel protected-mode segmented address-space mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedAddressSpace {
    inner: SegmentedAddressSpace,
}

impl ProtectedAddressSpace {
    pub fn new(name: &str, unique: i32) -> Self {
        Self {
            inner: SegmentedAddressSpace::protected(name, unique),
        }
    }

    pub fn as_segmented_space(&self) -> &SegmentedAddressSpace {
        &self.inner
    }

    pub fn address_in_segment(
        &self,
        segment: u32,
        segment_offset: u32,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        self.inner.address_in_segment(segment, segment_offset)
    }

    pub fn address(
        &self,
        flat_offset: i64,
    ) -> Result<SegmentedAddress, AddressOutOfBoundsException> {
        self.inner.address(flat_offset)
    }

    pub fn next_open_segment(&self, address: &SegmentedAddress) -> u32 {
        self.inner.next_open_segment(address)
    }
}

/// Segmented address with a flat address for interoperability.
#[derive(Debug, Clone)]
pub struct SegmentedAddress {
    space: SegmentedAddressSpace,
    address: Address,
    segment: u32,
}

impl SegmentedAddress {
    fn new(space: SegmentedAddressSpace, segment: u32, flat: i64) -> Self {
        Self {
            address: Address::new(space.space.clone(), flat),
            space,
            segment,
        }
    }

    fn from_flat(space: SegmentedAddressSpace, flat: i64) -> Self {
        let segment = space.default_segment_from_flat(flat) as u32;
        let offset = space.default_offset_from_flat(flat) as u32;
        let adjusted_flat = space.flat_offset(segment, offset as i64);
        Self::new(space, segment, adjusted_flat)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn offset(&self) -> i64 {
        self.address.offset()
    }

    pub fn segment(&self) -> u32 {
        self.segment
    }

    pub fn segment_offset(&self) -> u32 {
        self.space.offset_from_flat(self.offset(), self.segment) as u32
    }

    pub fn normalize(&self, segment: u32) -> Self {
        self.space
            .address_in_preferred_segment(self.offset(), segment)
            .unwrap_or_else(|| self.clone())
    }

    pub fn format_with_prefix(&self, prefix: &str) -> String {
        format!(
            "{}{:04x}:{:04x}",
            prefix,
            self.segment(),
            self.segment_offset()
        )
    }
}

impl std::fmt::Display for SegmentedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}:{:04x}", self.segment(), self.segment_offset())
    }
}

impl PartialEq for SegmentedAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for SegmentedAddress {}

impl std::hash::Hash for SegmentedAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SegmentMode {
    Real,
    Protected,
}

fn parse_hex(value: &str) -> Result<i64, std::num::ParseIntError> {
    let text = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    i64::from_str_radix(text, 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_mode_parses_flat_and_segmented_forms() {
        let space = SegmentedAddressSpace::new("Test", 0);

        for text in ["12345", "1000:2345", "Test:12345", "Test:1000:2345"] {
            let address = space.parse_address(text, true).unwrap().unwrap();
            assert_eq!(address.segment(), 0x1000);
            assert_eq!(address.segment_offset(), 0x2345);
            assert_eq!(address.offset(), 0x12345);
        }

        assert!(space.parse_address(":10", true).unwrap().is_none());
        assert!(space.parse_address("Foo:0", true).unwrap().is_none());
        assert!(space.parse_address("3:ffffff", true).is_err());
        assert!(space.parse_address("ffffff", true).is_err());
    }

    #[test]
    fn real_mode_add_subtract_preserves_preferred_segment_when_possible() {
        let space = SegmentedAddressSpace::new("Test", 0);
        let addr = |segment, offset| space.address_in_segment(segment, offset).unwrap();

        assert_eq!(space.add(&addr(0, 5), 3).unwrap(), addr(0, 8));
        assert_eq!(space.add(&addr(10, 5), -4).unwrap(), addr(10, 1));
        assert_eq!(space.subtract(&addr(4, 5), 3).unwrap(), addr(4, 2));
        assert_eq!(space.subtract(&addr(3, 0), 1).unwrap(), addr(0, 0x2f));
        assert_eq!(
            space.add(&addr(0, 0), 0x10ffef).unwrap(),
            addr(0xffff, 0xffff)
        );
        assert!(space.add(&addr(0, 1), 0x10ffef).is_err());
        assert!(space.subtract(&addr(0, 0), 0x100000).is_err());
    }

    #[test]
    fn real_mode_successor_and_normalization_match_flat_offsets() {
        let space = SegmentedAddressSpace::new("Test", 0);
        let addr = |segment, offset| space.address_in_segment(segment, offset).unwrap();

        assert!(space.is_successor(&addr(3, 4), &addr(3, 5)));
        assert!(space.is_successor(&addr(0, 0xffff), &addr(0x1000, 0)));
        assert!(space.is_successor(&addr(0x1000, 0x2345), &addr(0x1200, 0x0346)));
        assert!(!space.is_successor(&addr(2, 5), &addr(3, 5)));

        assert_eq!(addr(0x1234, 0x5), addr(0x1000, 0x2345));
        assert_eq!(addr(0x1000, 0x2345).normalize(0x1234), addr(0x1234, 0x5));
    }

    #[test]
    fn real_mode_format_and_next_open_segment_match_java() {
        let space = SegmentedAddressSpace::new("Test", 0);
        let address = space.address_in_segment(0x123, 0x1000).unwrap();

        assert_eq!(address.segment(), 0x123);
        assert_eq!(address.to_string(), "0123:1000");
        assert_eq!(address.format_with_prefix("0x"), "0x0123:1000");
        assert_eq!(
            space.next_open_segment(&space.address_in_segment(3, 0).unwrap()),
            4
        );
    }

    #[test]
    fn protected_mode_encodes_segment_in_upper_bits() {
        let space = ProtectedAddressSpace::new("prot", 1);
        let address = space.address_in_segment(0x1234, 0x5678).unwrap();

        assert_eq!(address.offset(), 0x12345678);
        assert_eq!(address.segment(), 0x1234);
        assert_eq!(address.segment_offset(), 0x5678);
        assert_eq!(space.address(0x12345678).unwrap(), address);
        assert_eq!(space.next_open_segment(&address), 0x1238);
        assert_eq!(address.normalize(0x1111), address);
    }
}
