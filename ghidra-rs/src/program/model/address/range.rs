use super::{Address, AddressOverflowException, AddressSpace};
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddressRange {
    min: Address,
    max: Address,
}

impl AddressRange {
    pub fn new(start: Address, end: Address) -> Self {
        if start.space() != end.space() {
            panic!("AddressRange must be in the same space");
        }
        if start <= end {
            Self {
                min: start,
                max: end,
            }
        } else {
            Self {
                min: end,
                max: start,
            }
        }
    }

    pub fn from_start_len(start: Address, length: u64) -> Result<Self, AddressOverflowException> {
        if length == 0 {
            return Ok(Self {
                min: start.clone(),
                max: start,
            });
        }
        let end = start.add_no_wrap((length - 1) as i64)?;
        Ok(Self {
            min: start,
            max: end,
        })
    }

    pub fn min_address(&self) -> &Address {
        &self.min
    }

    pub fn max_address(&self) -> &Address {
        &self.max
    }

    pub fn space(&self) -> &Arc<AddressSpace> {
        self.min.space()
    }

    pub fn length(&self) -> u64 {
        (self.max.offset() as u64)
            .wrapping_sub(self.min.offset() as u64)
            .wrapping_add(1)
    }

    /// Corresponds to Java's `AddressRangeImpl.getBigLength()`; this crate
    /// represents `BigInteger` values as `i128`.
    pub fn big_length(&self) -> i128 {
        self.max.unsigned_offset() as i128 - self.min.unsigned_offset() as i128 + 1
    }

    pub fn contains(&self, addr: &Address) -> bool {
        if self.min.space() != addr.space() {
            return false;
        }
        addr.offset() >= self.min.offset() && addr.offset() <= self.max.offset()
    }

    pub fn intersect(&self, other: &AddressRange) -> Option<Self> {
        if !self.intersects(other) {
            return None;
        }
        let min = self.min.clone().max(other.min.clone());
        let max = self.max.clone().min(other.max.clone());
        Some(Self { min, max })
    }

    pub fn intersect_range(&self, start: &Address, end: &Address) -> Option<Self> {
        self.intersect(&Self::new(start.clone(), end.clone()))
    }

    pub fn intersects(&self, other: &AddressRange) -> bool {
        if self.min.space() != other.min.space() {
            return false;
        }
        self.min.offset() <= other.max.offset() && self.max.offset() >= other.min.offset()
    }

    pub fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.intersects(&Self::new(start.clone(), end.clone()))
    }

    pub fn compare_to_address(&self, addr: &Address) -> Ordering {
        if addr < &self.min {
            Ordering::Greater
        } else if addr > &self.max {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }

    pub fn addresses(&self) -> AddressRangeAddressIterator {
        AddressRangeAddressIterator {
            current: Some(self.min.clone()),
            max: self.max.clone(),
        }
    }
}

/// Iterator over each address in an inclusive `AddressRange`.
#[derive(Debug, Clone)]
pub struct AddressRangeAddressIterator {
    current: Option<Address>,
    max: Address,
}

impl Iterator for AddressRangeAddressIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.current.clone()?;
        self.current = if next == self.max {
            None
        } else {
            Some(next.add(1).ok()?)
        };
        Some(next)
    }
}

impl PartialOrd for AddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.min.cmp(&other.min).then(self.max.cmp(&other.max))
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.min, self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn intersect_returns_common_range() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));
        let other = AddressRange::new(addr(0x1080), addr(0x11ff));

        let intersection = range.intersect(&other).unwrap();

        assert_eq!(intersection.min_address(), &addr(0x1080));
        assert_eq!(intersection.max_address(), &addr(0x10ff));
    }

    #[test]
    fn intersect_returns_none_for_disjoint_range() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));
        let other = AddressRange::new(addr(0x1100), addr(0x11ff));

        assert!(range.intersect(&other).is_none());
    }

    #[test]
    fn range_intersection_accepts_start_and_end_addresses() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));

        assert!(range.intersects_range(&addr(0x0fff), &addr(0x1000)));
        assert!(!range.intersects_range(&addr(0x0f00), &addr(0x0fff)));

        let intersection = range.intersect_range(&addr(0x10f0), &addr(0x1100)).unwrap();
        assert_eq!(intersection.min_address(), &addr(0x10f0));
        assert_eq!(intersection.max_address(), &addr(0x10ff));
    }

    #[test]
    fn compare_to_address_matches_java_signs() {
        let range = AddressRange::new(addr(0x1000), addr(0x10ff));

        assert_eq!(range.compare_to_address(&addr(0x0fff)), Ordering::Greater);
        assert_eq!(range.compare_to_address(&addr(0x1000)), Ordering::Equal);
        assert_eq!(range.compare_to_address(&addr(0x1080)), Ordering::Equal);
        assert_eq!(range.compare_to_address(&addr(0x10ff)), Ordering::Equal);
        assert_eq!(range.compare_to_address(&addr(0x1100)), Ordering::Less);
    }

    #[test]
    fn big_length_matches_inclusive_span() {
        let range = AddressRange::new(addr(0x1000), addr(0x1002));
        assert_eq!(range.big_length(), 3);

        let single = AddressRange::new(addr(0x1000), addr(0x1000));
        assert_eq!(single.big_length(), 1);
    }

    #[test]
    fn display_formats_as_bracketed_pair() {
        let range = AddressRange::new(addr(0x1000), addr(0x1002));
        assert_eq!(range.to_string(), format!("[{}, {}]", addr(0x1000), addr(0x1002)));
    }

    #[test]
    fn addresses_iterates_inclusive_range() {
        let range = AddressRange::new(addr(0x1000), addr(0x1002));
        let addresses: Vec<_> = range.addresses().collect();

        assert_eq!(addresses, vec![addr(0x1000), addr(0x1001), addr(0x1002)]);
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
