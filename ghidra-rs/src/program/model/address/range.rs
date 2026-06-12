use super::{Address, AddressSpace};
use crate::util::exception::AddressOverflowException;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
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

    pub fn contains(&self, addr: &Address) -> bool {
        if self.min.space() != addr.space() {
            return false;
        }
        addr.offset() >= self.min.offset() && addr.offset() <= self.max.offset()
    }

    pub fn intersects(&self, other: &AddressRange) -> bool {
        if self.min.space() != other.min.space() {
            return false;
        }
        self.min.offset() <= other.max.offset() && self.max.offset() >= other.min.offset()
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
