//! Test-only [`AddressMap`] implementation shared by this module's adapter test suites. **Not a
//! port of a Java class** -- Java's tests build a real `AddressMapDB` backed by a live `DBHandle`;
//! these adapters' tests only need `AddressMap`'s key-range/encoding contract (used by
//! [`AddressKeyRecordIterator`](crate::program::database::map::AddressKeyRecordIterator) and
//! [`AddressIndexPrimaryKeyIterator`](crate::program::database::map::AddressIndexPrimaryKeyIterator)),
//! so this supplies a minimal, deterministic stand-in (identity mapping between an address's
//! offset and its key, within a single address space).
//!
//! This duplicates `program::database::map::test_support::TestAddressMap` rather than reusing it:
//! that module is private to `program::database::map` (its `TestAddressMap` is `pub(crate)`, but
//! its containing `mod test_support` is not), so it is not reachable from sibling adapter
//! families. `BookmarkDBAdapterV3`'s own tests hit the same constraint and resolved it the same
//! way -- a small local `IdentityAddressMap` -- so this just promotes that per-file pattern to a
//! single shared module for the six relocation adapter versions that all need it.

use std::sync::Arc;

use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace, KeyRange};

pub(crate) struct IdentityAddressMap {
    space: Arc<AddressSpace>,
}

impl IdentityAddressMap {
    pub(crate) fn new(space: Arc<AddressSpace>) -> Self {
        IdentityAddressMap { space }
    }
}

impl AddressMap for IdentityAddressMap {
    fn get_key(&self, addr: &Address, _create: bool) -> i64 {
        addr.offset()
    }

    fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
        addr.offset()
    }

    fn find_key_range(&self, key_range_list: &[KeyRange], addr: Option<&Address>) -> i32 {
        let Some(addr) = addr else {
            return -1;
        };
        let key = addr.offset();
        match key_range_list.binary_search_by(|range| {
            if key < range.min_key {
                std::cmp::Ordering::Greater
            } else if key > range.max_key {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(index) => index as i32,
            Err(index) => -(index as i32) - 1,
        }
    }

    fn decode_address(&self, value: i64) -> Address {
        self.space.address(value)
    }

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        None
    }

    fn get_key_ranges_absolute(
        &self,
        start: &Address,
        end: &Address,
        _absolute: bool,
        _create: bool,
    ) -> Vec<KeyRange> {
        vec![KeyRange::new(start.offset(), end.offset())]
    }

    fn get_key_ranges_for_set_absolute(
        &self,
        set: Option<&dyn AddressSetView>,
        _absolute: bool,
        _create: bool,
    ) -> Vec<KeyRange> {
        match set {
            None => vec![KeyRange::new(i64::MIN, i64::MAX)],
            Some(set) => {
                let mut ranges = Vec::new();
                let mut it = set.address_ranges();
                while let Some(range) = it.next() {
                    ranges.push(KeyRange::new(range.min_address().offset(), range.max_address().offset()));
                }
                ranges
            }
        }
    }

    fn get_old_address_map(&self) -> Box<dyn AddressMap> {
        Box::new(IdentityAddressMap { space: self.space.clone() })
    }

    fn is_upgraded(&self) -> bool {
        false
    }

    fn get_image_base(&self) -> Address {
        self.space.address(0)
    }
}
