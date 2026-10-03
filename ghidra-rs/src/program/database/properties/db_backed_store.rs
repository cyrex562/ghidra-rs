//! Shared, non-public implementation plumbing for the concrete `*PropertyMapDB` structs in this
//! module (`VoidPropertyMapDB`, `IntPropertyMapDB`, `LongPropertyMapDB`, `StringPropertyMapDB`,
//! `ObjectPropertyMapDB`).
//!
//! This is not itself a port of any single Java class -- it factors out the pieces that are
//! identical across every concrete map (walking a [`Table`]'s records into a sorted address list,
//! and a bidirectional cursor over `long` address keys) so each concrete struct can compose it
//! rather than duplicating the same table-walking logic five times. This mirrors the project's
//! "compose, don't inherit" convention: Java's shared behavior lived in the `PropertyMapDB<T>`
//! abstract base class via inheritance; here it lives in free functions and a small helper type
//! that each concrete struct calls into.
//!
//! Key encoding: every concrete map keyed here stores records under a single [`Table`] whose
//! primary key is a `long` equal to `Address::offset()` within one fixed [`AddressSpace`]
//! (recorded on the struct as `space`). Real Ghidra addresses can span multiple spaces encoded
//! into one packed key by `AddressMap`; that translation layer is a separate, already-ported
//! component (`AddressMapDB`) that is not wired up here, so this port -- like the address-fixture
//! pattern already used throughout this crate's property-map tests (see
//! `program::util::*_property_map`'s test modules) -- is scoped to a single address space per map
//! instance.

use std::sync::Arc;

use crate::framework::db::Table;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::seam_stubs::AddressKeyIteratorLike;

/// Walks every record currently in `table` and returns the addresses they represent (`space` +
/// the record's `long` key), sorted ascending. Used by every concrete map's `PropertyMap`
/// iteration/lookup methods as the common "read everything, then filter/search in memory" base,
/// which is an acceptable simplification for the record counts these maps are exercised at (the
/// same tradeoff `AddressRangeMapDB` already makes for its own full-table scans).
pub(crate) fn collect_sorted_addresses(table: &Table, space: &Arc<AddressSpace>) -> Vec<Address> {
    let mut addrs: Vec<Address> = Vec::new();
    if let Ok(mut it) = table.get_record_iterator() {
        while let Ok(Some(rec)) = it.next() {
            let offset = rec.get_key().get_long_value();
            addrs.push(Address::new(space.clone(), offset));
        }
    }
    addrs.sort();
    addrs
}

/// A simple owned, bidirectional cursor over a fixed `Vec<i64>` of address keys. Implements
/// [`AddressKeyIteratorLike`] so it can be handed back from `PropertyMapDB::get_address_key_iterator_*`
/// without borrowing from the backing `Table`/lock guard (every concrete map builds one of these by
/// collecting the keys it cares about up front).
pub(crate) struct VecKeyIterator {
    keys: Vec<i64>,
    pos: usize,
}

impl VecKeyIterator {
    pub(crate) fn new(keys: Vec<i64>) -> Self {
        VecKeyIterator { keys, pos: 0 }
    }
}

impl AddressKeyIteratorLike for VecKeyIterator {
    fn has_next(&mut self) -> bool {
        self.pos < self.keys.len()
    }

    fn has_previous(&mut self) -> bool {
        self.pos > 0
    }

    fn next(&mut self) -> Option<i64> {
        if !self.has_next() {
            return None;
        }
        let v = self.keys[self.pos];
        self.pos += 1;
        Some(v)
    }

    fn previous(&mut self) -> Option<i64> {
        if !self.has_previous() {
            return None;
        }
        self.pos -= 1;
        Some(self.keys[self.pos])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_key_iterator_walks_forward_then_backward() {
        let mut it = VecKeyIterator::new(vec![1, 2, 3]);
        assert!(it.has_next());
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(2));
        assert_eq!(it.next(), Some(3));
        assert!(!it.has_next());
        assert!(it.next().is_none());

        assert!(it.has_previous());
        assert_eq!(it.previous(), Some(3));
        assert_eq!(it.previous(), Some(2));
        assert_eq!(it.previous(), Some(1));
        assert!(!it.has_previous());
    }

    #[test]
    fn empty_iterator_has_neither_direction() {
        let mut it = VecKeyIterator::new(Vec::new());
        assert!(!it.has_next());
        assert!(!it.has_previous());
        assert!(it.next().is_none());
        assert!(it.previous().is_none());
    }
}
