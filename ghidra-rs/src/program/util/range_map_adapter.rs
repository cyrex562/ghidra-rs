use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::program::model::lang::register::Register;
use crate::program::util::LanguageTranslator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Storage of arbitrary byte-array values keyed by address range.
///
/// Port of `ghidra.program.util.RangeMapAdapter`.
pub trait RangeMapAdapter {
    /// Returns the byte array that has been associated with the given index, or `None` if no
    /// such association exists.
    fn get_value(&self, address: &Address) -> Option<Vec<u8>>;

    /// Move all values within an address range to a new range.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Associates the given byte array with all indexes in the given (inclusive) range. Any
    /// existing values will be overwritten.
    fn set(&mut self, start: &Address, end: &Address, bytes: &[u8]);

    /// Returns an iterator over all stored values in the given (inclusive) range. If the given
    /// range intersects an actual stored range either at the beginning or end, the iterator will
    /// return those ranges truncated to fit within the given range.
    fn get_address_range_iterator_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator>;

    /// Returns an iterator over all stored values.
    fn get_address_range_iterator(&self) -> Box<dyn AddressRangeIterator>;

    /// Clears all associated values in the given (inclusive) range.
    fn clear_range(&mut self, start: &Address, end: &Address);

    /// Clears all values.
    fn clear_all(&mut self);

    /// Returns true if this storage has no associated values for any address.
    fn is_empty(&self) -> bool;

    /// Update table name and values to reflect a new base register.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    fn set_language(
        &mut self,
        translator: &dyn LanguageTranslator,
        map_reg: &Register,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Returns the bounding address-range containing `addr` and the same value throughout. This
    /// range will be limited by any value change associated with the base register.
    fn get_value_range_containing(&self, addr: &Address) -> AddressRange;

    /// Verify that this adapter is in a writable state (i.e. a valid transaction has been
    /// started).
    ///
    /// # Panics
    /// Implementations should panic if not in a writable state (mirrors `IllegalStateException`).
    fn check_writable_state(&self);

    /// Notification that something has changed that may affect internal caching.
    fn invalidate(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressRangeIteratorAdapter;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// Minimal in-memory mock proving `RangeMapAdapter` is object-safe and that the trait's
    /// contract (last write wins, clears remove values, moves shift keys) is exercisable through
    /// a `Box<dyn RangeMapAdapter>`.
    struct MockRangeMap {
        values: RefCell<BTreeMap<i64, Vec<u8>>>,
        writable: bool,
    }

    impl MockRangeMap {
        fn new(writable: bool) -> Self {
            MockRangeMap {
                values: RefCell::new(BTreeMap::new()),
                writable,
            }
        }
    }

    impl RangeMapAdapter for MockRangeMap {
        fn get_value(&self, address: &Address) -> Option<Vec<u8>> {
            self.values.borrow().get(&address.offset()).cloned()
        }

        fn move_address_range(
            &mut self,
            from_addr: &Address,
            to_addr: &Address,
            length: u64,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            let mut values = self.values.borrow_mut();
            let moved: Vec<(i64, Vec<u8>)> = values
                .range(from_addr.offset()..from_addr.offset() + length as i64)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            for (k, _) in &moved {
                values.remove(k);
            }
            let delta = to_addr.offset() as i128 - from_addr.offset() as i128;
            for (k, v) in moved {
                values.insert((k as i128 + delta) as i64, v);
            }
            Ok(())
        }

        fn set(&mut self, start: &Address, end: &Address, bytes: &[u8]) {
            let mut values = self.values.borrow_mut();
            for offset in start.offset()..=end.offset() {
                values.insert(offset, bytes.to_vec());
            }
        }

        fn get_address_range_iterator_in_range(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn AddressRangeIterator> {
            Box::new(AddressRangeIteratorAdapter::new(Vec::new()))
        }

        fn get_address_range_iterator(&self) -> Box<dyn AddressRangeIterator> {
            Box::new(AddressRangeIteratorAdapter::new(Vec::new()))
        }

        fn clear_range(&mut self, start: &Address, end: &Address) {
            let mut values = self.values.borrow_mut();
            for offset in start.offset()..=end.offset() {
                values.remove(&offset);
            }
        }

        fn clear_all(&mut self) {
            self.values.borrow_mut().clear();
        }

        fn is_empty(&self) -> bool {
            self.values.borrow().is_empty()
        }

        fn set_language(
            &mut self,
            _translator: &dyn LanguageTranslator,
            _map_reg: &Register,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn get_value_range_containing(&self, addr: &Address) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }

        fn check_writable_state(&self) {
            if !self.writable {
                panic!("not in a writable state");
            }
        }

        fn invalidate(&mut self) {}
    }

    #[test]
    fn set_get_clear_round_trip() {
        let space = test_space();
        let mut map: Box<dyn RangeMapAdapter> = Box::new(MockRangeMap::new(true));

        assert!(map.is_empty());
        map.set(&addr(&space, 0x10), &addr(&space, 0x1f), &[0xAB]);
        assert!(!map.is_empty());
        assert_eq!(map.get_value(&addr(&space, 0x15)), Some(vec![0xAB]));
        assert_eq!(map.get_value(&addr(&space, 0x20)), None);

        map.clear_range(&addr(&space, 0x10), &addr(&space, 0x1f));
        assert!(map.is_empty());
        assert_eq!(map.get_value(&addr(&space, 0x15)), None);
    }

    #[test]
    fn move_address_range_shifts_values() {
        let space = test_space();
        let mut map = MockRangeMap::new(true);
        map.set(&addr(&space, 0x0), &addr(&space, 0x3), &[1, 2, 3]);

        let monitor = DummyMonitor;
        map.move_address_range(&addr(&space, 0x0), &addr(&space, 0x100), 4, &monitor)
            .expect("move should not be cancelled");

        assert_eq!(map.get_value(&addr(&space, 0x0)), None);
        assert_eq!(map.get_value(&addr(&space, 0x100)), Some(vec![1, 2, 3]));
    }

    #[test]
    #[should_panic(expected = "not in a writable state")]
    fn check_writable_state_panics_when_not_writable() {
        let map = MockRangeMap::new(false);
        map.check_writable_state();
    }
}
