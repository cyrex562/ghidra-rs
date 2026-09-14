//! Port of `ghidra.program.database.util.IndexedAddressIterator`.
//!
//! Java implements Ghidra's `AddressIterator` (`hasNext()`/`next()`). Per this port's
//! `AddressIterator` convention (see `program::model::address::iterator`, and the analogous
//! [`AddressKeyAddressIterator`](crate::program::database::map::address_key_address_iterator::AddressKeyAddressIterator)),
//! that becomes a plain `Iterator<Item = Address>` here -- no bespoke trait, no `RefCell`-cached
//! lookahead, since `Iterator::next(&mut self)` already owns the mutation `hasNext()` needed to
//! fake.

use crate::framework::db::db_field_iterator::DBFieldIterator;
use crate::framework::db::util::ErrorHandler;
use crate::program::database::map::address_map::AddressMap;
use crate::program::model::address::Address;

/// Iterates over a [`DBFieldIterator`]; the field is the address but not the key; the column for
/// the field must be indexed.
///
/// Port of `ghidra.program.database.util.IndexedAddressIterator`.
pub struct IndexedAddressIterator<'a> {
    iter: Box<dyn DBFieldIterator>,
    addr_map: &'a dyn AddressMap,
    err_handler: &'a dyn ErrorHandler,
}

impl<'a> IndexedAddressIterator<'a> {
    /// Constructs a new iterator.
    ///
    /// * `iter` -- field iterator whose field values are the addresses (as encoded longs).
    /// * `addr_map` -- address map used to convert the longs into addresses.
    /// * `col_index` -- the indexed column in the record. Preserved for signature parity with
    ///   Java's `IndexedAddressIterator(DBFieldIterator, AddressMap, int, ErrorHandler)`
    ///   constructor, which accepts this parameter but -- faithfully reproduced quirk -- never
    ///   actually stores it on a field; it is effectively documentation-only in the Java source
    ///   too.
    /// * `err_handler` -- error handler notified of any I/O error encountered while iterating.
    ///
    /// Port of `IndexedAddressIterator(DBFieldIterator, AddressMap, int, ErrorHandler)`.
    pub fn new(
        iter: Box<dyn DBFieldIterator>,
        addr_map: &'a dyn AddressMap,
        col_index: i32,
        err_handler: &'a dyn ErrorHandler,
    ) -> Self {
        let _ = col_index;
        IndexedAddressIterator { iter, addr_map, err_handler }
    }
}

impl<'a> Iterator for IndexedAddressIterator<'a> {
    type Item = Address;

    /// Port of `hasNext()` + `next()`, which collapse into one method: `Iterator::next` already
    /// returns `Option`, so there is no separate boolean check to keep in sync.
    ///
    /// Java's `next()` calls `iter.next()` directly (without first calling `iter.hasNext()`),
    /// catching both `IOException` (reported to `errHandler`) and `NoSuchElementException`
    /// (silently swallowed) and returning `null` either way. This port's
    /// [`DBFieldIterator::next`] already reports exhaustion as `Ok(None)` rather than an
    /// exception, so the `NoSuchElementException` catch has no Rust equivalent to reproduce; the
    /// `IOException` -> `errHandler.dbError(e)` -> `null` path is preserved via `Err(e)` ->
    /// [`ErrorHandler::db_error`] -> `None`.
    fn next(&mut self) -> Option<Address> {
        match self.iter.next() {
            Ok(Some(field)) => Some(self.addr_map.decode_address(field.get_long_value())),
            Ok(None) => None,
            Err(e) => {
                self.err_handler.db_error(e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::Field;
    use crate::program::model::address::{
        AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use std::io;
    use std::sync::Arc;

    /// Minimal `AddressMap` test double: an identity mapping between an address's offset and its
    /// key, within a single address space. Java's tests build a real `AddressMapDB` backed by a
    /// live `DBHandle`; this port's iterator tests only need `AddressMap::decode_address`, so this
    /// supplies a deterministic stand-in rather than pulling in the full `AddressMapDB` machinery
    /// (mirroring `program::database::map::test_support::TestAddressMap`, which is private to the
    /// `map` module and so not reusable from here).
    struct TestAddressMap {
        space: Arc<AddressSpace>,
    }

    impl TestAddressMap {
        fn new(space: Arc<AddressSpace>) -> Self {
            TestAddressMap { space }
        }
    }

    impl AddressMap for TestAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], addr: Option<&Address>) -> i32 {
            match addr {
                None => -1,
                Some(_) => -1,
            }
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(self.space.clone(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(TestAddressMap { space: self.space.clone() })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(self.space.clone(), 0)
        }
    }

    struct VecFieldIterator {
        values: Vec<Field>,
        pos: usize,
    }

    impl DBFieldIterator for VecFieldIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.values.len())
        }
        fn has_previous(&mut self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }
        fn next(&mut self) -> io::Result<Option<Field>> {
            if self.pos >= self.values.len() {
                return Ok(None);
            }
            let v = self.values[self.pos].clone();
            self.pos += 1;
            Ok(Some(v))
        }
        fn previous(&mut self) -> io::Result<Option<Field>> {
            if self.pos == 0 {
                return Ok(None);
            }
            self.pos -= 1;
            Ok(Some(self.values[self.pos].clone()))
        }
        fn delete(&mut self) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct FailingFieldIterator;
    impl DBFieldIterator for FailingFieldIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn has_previous(&mut self) -> io::Result<bool> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn next(&mut self) -> io::Result<Option<Field>> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn previous(&mut self) -> io::Result<Option<Field>> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn delete(&mut self) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct CollectingHandler {
        errors: std::cell::RefCell<Vec<String>>,
    }
    impl ErrorHandler for CollectingHandler {
        fn db_error(&self, e: io::Error) {
            self.errors.borrow_mut().push(e.to_string());
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn iterates_decoded_addresses_in_order() {
        let addr_map = TestAddressMap::new(space());
        let iter = Box::new(VecFieldIterator {
            values: vec![Field::Long(Some(1)), Field::Long(Some(2)), Field::Long(Some(3))],
            pos: 0,
        });
        let handler = CollectingHandler { errors: std::cell::RefCell::new(Vec::new()) };
        let mut it = IndexedAddressIterator::new(iter, &addr_map, 0, &handler);

        let s = space();
        assert_eq!(it.next(), Some(s.address(1)));
        assert_eq!(it.next(), Some(s.address(2)));
        assert_eq!(it.next(), Some(s.address(3)));
        assert_eq!(it.next(), None);
        assert!(handler.errors.borrow().is_empty());
    }

    #[test]
    fn empty_iterator_yields_nothing() {
        let addr_map = TestAddressMap::new(space());
        let iter = Box::new(VecFieldIterator { values: vec![], pos: 0 });
        let handler = CollectingHandler { errors: std::cell::RefCell::new(Vec::new()) };
        let mut it = IndexedAddressIterator::new(iter, &addr_map, 0, &handler);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn io_error_reports_to_handler_and_yields_none() {
        let addr_map = TestAddressMap::new(space());
        let handler = CollectingHandler { errors: std::cell::RefCell::new(Vec::new()) };
        let mut it = IndexedAddressIterator::new(Box::new(FailingFieldIterator), &addr_map, 0, &handler);
        assert_eq!(it.next(), None);
        assert_eq!(handler.errors.borrow().len(), 1);
    }

    #[test]
    fn col_index_argument_is_accepted_but_has_no_effect() {
        // Faithful quirk: Java's constructor takes a `colIndex` parameter but never stores it on
        // a field; two iterators built with different col_index values over the same data behave
        // identically.
        let addr_map = TestAddressMap::new(space());
        let handler = CollectingHandler { errors: std::cell::RefCell::new(Vec::new()) };
        let mut it_a = IndexedAddressIterator::new(
            Box::new(VecFieldIterator { values: vec![Field::Long(Some(7))], pos: 0 }),
            &addr_map,
            0,
            &handler,
        );
        let mut it_b = IndexedAddressIterator::new(
            Box::new(VecFieldIterator { values: vec![Field::Long(Some(7))], pos: 0 }),
            &addr_map,
            99,
            &handler,
        );
        assert_eq!(it_a.next(), it_b.next());
    }
}
