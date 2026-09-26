//! Port of `ghidra.program.database.map.AddressKeyAddressIterator`.
//!
//! Java implements Ghidra's `AddressIterator` (`hasNext()`/`next()`). Per this port's
//! `AddressIterator` convention (see `program::model::address::iterator`), that becomes a plain
//! `Iterator<Item = Address>` here -- no bespoke trait, no `RefCell`-cached lookahead, since
//! `Iterator::next(&mut self)` already owns the mutation `hasNext()` needed to fake.

use crate::framework::db::DBLongIterator;
use crate::framework::db::util::ErrorHandler;
use crate::program::database::map::address_map::AddressMap;
use crate::program::model::address::Address;

/// Converts an [`DBLongIterator`] of address-encoded keys (e.g. an `AddressKeyIterator` or
/// `AddressIndexKeyIterator`) into an iterator of [`Address`]es.
///
/// Port of `ghidra.program.database.map.AddressKeyAddressIterator`.
pub struct AddressKeyAddressIterator<'a> {
    key_iter: Option<Box<dyn DBLongIterator>>,
    addr_map: &'a dyn AddressMap,
    err_handler: Option<&'a dyn ErrorHandler>,
    forward: bool,
}

impl<'a> AddressKeyAddressIterator<'a> {
    /// Constructs a new iterator.
    ///
    /// * `key_iter` -- address key iterator, may be `None`. All values it produces must decode
    ///   properly with `addr_map`.
    /// * `forward` -- iterate in the direction of increasing addresses.
    /// * `addr_map` -- address map used to decode keys into addresses.
    /// * `err_handler` -- I/O error handler (may be `None`).
    ///
    /// Port of `AddressKeyAddressIterator(DBLongIterator, boolean, AddressMap, ErrorHandler)`.
    pub fn new(
        key_iter: Option<Box<dyn DBLongIterator>>,
        forward: bool,
        addr_map: &'a dyn AddressMap,
        err_handler: Option<&'a dyn ErrorHandler>,
    ) -> Self {
        AddressKeyAddressIterator { key_iter, addr_map, err_handler, forward }
    }
}

impl<'a> Iterator for AddressKeyAddressIterator<'a> {
    type Item = Address;

    /// Port of `hasNext()` + `next()`, which collapse into one method: `Iterator::next` already
    /// returns `Option`, so there is no separate boolean check to keep in sync.
    fn next(&mut self) -> Option<Address> {
        let key_iter = self.key_iter.as_mut()?;
        let has_value = if self.forward { key_iter.has_next() } else { key_iter.has_previous() };
        match has_value {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => {
                if let Some(handler) = self.err_handler {
                    handler.db_error(e);
                }
                return None;
            }
        }
        let value = if self.forward { key_iter.next() } else { key_iter.previous() };
        match value {
            Ok(v) => Some(self.addr_map.decode_address(v)),
            Err(e) => {
                if let Some(handler) = self.err_handler {
                    handler.db_error(e);
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::map::test_support::TestAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::io;

    struct VecLongIterator {
        values: Vec<i64>,
        pos: usize,
    }

    impl DBLongIterator for VecLongIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.values.len())
        }
        fn has_previous(&mut self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }
        fn next(&mut self) -> io::Result<i64> {
            if self.pos < self.values.len() {
                let v = self.values[self.pos];
                self.pos += 1;
                Ok(v)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "no next"))
            }
        }
        fn previous(&mut self) -> io::Result<i64> {
            if self.pos > 0 {
                self.pos -= 1;
                Ok(self.values[self.pos])
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "no previous"))
            }
        }
        fn delete(&mut self) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct FailingIterator;
    impl DBLongIterator for FailingIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn has_previous(&mut self) -> io::Result<bool> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn next(&mut self) -> io::Result<i64> {
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        }
        fn previous(&mut self) -> io::Result<i64> {
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

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn forward_iteration_decodes_addresses_in_order() {
        let addr_map = TestAddressMap::new(space());
        let key_iter = Box::new(VecLongIterator { values: vec![1, 2, 3], pos: 0 });
        let mut iter = AddressKeyAddressIterator::new(Some(key_iter), true, &addr_map, None);

        let s = space();
        assert_eq!(iter.next(), Some(s.address(1)));
        assert_eq!(iter.next(), Some(s.address(2)));
        assert_eq!(iter.next(), Some(s.address(3)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn reverse_iteration_walks_backward() {
        let addr_map = TestAddressMap::new(space());
        let key_iter = Box::new(VecLongIterator { values: vec![1, 2, 3], pos: 3 });
        let mut iter = AddressKeyAddressIterator::new(Some(key_iter), false, &addr_map, None);

        let s = space();
        assert_eq!(iter.next(), Some(s.address(3)));
        assert_eq!(iter.next(), Some(s.address(2)));
        assert_eq!(iter.next(), Some(s.address(1)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn none_key_iter_yields_nothing() {
        let addr_map = TestAddressMap::new(space());
        let mut iter = AddressKeyAddressIterator::new(None, true, &addr_map, None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn io_error_reports_to_handler_and_stops() {
        let addr_map = TestAddressMap::new(space());
        let handler = CollectingHandler { errors: std::cell::RefCell::new(Vec::new()) };
        let mut iter =
            AddressKeyAddressIterator::new(Some(Box::new(FailingIterator)), true, &addr_map, Some(&handler));
        assert_eq!(iter.next(), None);
        assert_eq!(handler.errors.borrow().len(), 1);
    }
}
