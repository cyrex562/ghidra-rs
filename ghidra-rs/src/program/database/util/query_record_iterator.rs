//! Port of `ghidra.program.database.util.QueryRecordIterator`.
//!
//! Java's `hasNext()`/`hasPrevious()` mutate the cached `record` field (and, transitively, the
//! wrapped `iter`) through a shared method receiver; this port's [`RecordIterator::has_next`] and
//! [`RecordIterator::has_previous`] take `&self`, so the cached record and the wrapped iterator
//! are held behind [`RefCell`] for interior mutability -- the same technique
//! [`AddressKeyAddressIterator`](crate::program::database::map::address_key_address_iterator::AddressKeyAddressIterator)
//! and
//! [`DefaultAddressIteratorConverter`](crate::program::util::address_iterator_converter::DefaultAddressIteratorConverter)
//! use for the analogous problem.
//!
//! # `ClosedException` detection
//!
//! Java's `findNext`/`findPrevious` catch `ClosedException` specifically (silently ending
//! iteration, "just make it look like the iterator is done") and every *other* `IOException`
//! generically (reported via `Msg.showError`). This port's [`RecordIterator::next`]/
//! [`RecordIterator::previous`] report both through the same `std::io::Error` channel, so the
//! distinction is recovered by checking whether the error's inner source downcasts to
//! [`ClosedException`]: callers that want the "closed" branch taken should construct their
//! `io::Error` with a [`ClosedException`] as its source (e.g. via `io::Error::other(..)`),
//! mirroring how a real closed-resource `RecordIterator` implementation would report it.

use std::cell::RefCell;
use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::util::query::Query;
use crate::util::exception::ClosedException;
use crate::util::msg::Msg;

/// Iterator that only returns records from another iterator that match the given query.
///
/// Port of `ghidra.program.database.util.QueryRecordIterator`.
pub struct QueryRecordIterator {
    iter: RefCell<Box<dyn RecordIterator>>,
    query: Box<dyn Query>,
    record: RefCell<Option<DBRecord>>,
    forward: bool,
}

impl QueryRecordIterator {
    /// Constructs a new `QueryRecordIterator` that filters the given record iterator with the
    /// given query, iterating forward.
    ///
    /// Port of `QueryRecordIterator(RecordIterator, Query)`.
    pub fn new(iter: Box<dyn RecordIterator>, query: Box<dyn Query>) -> Self {
        Self::with_direction(iter, query, true)
    }

    /// Constructs a new `QueryRecordIterator` that filters the given record iterator with the
    /// given query.
    ///
    /// Port of `QueryRecordIterator(RecordIterator, Query, boolean)`.
    pub fn with_direction(iter: Box<dyn RecordIterator>, query: Box<dyn Query>, forward: bool) -> Self {
        QueryRecordIterator {
            iter: RefCell::new(iter),
            query,
            record: RefCell::new(None),
            forward,
        }
    }

    /// Port of the private `findNext()`.
    fn find_next(&self) {
        let mut iter = self.iter.borrow_mut();
        loop {
            match iter.next() {
                Ok(Some(rec)) => {
                    if self.query.matches(&rec) {
                        *self.record.borrow_mut() = Some(rec);
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    report_iteration_error(&e);
                    return;
                }
            }
        }
    }

    /// Port of the private `findPrevious()`.
    fn find_previous(&self) {
        let mut iter = self.iter.borrow_mut();
        loop {
            match iter.previous() {
                Ok(Some(rec)) => {
                    if self.query.matches(&rec) {
                        *self.record.borrow_mut() = Some(rec);
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    report_iteration_error(&e);
                    return;
                }
            }
        }
    }
}

/// Port of the shared `catch (ClosedException e) { /* done */ } catch (IOException e) {
/// Msg.showError(...) }` handling in both `findNext`/`findPrevious`. See the module docs for how
/// the `ClosedException`/generic-`IOException` distinction is recovered from a plain
/// `std::io::Error`.
fn report_iteration_error(e: &io::Error) {
    let is_closed = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ClosedException>())
        .is_some();
    if !is_closed {
        Msg::show_error_with_error("QueryRecordIterator", "", &"", e);
    }
}

impl RecordIterator for QueryRecordIterator {
    /// Port of `hasNext()`.
    fn has_next(&self) -> bool {
        if self.record.borrow().is_none() {
            if self.forward {
                self.find_next();
            } else {
                self.find_previous();
            }
        }
        self.record.borrow().is_some()
    }

    /// Port of `next()`.
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        if RecordIterator::has_next(self) {
            Ok(self.record.borrow_mut().take())
        } else {
            Ok(None)
        }
    }

    /// Port of `hasPrevious()`.
    fn has_previous(&self) -> io::Result<bool> {
        if self.record.borrow().is_none() {
            self.find_previous();
        }
        Ok(self.record.borrow().is_some())
    }

    /// Port of `previous()`.
    fn previous(&mut self) -> io::Result<Option<DBRecord>> {
        if RecordIterator::has_previous(self)? {
            Ok(self.record.borrow_mut().take())
        } else {
            Ok(None)
        }
    }

    /// Port of `delete()`.
    fn delete(&mut self) -> io::Result<bool> {
        self.iter.borrow_mut().delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::sync::Arc;

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        pos: isize,
    }

    impl VecRecordIterator {
        fn new(records: Vec<DBRecord>) -> Self {
            let len = records.len();
            // Start "before the beginning" for forward iteration; with `pos == len` it would be
            // positioned "after the end" for backward iteration -- callers pick one direction per
            // test.
            let _ = len;
            Self { records, pos: -1 }
        }

        fn at_end(records: Vec<DBRecord>) -> Self {
            let len = records.len() as isize;
            Self { records, pos: len }
        }
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            let nxt = self.pos + 1;
            if nxt >= self.records.len() as isize {
                return Ok(None);
            }
            self.pos = nxt;
            Ok(Some(self.records[self.pos as usize].clone()))
        }
        fn has_next(&self) -> bool {
            (self.pos + 1) < self.records.len() as isize
        }
        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.pos > 0)
        }
        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.pos <= 0 {
                return Ok(None);
            }
            self.pos -= 1;
            Ok(Some(self.records[self.pos as usize].clone()))
        }
        fn delete(&mut self) -> io::Result<bool> {
            Ok(true)
        }
    }

    struct FailingRecordIterator {
        closed: bool,
    }
    impl RecordIterator for FailingRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            if self.closed {
                Err(io::Error::other(ClosedException::new()))
            } else {
                Err(io::Error::other("boom"))
            }
        }
        fn has_next(&self) -> bool {
            true
        }
        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            self.next()
        }
        fn has_previous(&self) -> io::Result<bool> {
            Ok(true)
        }
    }

    struct EvenKeyQuery;
    impl Query for EvenKeyQuery {
        fn matches(&self, record: &DBRecord) -> bool {
            record.get_key().get_long_value() % 2 == 0
        }
    }

    struct MatchAllQuery;
    impl Query for MatchAllQuery {
        fn matches(&self, _record: &DBRecord) -> bool {
            true
        }
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(0, FieldType::Long, "Key".to_string(), vec![], vec![], vec![]))
    }

    fn rec(key: i64) -> DBRecord {
        DBRecord::new(schema(), Field::Long(Some(key)))
    }

    #[test]
    fn forward_iteration_yields_only_matching_records() {
        let records = vec![rec(1), rec(2), rec(3), rec(4), rec(5)];
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = QueryRecordIterator::new(inner, Box::new(EvenKeyQuery));

        let mut keys = Vec::new();
        while let Some(r) = it.next().unwrap() {
            keys.push(r.get_key().get_long_value());
        }
        assert_eq!(keys, vec![2, 4]);
    }

    #[test]
    fn backward_iteration_yields_only_matching_records() {
        let records = vec![rec(1), rec(2), rec(3), rec(4), rec(5)];
        let inner = Box::new(VecRecordIterator::at_end(records));
        let mut it = QueryRecordIterator::with_direction(inner, Box::new(EvenKeyQuery), false);

        let mut keys = Vec::new();
        while let Some(r) = it.previous().unwrap() {
            keys.push(r.get_key().get_long_value());
        }
        assert_eq!(keys, vec![4, 2]);
    }

    #[test]
    fn has_next_is_idempotent_before_consuming() {
        let records = vec![rec(2)];
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = QueryRecordIterator::new(inner, Box::new(EvenKeyQuery));

        assert!(RecordIterator::has_next(&it));
        assert!(RecordIterator::has_next(&it));
        let r = it.next().unwrap().unwrap();
        assert_eq!(r.get_key().get_long_value(), 2);
        assert!(!RecordIterator::has_next(&it));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn no_matching_records_exhausts_immediately() {
        let records = vec![rec(1), rec(3), rec(5)];
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = QueryRecordIterator::new(inner, Box::new(EvenKeyQuery));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn closed_exception_ends_iteration_without_reporting_an_error() {
        // Faithful quirk: Java's findNext() catches ClosedException specially, silently making
        // the iterator "look done" (no Msg.showError call), unlike a generic IOException.
        let inner = Box::new(FailingRecordIterator { closed: true });
        let mut it = QueryRecordIterator::new(inner, Box::new(MatchAllQuery));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn generic_io_error_also_ends_iteration() {
        let inner = Box::new(FailingRecordIterator { closed: false });
        let mut it = QueryRecordIterator::new(inner, Box::new(MatchAllQuery));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn delete_forwards_to_the_wrapped_iterator() {
        let records = vec![rec(2)];
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it = QueryRecordIterator::new(inner, Box::new(EvenKeyQuery));
        it.next().unwrap();
        assert!(it.delete().unwrap());
    }

    #[test]
    fn object_safe_as_boxed_trait() {
        let records = vec![rec(2), rec(4)];
        let inner = Box::new(VecRecordIterator::new(records));
        let mut it: Box<dyn RecordIterator> =
            Box::new(QueryRecordIterator::new(inner, Box::new(EvenKeyQuery)));
        assert_eq!(it.next().unwrap().unwrap().get_key().get_long_value(), 2);
    }
}
