use crate::framework::data::domain_object_db_change_set::DomainObjectDBChangeSet;
use crate::framework::db::util::ErrorHandler;
use crate::framework::db::DBHandle;
use crate::framework::model::DomainObject;

/// Maximum number of undo entries retained by default, mirroring
/// `DomainObjectAdapterDB.NUM_UNDOS`.
pub const NUM_UNDOS: i32 = 50;

/// Database version of the `DomainObjectAdapter`. Adds the concept of starting a transaction
/// before a change is made to the domain object and ending the transaction. The transaction
/// allows for undo/redo changes.
///
/// Port of `ghidra.framework.data.DomainObjectAdapterDB`.
///
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that declared
/// no methods, so there is nothing to retain as a superset here. In Java this type is an abstract
/// class that both extends `DomainObjectAdapter` (an intermediate class not yet ported) and
/// implements `DomainObject`; here it is mapped as a Rust trait bounded by [`DomainObject`]
/// directly, since `DomainObjectAdapter`'s own contribution is just a concrete field-backed
/// implementation of the `DomainObject` interface with no additional public surface of its own.
/// The many `DomainObject` methods this class overrides with transaction-manager-backed behavior
/// (`openTransaction`, `startTransaction`, `undo`, `redo`, `lock`, `save`, `close`, etc.) are
/// already declared with default bodies on [`DomainObject`] itself, so they are not redeclared
/// here; concrete implementations of this trait will override those `DomainObject` defaults
/// directly once the transaction-manager subsystem (`AbstractTransactionManager` and friends) is
/// ported. Only the members genuinely new to `DomainObjectAdapterDB` -- the database handle,
/// change set, write-cache hooks, and undo-stack depth query -- are declared here.
///
/// `implements ErrorHandler` is mapped as a supertrait bound; its one method, `dbError`, is
/// already ported as [`ErrorHandler::db_error`].
pub trait DomainObjectAdapterDB: DomainObject + ErrorHandler {
    /// Gets the open handle to the underlying database.
    fn get_db_handle(&self) -> &DBHandle;

    /// Returns the change set corresponding to all unsaved changes in this domain object, or
    /// `None` if no change set has been established, mirroring the Java field's default `null`
    /// value.
    fn get_change_set(&self) -> Option<&dyn DomainObjectDBChangeSet> {
        None
    }

    /// Flush any pending database changes. This method is invoked by the transaction manager
    /// prior to closing a transaction. Does nothing by default.
    fn flush_write_cache(&mut self) {}

    /// Invalidate (i.e., clear) any pending database changes not yet written. This method is
    /// invoked by the transaction manager prior to aborting a transaction. Does nothing by
    /// default.
    fn invalidate_write_cache(&mut self) {}

    /// Returns the undo stack depth (the number of items on the undo stack). This method is for
    /// JUnits.
    fn get_undo_stack_depth(&self) -> i32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainObjectAdapterDB {
        dbh: DBHandle,
        change_set: Option<Box<dyn DomainObjectDBChangeSet>>,
        write_cache_flushed: usize,
        write_cache_invalidated: usize,
        undo_stack_depth: i32,
        last_error: std::cell::Cell<Option<String>>,
    }

    impl MockDomainObjectAdapterDB {
        fn new() -> Self {
            Self {
                dbh: DBHandle::new().unwrap(),
                change_set: None,
                write_cache_flushed: 0,
                write_cache_invalidated: 0,
                undo_stack_depth: 0,
                last_error: std::cell::Cell::new(None),
            }
        }
    }

    impl DomainObject for MockDomainObjectAdapterDB {}

    impl ErrorHandler for MockDomainObjectAdapterDB {
        fn db_error(&self, e: std::io::Error) {
            self.last_error.set(Some(e.to_string()));
        }
    }

    impl DomainObjectAdapterDB for MockDomainObjectAdapterDB {
        fn get_db_handle(&self) -> &DBHandle {
            &self.dbh
        }

        fn get_change_set(&self) -> Option<&dyn DomainObjectDBChangeSet> {
            self.change_set.as_deref()
        }

        fn flush_write_cache(&mut self) {
            self.write_cache_flushed += 1;
        }

        fn invalidate_write_cache(&mut self) {
            self.write_cache_invalidated += 1;
        }

        fn get_undo_stack_depth(&self) -> i32 {
            self.undo_stack_depth
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut obj = MockDomainObjectAdapterDB::new();
        obj.undo_stack_depth = 3;

        let dyn_obj: &mut dyn DomainObjectAdapterDB = &mut obj;
        assert!(dyn_obj.get_change_set().is_none());
        assert_eq!(dyn_obj.get_undo_stack_depth(), 3);

        dyn_obj.flush_write_cache();
        dyn_obj.invalidate_write_cache();
        dyn_obj.db_error(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));

        assert_eq!(obj.write_cache_flushed, 1);
        assert_eq!(obj.write_cache_invalidated, 1);
        assert_eq!(obj.last_error.take(), Some("disk full".to_string()));
    }

    #[test]
    fn default_change_set_is_none_and_undo_stack_depth_is_zero() {
        let obj = MockDomainObjectAdapterDB::new();
        assert!(obj.get_change_set().is_none());
        assert_eq!(obj.get_undo_stack_depth(), 0);
    }
}
