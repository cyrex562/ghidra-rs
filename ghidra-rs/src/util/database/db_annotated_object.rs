//! Port of `ghidra.util.database.DBAnnotatedObject`: an object backed by a `DBRecord`.
//!
//! Essentially, this is a data access object (DAO) for Ghidra's custom database engine. Not all
//! object fields necessarily have a corresponding database field. Instead, those fields are
//! annotated (see [`DBAnnotatedField`](super::annot::DBAnnotatedField)), and various methods are
//! provided for updating the record, and conversely, re-loading fields from the record. These
//! objects are managed by a `DBCachedObjectStore`.
//!
//! The Java class is a concrete base class carrying `store`/`adapter`/`codecs`/`record` fields
//! and a two-argument constructor; this port turns it into a trait so that cycle-cutting
//! consumers can depend on the *shape* of an annotated object without depending on the concrete
//! store/adapter/codec machinery. Implementors expose those fields through the required accessor
//! methods below, and get the record-update/refresh machinery (`update`, `reload_fields`,
//! `refresh_locked`, `get_object_key`, `table_name`, `currently_deleted`) as default methods built
//! on top of them, mirroring the Java instance methods.
//!
//! Two renames avoid name collisions with the [`DbObject`] supertrait, which every implementor
//! also carries: Java's `DBAnnotatedObject.refresh(DBRecord)` (the override of
//! `DbObject.refresh(DBRecord)`) becomes [`refresh_locked`](DBAnnotatedObject::refresh_locked) --
//! implementors' own `DbObject::refresh` should simply delegate to it -- and Java's zero-argument
//! `isDeleted()` becomes [`currently_deleted`](DBAnnotatedObject::currently_deleted), distinct
//! from the inherited [`DbObject::is_deleted`], which takes an explicit lock.
//!
//! Java's four overloads of `update` (1-, 2-, 3-arity, and varargs) collapse into the single
//! slice-taking [`update`](DBAnnotatedObject::update), since Rust has no overloading.

use std::io;

use crate::framework::db::record::DBRecord;
use crate::program::database::db_object::DbObject;
use crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter;
use crate::util::database::db_object_column::DBObjectColumn;
use crate::util::lock_hold::LockHold;
use crate::trace::seam_stubs::ObjectKey;
use crate::util::seam_stubs::{DBCachedObjectStoreCore, DBFieldCodec};

/// An object backed by a `DBRecord`, mirroring `ghidra.util.database.DBAnnotatedObject`.
pub trait DBAnnotatedObject: DbObject {
    /// The store containing this object, mirroring the `store` field.
    ///
    /// Only the operations independent of the store's managed object type are exposed here (see
    /// [`DBCachedObjectStoreCore`]'s doc comment for why).
    fn store(&self) -> &dyn DBCachedObjectStoreCore;

    /// The domain object owning this object's table, mirroring the `adapter` field.
    fn adapter(&self) -> &dyn DBCachedDomainObjectAdapter;

    /// The field codecs, ordered by column number, mirroring the `codecs` field.
    fn codecs(&self) -> &[Box<dyn DBFieldCodec>];

    /// The backing record, mirroring the `record` field.
    fn record(&self) -> DBRecord;

    /// Replaces the backing record, mirroring assignment to the `record` field.
    fn set_record(&self, record: DBRecord);

    /// Get an opaque unique id for this object, whose hash is immutable, mirroring
    /// `getObjectKey()`.
    fn get_object_key(&self) -> Box<dyn ObjectKey> {
        self.store().object_key(self.get_key())
    }

    /// Encodes the field for `column` into the record, mirroring `doWrite(DBObjectColumn)`.
    ///
    /// Requires `Self: Sized` (like the other update/refresh helpers below) because it must
    /// coerce `self` to `&dyn DBAnnotatedObject` to hand to a codec; this mirrors these methods
    /// being `protected` in Java -- reachable only from within a concrete implementation, never
    /// through a `dyn DBAnnotatedObject`.
    fn do_write(&self, column: &dyn DBObjectColumn)
    where
        Self: Sized,
    {
        let mut record = self.record();
        {
            let codec = &self.codecs()[column.column_number() as usize];
            codec.store(self, &mut record);
        }
        self.set_record(record);
    }

    /// Writes the given columns into the record and updates the table, mirroring
    /// `update(DBObjectColumn...)` (and its 1-, 2-, and 3-arity overloads).
    fn update(&self, columns: &[&dyn DBObjectColumn])
    where
        Self: Sized,
    {
        for column in columns {
            self.do_write(*column);
        }
        let _hold = LockHold::lock(self.store().write_lock());
        if let Err(e) = self.do_updated() {
            self.store().db_error(e);
        }
    }

    /// Encodes every field into the record and updates the table, mirroring `doUpdateAll()`.
    fn do_update_all(&self) -> io::Result<()>
    where
        Self: Sized,
    {
        let mut record = self.record();
        for codec in self.codecs() {
            codec.store(self, &mut record);
        }
        self.set_record(record);
        self.do_updated()
    }

    /// Persists the current record to the table, mirroring `doUpdated()`.
    fn do_updated(&self) -> io::Result<()> {
        let record = self.record();
        self.store().put_record(&record)
    }

    /// Extension point: called when the object's fields are populated. Provides an opportunity
    /// to initialize any non-database-backed fields that depend on the database-backed ones.
    /// Mirrors `fresh(boolean)`. Does nothing by default.
    fn fresh(&self, created: bool) -> io::Result<()> {
        let _ = created;
        Ok(())
    }

    /// Returns `rec` if given, otherwise fetches this object's current record from the table,
    /// mirroring `getFreshRecord(DBRecord)`.
    fn get_fresh_record(&self, rec: Option<DBRecord>) -> io::Result<Option<DBRecord>> {
        if rec.is_some() {
            return Ok(rec);
        }
        self.store().get_record(self.get_key())
    }

    /// Reloads every field from `rec` (or the table, if `rec` is `None`), mirroring
    /// `doRefresh(DBRecord)`. Returns `Ok(false)` if no record could be found (the object has
    /// been deleted).
    fn reload_fields(&self, rec: Option<&DBRecord>) -> io::Result<bool>
    where
        Self: Sized,
    {
        let rec = match self.get_fresh_record(rec.cloned())? {
            Some(r) => r,
            None => return Ok(false),
        };
        for codec in self.codecs() {
            codec.load(self, &rec)?;
        }
        self.set_record(rec);
        self.fresh(false)?;
        Ok(true)
    }

    /// Reloads this object's fields under the store's read lock, mirroring the
    /// `DBAnnotatedObject` override of `DbObject.refresh(DBRecord)`. Implementors' own
    /// `DbObject::refresh` should delegate here, e.g. `fn refresh(&self, r) -> bool {
    /// self.refresh_locked(r) }`.
    fn refresh_locked(&self, rec: Option<&DBRecord>) -> bool
    where
        Self: Sized,
    {
        let _hold = LockHold::lock(self.store().read_lock());
        match self.reload_fields(rec) {
            Ok(refreshed) => refreshed,
            Err(e) => {
                self.store().db_error(e);
                false
            }
        }
    }

    /// Check if this object has been deleted, mirroring the zero-argument `isDeleted()`.
    ///
    /// The Java method delegates to `DbObject.isDeleted(adapter.getLock())`, using the domain
    /// object's transaction-wide lock. [`DBCachedDomainObjectAdapter`] only exposes its
    /// degenerate `readWriteLock` (see its doc comment), not that lock, so this reimplements the
    /// equivalent check (deleted flag, else validate-and-refresh under a lock) against the
    /// read-write lock instead.
    fn currently_deleted(&self) -> bool {
        if self.state().is_deleted_flag() {
            return true;
        }
        if self.is_valid() {
            return false;
        }
        let _hold = LockHold::lock(self.adapter().get_read_write_lock());
        !self.refresh_if_needed()
    }

    /// Mirrors `getTableName()`.
    fn table_name(&self) -> String {
        self.store().get_table_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use crate::framework::db::util::ErrorHandler;
    use crate::program::database::db_object::DbObjectState;
    use crate::util::lock_hold::Lock as HoldLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct NoopLock;
    impl HoldLock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockAdapter {
        lock: NoopLock,
    }
    impl crate::framework::model::DomainObject for MockAdapter {}
    impl ErrorHandler for MockAdapter {
        fn db_error(&self, _e: io::Error) {}
    }
    impl crate::framework::data::DomainObjectAdapterDB for MockAdapter {
        fn get_db_handle(&self) -> &crate::framework::db::DBHandle {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::framework::seam_stubs::DBDomainObjectSupport for MockAdapter {
        fn init(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl DBCachedDomainObjectAdapter for MockAdapter {
        fn get_read_write_lock(&self) -> &dyn HoldLock {
            &self.lock
        }
    }

    /// A `DBFieldCodec` that stores/loads a single `i64` "value" column, holding the value
    /// itself (rather than reaching back into the concrete `DBAnnotatedObject`, which the trait
    /// object reference given to `store`/`load` cannot be downcast from).
    struct ValueCodec(Arc<std::sync::atomic::AtomicI64>);
    impl DBFieldCodec for ValueCodec {
        fn store(&self, _obj: &dyn DBAnnotatedObject, record: &mut DBRecord) {
            record.set_long(0, self.0.load(Ordering::SeqCst));
        }

        fn load(&self, _obj: &dyn DBAnnotatedObject, record: &DBRecord) -> io::Result<()> {
            self.0.store(record.get_long(0).unwrap_or_default(), Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockStore {
        lock: NoopLock,
        table_name: String,
        table: Mutex<std::collections::HashMap<i64, DBRecord>>,
        db_errors: AtomicUsize,
    }

    impl ErrorHandler for MockStore {
        fn db_error(&self, _e: io::Error) {
            self.db_errors.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl DBCachedObjectStoreCore for MockStore {
        fn read_lock(&self) -> &dyn HoldLock {
            &self.lock
        }

        fn write_lock(&self) -> &dyn HoldLock {
            &self.lock
        }

        fn get_table_name(&self) -> String {
            self.table_name.clone()
        }

        fn put_record(&self, record: &DBRecord) -> io::Result<()> {
            let Field::Long(Some(key)) = *record.get_key() else {
                panic!("expected long key");
            };
            self.table.lock().unwrap().insert(key, record.clone());
            Ok(())
        }

        fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.table.lock().unwrap().get(&key).cloned())
        }

        fn object_key(&self, key: i64) -> Box<dyn ObjectKey> {
            struct SimpleKey(i64);
            impl ObjectKey for SimpleKey {
                fn equals(&self, obj: &dyn std::any::Any) -> bool {
                    obj.downcast_ref::<SimpleKey>().is_some_and(|o| o.0 == self.0)
                }
                fn hash_code(&self) -> i32 {
                    self.0 as i32
                }
                fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
                    (self.hash_code() - that.hash_code()) as i32
                }
            }
            Box::new(SimpleKey(key))
        }
    }

    /// A minimal `DBAnnotatedObject`, standing in for the example `DBPerson` from the Java
    /// class's documentation: a single database-backed `value` field, reloadable via
    /// [`ValueCodec`].
    struct DBPerson {
        state: DbObjectState,
        store: Arc<MockStore>,
        adapter: Arc<MockAdapter>,
        codecs: Vec<Box<dyn DBFieldCodec>>,
        record: Mutex<DBRecord>,
        value: Arc<std::sync::atomic::AtomicI64>,
    }

    impl DBPerson {
        fn new(store: Arc<MockStore>, adapter: Arc<MockAdapter>, record: DBRecord) -> Self {
            let Field::Long(Some(key)) = *record.get_key() else {
                panic!("expected long key");
            };
            let value = Arc::new(std::sync::atomic::AtomicI64::new(record.get_long(0).unwrap_or_default()));
            DBPerson {
                state: DbObjectState::new(key),
                store,
                adapter,
                codecs: vec![Box::new(ValueCodec(value.clone()))],
                record: Mutex::new(record),
                value,
            }
        }
    }

    impl DbObject for DBPerson {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, record: Option<&DBRecord>) -> bool {
            self.refresh_locked(record)
        }
    }

    impl DBAnnotatedObject for DBPerson {
        fn store(&self) -> &dyn DBCachedObjectStoreCore {
            self.store.as_ref()
        }

        fn adapter(&self) -> &dyn DBCachedDomainObjectAdapter {
            self.adapter.as_ref()
        }

        fn codecs(&self) -> &[Box<dyn DBFieldCodec>] {
            &self.codecs
        }

        fn record(&self) -> DBRecord {
            self.record.lock().unwrap().clone()
        }

        fn set_record(&self, record: DBRecord) {
            *self.record.lock().unwrap() = record;
        }
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "KEY".to_string(),
            vec![FieldType::Long],
            vec!["VALUE".to_string()],
            vec![],
        ))
    }

    fn store_and_adapter() -> (Arc<MockStore>, Arc<MockAdapter>) {
        (
            Arc::new(MockStore {
                lock: NoopLock,
                table_name: "Person".to_string(),
                table: Mutex::new(std::collections::HashMap::new()),
                db_errors: AtomicUsize::new(0),
            }),
            Arc::new(MockAdapter { lock: NoopLock }),
        )
    }

    #[test]
    fn object_safe_and_reports_table_name() {
        let (store, adapter) = store_and_adapter();
        let record = DBRecord::new(schema(), Field::Long(Some(1)));
        let person: Box<dyn DBAnnotatedObject> = Box::new(DBPerson::new(store, adapter, record));
        assert_eq!(person.table_name(), "Person");
        assert_eq!(person.get_key(), 1);
    }

    #[test]
    fn update_writes_the_column_and_persists_the_record() {
        let (store, adapter) = store_and_adapter();
        let record = DBRecord::new(schema(), Field::Long(Some(7)));
        let person = DBPerson::new(store.clone(), adapter, record);
        person.value.store(42, Ordering::SeqCst);

        let column = crate::util::database::db_object_column::get(0);
        person.update(&[column.as_ref()]);

        let stored = store.table.lock().unwrap().get(&7).cloned().expect("record persisted");
        assert_eq!(stored.get_long(0), Some(42));
    }

    #[test]
    fn reload_fields_pulls_the_value_back_from_a_fresh_record() {
        let (store, adapter) = store_and_adapter();
        let mut record = DBRecord::new(schema(), Field::Long(Some(3)));
        record.set_long(0, 99);
        store.table.lock().unwrap().insert(3, record.clone());

        let person = DBPerson::new(store, adapter, record);
        assert_eq!(person.value.load(Ordering::SeqCst), 99);

        person.value.store(0, Ordering::SeqCst);
        assert!(person.reload_fields(None).unwrap());
        assert_eq!(person.value.load(Ordering::SeqCst), 99);
    }

    #[test]
    fn refresh_locked_reports_deletion_when_no_record_remains() {
        let (store, adapter) = store_and_adapter();
        let record = DBRecord::new(schema(), Field::Long(Some(9)));
        // Never inserted into the store's table, so a keyed lookup finds nothing.
        let person = DBPerson::new(store, adapter, record);

        assert!(!person.refresh_locked(None));
    }
}
