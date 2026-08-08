//! The database-backed [`TraceEquate`].
//!
//! Port of `ghidra.trace.database.symbol.DBTraceEquate`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends DBAnnotatedObject implements TraceEquate`. Nearly every public method
//! it declares is just an override satisfying [`TraceEquate`], whose full surface is already
//! ported; the two members below are what `DBTraceEquate` actually adds on top of its
//! supertraits:
//!
//! - the package-private `set(String, long)` setter, which the owning `DBTraceEquateManager`
//!   uses to (re)name/revalue an equate record (and which the Java constructor's caller relies
//!   on to populate a freshly-created row);
//! - the public, non-override `getReferences(Address)` overload, which returns the raw stored
//!   [`EquateReference`]s at one address, distinct from [`TraceEquate::get_references`], which is
//!   scoped by lifespan/thread and returns [`TraceEquateReference`]-trait-object references.
//!
//! The Java constructor (`DBTraceEquateManager`, `DBCachedObjectStore<DBTraceEquate>`,
//! `DBRecord`) and the `manager` field it stashes are construction/bookkeeping details, not part
//! of the type's behavioral surface, so they aren't represented here -- consistent with this
//! being a trait rather than a struct port.
//!
//! [`TraceEquateReference`]: crate::trace::model::symbol::trace_equate_reference::TraceEquateReference

use crate::program::database::symbol::equate_store::EquateReference;
use crate::program::model::address::Address;
use crate::trace::model::symbol::trace_equate::TraceEquate;
use crate::util::database::db_annotated_object::DBAnnotatedObject;

/// The database-backed [`TraceEquate`].
///
/// Port of `ghidra.trace.database.symbol.DBTraceEquate`.
pub trait DBTraceEquate: TraceEquate + DBAnnotatedObject {
    /// (Re)name and revalue this equate, mirroring the package-private `set(String, long)`.
    fn set(&mut self, name: &str, value: i64);

    /// Get the stored equate references at the given address, mirroring the public
    /// `getReferences(Address)` overload.
    fn get_references_at(&self, ref_addr: &Address) -> Vec<EquateReference>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;

    use crate::framework::data::DomainObjectAdapterDB;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::db::DBHandle;
    use crate::framework::model::DomainObject;
    use crate::framework::seam_stubs::DBDomainObjectSupport;
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::enum_::Enum;
    use crate::program::model::pcode::Varnode;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_equate_reference::TraceEquateReference;
    use crate::trace::seam_stubs::{ObjectKey, TraceThread};
    use crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter;
    use crate::util::database::db_object_column::DBObjectColumn;
    use crate::util::lock_hold::Lock;
    use crate::util::seam_stubs::{DBCachedObjectStoreCore, DBFieldCodec};
    use std::sync::Arc;

    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct DummyKey(i64);
    impl ObjectKey for DummyKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<DummyKey>().is_some_and(|o| o.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0 as i32
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            (self.hash_code() - that.hash_code()) as i32
        }
    }

    struct DummyAdapter {
        lock: NoopLock,
    }
    impl DomainObject for DummyAdapter {}
    impl ErrorHandler for DummyAdapter {
        fn db_error(&self, _e: io::Error) {}
    }
    impl DomainObjectAdapterDB for DummyAdapter {
        fn get_db_handle(&self) -> &DBHandle {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl DBDomainObjectSupport for DummyAdapter {
        fn init(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl DBCachedDomainObjectAdapter for DummyAdapter {
        fn get_read_write_lock(&self) -> &dyn Lock {
            &self.lock
        }
    }

    struct DummyStore {
        lock: NoopLock,
    }
    impl ErrorHandler for DummyStore {
        fn db_error(&self, _e: io::Error) {}
    }
    impl DBCachedObjectStoreCore for DummyStore {
        fn read_lock(&self) -> &dyn Lock {
            &self.lock
        }
        fn write_lock(&self) -> &dyn Lock {
            &self.lock
        }
        fn get_table_name(&self) -> String {
            "Equates".to_string()
        }
        fn put_record(&self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }
        fn get_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn object_key(&self, key: i64) -> Box<dyn ObjectKey> {
            Box::new(DummyKey(key))
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn new_record() -> DBRecord {
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String, FieldType::Long],
            vec!["Name".to_string(), "Value".to_string()],
            Vec::new(),
        ));
        DBRecord::new(schema, Field::Long(Some(1)))
    }

    /// A minimal `DBTraceEquate` backed by the `DBRecord`/`DBAnnotatedObject` machinery, proving
    /// the combined `TraceEquate + DBAnnotatedObject` trait object is object-safe and that the
    /// `set`/`get_references_at` members added on top actually do something (mutate real state,
    /// not just return canned values).
    struct MockDbTraceEquate {
        state: DbObjectState,
        store: DummyStore,
        adapter: DummyAdapter,
        record: Mutex<DBRecord>,
        name: String,
        value: i64,
        references: Vec<EquateReference>,
        deleted: bool,
    }

    impl MockDbTraceEquate {
        fn new(name: &str, value: i64) -> Self {
            MockDbTraceEquate {
                state: DbObjectState::new(1),
                store: DummyStore { lock: NoopLock },
                adapter: DummyAdapter { lock: NoopLock },
                record: Mutex::new(new_record()),
                name: name.to_string(),
                value,
                references: Vec::new(),
                deleted: false,
            }
        }
    }

    impl DbObject for MockDbTraceEquate {
        fn state(&self) -> &DbObjectState {
            &self.state
        }
        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    impl DBAnnotatedObject for MockDbTraceEquate {
        fn store(&self) -> &dyn DBCachedObjectStoreCore {
            &self.store
        }
        fn adapter(&self) -> &dyn DBCachedDomainObjectAdapter {
            &self.adapter
        }
        fn codecs(&self) -> &[Box<dyn DBFieldCodec>] {
            &[]
        }
        fn record(&self) -> DBRecord {
            self.record.lock().unwrap().clone()
        }
        fn set_record(&self, record: DBRecord) {
            *self.record.lock().unwrap() = record;
        }
    }

    impl TraceEquate for MockDbTraceEquate {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_display_name(&self) -> String {
            self.name.clone()
        }
        fn get_value(&self) -> i64 {
            self.value
        }
        fn get_display_value(&self) -> String {
            format!("0x{:x}", self.value)
        }
        fn get_reference_count(&self) -> i32 {
            self.references.len() as i32
        }
        fn add_reference(
            &mut self,
            _lifespan: Lifespan,
            _thread: Option<Box<dyn TraceThread>>,
            _address: Address,
            _operand_index: i32,
        ) -> Box<dyn TraceEquateReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_reference_varnode(
            &mut self,
            _lifespan: Lifespan,
            _thread: Option<Box<dyn TraceThread>>,
            _address: Address,
            _varnode: Varnode,
        ) -> Box<dyn TraceEquateReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, new_name: &str) {
            self.name = new_name.to_string();
        }
        fn get_references(&self) -> Vec<Box<dyn TraceEquateReference>> {
            Vec::new()
        }
        fn get_reference(
            &self,
            _snap: i64,
            _thread: Option<&dyn TraceThread>,
            _address: &Address,
            _operand_index: i32,
        ) -> Option<Box<dyn TraceEquateReference>> {
            None
        }
        fn get_reference_varnode(
            &self,
            _snap: i64,
            _thread: Option<&dyn TraceThread>,
            _address: &Address,
            _varnode: &Varnode,
        ) -> Option<Box<dyn TraceEquateReference>> {
            None
        }
        fn has_valid_enum(&self) -> bool {
            false
        }
        fn is_enum_based(&self) -> bool {
            false
        }
        fn get_enum(&self) -> Option<Box<dyn Enum>> {
            None
        }
        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    impl DBTraceEquate for MockDbTraceEquate {
        fn set(&mut self, name: &str, value: i64) {
            self.name = name.to_string();
            self.value = value;
        }
        fn get_references_at(&self, ref_addr: &Address) -> Vec<EquateReference> {
            self.references.iter().filter(|r| &r.address == ref_addr).cloned().collect()
        }
    }

    #[test]
    fn set_updates_name_and_value_through_the_trait_object() {
        let mut equate = MockDbTraceEquate::new("FOO", 1);
        {
            let boxed: &mut dyn DBTraceEquate = &mut equate;
            assert_eq!(boxed.get_name(), "FOO");
            assert_eq!(boxed.get_value(), 1);

            boxed.set("BAR", 42);
            assert_eq!(boxed.get_name(), "BAR");
            assert_eq!(boxed.get_value(), 42);

            // The `DBAnnotatedObject` supertrait surface is also reachable through the same
            // trait object.
            assert_eq!(boxed.table_name(), "Equates");

            boxed.delete();
        }
        assert!(equate.deleted);
    }

    #[test]
    fn get_references_at_filters_by_address() {
        let mut equate = MockDbTraceEquate::new("FLAG", 0x10);
        let addr1 = addr(0x400);
        let addr2 = addr(0x800);
        equate.references.push(EquateReference {
            address: addr1.clone(),
            op_index: Some(0),
            dynamic_hash: None,
        });
        equate.references.push(EquateReference {
            address: addr2.clone(),
            op_index: Some(1),
            dynamic_hash: None,
        });

        let boxed: Box<dyn DBTraceEquate> = Box::new(equate);
        let found = boxed.get_references_at(&addr1);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, addr1);
        assert!(boxed.get_references_at(&addr2.next().unwrap()).is_empty());
    }
}
