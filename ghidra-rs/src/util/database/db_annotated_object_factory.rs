//! Mirrors `ghidra.util.database.DBAnnotatedObjectFactory`: the strategy a
//! `DBCachedObjectStore<T>` uses to construct the objects it manages.
//!
//! The Java interface is a single-method functional interface (`create(DBCachedObjectStore<T>,
//! DBRecord)`); it never calls a method on the store it receives, only hands it along to the
//! constructed object, so the store parameter is represented by the
//! [`DBCachedObjectStore`](crate::util::seam_stubs::DBCachedObjectStore) marker placeholder
//! until the real cached-object store is ported.

use crate::framework::db::record::DBRecord;
use crate::util::database::db_annotated_object::DBAnnotatedObject;
use crate::util::seam_stubs::DBCachedObjectStore;

/// Needed by a `DBCachedObjectStore` to describe how to construct the objects it manages,
/// mirroring `DBAnnotatedObjectFactory<T extends DBAnnotatedObject>`.
pub trait DBAnnotatedObjectFactory<T: DBAnnotatedObject>: Send + Sync {
    /// Mirrors `create(DBCachedObjectStore<T>, DBRecord)`.
    fn create(&self, store: &dyn DBCachedObjectStore<T>, record: DBRecord) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockObject {
        key: i64,
        value: i64,
    }
    impl crate::program::database::db_object::DbObject for MockObject {
        fn state(&self) -> &crate::program::database::db_object::DbObjectState {
            unimplemented!("not exercised by this smoke test")
        }
        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl DBAnnotatedObject for MockObject {
        fn store(&self) -> &dyn crate::util::seam_stubs::DBCachedObjectStoreCore {
            unimplemented!("not exercised by this smoke test")
        }
        fn adapter(&self) -> &dyn crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter {
            unimplemented!("not exercised by this smoke test")
        }
        fn codecs(&self) -> &[Box<dyn crate::util::seam_stubs::DBFieldCodec>] {
            &[]
        }
        fn record(&self) -> DBRecord {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_record(&self, _record: DBRecord) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockStore;
    impl DBCachedObjectStore<MockObject> for MockStore {}

    struct MockObjectFactory;
    impl DBAnnotatedObjectFactory<MockObject> for MockObjectFactory {
        fn create(&self, _store: &dyn DBCachedObjectStore<MockObject>, record: DBRecord) -> MockObject {
            let Field::Long(Some(key)) = *record.get_key() else {
                panic!("expected long key");
            };
            MockObject {
                key,
                value: record.get_long(0).expect("VALUE column"),
            }
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

    #[test]
    fn object_safe_and_builds_from_record() {
        let mut record = DBRecord::new(schema(), Field::Long(Some(42)));
        record.set_long(0, 100);

        let factory: Box<dyn DBAnnotatedObjectFactory<MockObject>> = Box::new(MockObjectFactory);
        let store = MockStore;
        let obj = factory.create(&store, record);

        assert_eq!(obj.key, 42);
        assert_eq!(obj.value, 100);
    }
}
