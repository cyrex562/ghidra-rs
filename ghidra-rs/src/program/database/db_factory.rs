use crate::framework::db::DBRecord;
use crate::program::database::db_object::DbObject;

/// Interface for factories that create `DbObject`s. Required by `DbCache`.
///
/// NOTE: This factory is used to instantiate `DbObject` instances that are already backed
/// by records in the database. In general, these methods should only be used by the
/// `DbCache` class to ensure that the objects aren't already cached; if they are created using
/// this factory, they are added to the cache in a thread safe way.
///
/// Port of `ghidra.program.database.DbFactory`.
pub trait DbFactory<T: DbObject> {
    /// Creates a new database object of type `T` for the given key. It is
    /// expected that a record for this object already exists in the database. This method is
    /// simply creating the unique instance that is associated with that record.
    ///
    /// Returns the newly created instance of type `T`, or `None` if no record was found.
    fn instantiate(&self, key: i64) -> Option<T>;

    /// Creates a new database object of type `T` for the given record.
    fn instantiate_from_record(&self, record: &DBRecord) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::db_object::DbObjectState;
    use std::sync::Arc;

    struct MockDbObject {
        state: DbObjectState,
    }

    impl DbObject for MockDbObject {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    struct MockDbFactory {
        schema: Arc<Schema>,
    }

    impl DbFactory<MockDbObject> for MockDbFactory {
        fn instantiate(&self, key: i64) -> Option<MockDbObject> {
            if key < 0 {
                return None;
            }
            Some(MockDbObject {
                state: DbObjectState::new(key),
            })
        }

        fn instantiate_from_record(&self, record: &DBRecord) -> MockDbObject {
            let key = match record.get_key() {
                Field::Long(Some(value)) => *value,
                _ => -1,
            };
            MockDbObject {
                state: DbObjectState::new(key),
            }
        }
    }

    fn make_factory() -> MockDbFactory {
        MockDbFactory {
            schema: Arc::new(Schema::new(
                0,
                FieldType::Long,
                "key".to_string(),
                vec![],
                vec![],
                vec![],
            )),
        }
    }

    #[test]
    fn instantiate_by_key_returns_object() {
        let factory = make_factory();
        let obj = factory.instantiate(42).expect("expected an object");
        assert_eq!(obj.get_key(), 42);
    }

    #[test]
    fn instantiate_by_key_returns_none_when_missing() {
        let factory = make_factory();
        assert!(factory.instantiate(-1).is_none());
    }

    #[test]
    fn instantiate_from_record_uses_record_key() {
        let factory = make_factory();
        let record = DBRecord::new(factory.schema.clone(), Field::Long(Some(7)));
        let obj = factory.instantiate_from_record(&record);
        assert_eq!(obj.get_key(), 7);
    }
}
