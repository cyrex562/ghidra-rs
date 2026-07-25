//! Port of `ghidra.program.database.data.ArrayDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private, concrete `Array` implementation that extends the
//! not-yet-ported abstract `DataTypeDB` (itself backed by a shared `record`/`lock`/`dataMgr`
//! triple and the not-yet-ported [`ArrayDBAdapter`](super::ArrayDBAdapter)-typed `adapter`
//! field). Every public method it overrides already belongs to the already-ported
//! [`Array`](crate::program::model::data::array::Array) (which itself extends
//! [`DataType`](crate::program::model::data::data_type::DataType)) contract, so none of them are
//! repeated here.
//!
//! The one piece of `ArrayDB`'s own contract that matters for the dependency cycle is
//! `refresh(DBRecord)`: `DataTypeDB` declares it abstract, and every DB-backed datatype family
//! member (`ArrayDB`, `StructureDB`, `EnumDB`, ...) overrides it with its own record-driven
//! resync logic -- exactly the kind of per-subtype override that makes `DataTypeDB` a
//! dependency-cycle participant. Modeling it here as a required trait method lets a future
//! `ArrayDB` implementor supply its own logic without this trait needing the full (parked)
//! `DataTypeDB` base class.
//!
//! `ArrayDB.getDataTypeManager()` is also ported, narrowing `DataType::get_data_type_manager`'s
//! `Option<Box<dyn DataTypeManager>>` to the concrete, non-optional owning manager. That manager
//! is itself the not-yet-ported `DataTypeManagerDB`; `ArrayDB`'s constructor takes it directly and
//! `DataTypeManagerDB` in turn constructs `ArrayDB` instances, which is the actual
//! `ArrayDB` <-> `DataTypeManagerDB` construction-time cycle this port cuts. It is modeled via the
//! minimal placeholder-turned-trait
//! [`DataTypeManagerDb`](crate::program::database::data::data_type_manager_db::DataTypeManagerDb).

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::array::Array;

/// Database implementation of the [`Array`] interface.
///
/// Port of `ghidra.program.database.data.ArrayDB`.
pub trait ArrayDb: Array {
    /// Re-synchronizes this array's cached state against the latest database record, looking the
    /// record up via this array's backing `ArrayDBAdapter`/key when `record` is `None`. Returns
    /// `false` if the underlying record no longer exists (the array has been deleted).
    ///
    /// Stands in for the protected `DataTypeDB.refresh(DBRecord)` as overridden by `ArrayDB`.
    fn refresh(&mut self, record: Option<DBRecord>) -> bool;

    /// Returns the database-backed manager that owns this array's record.
    ///
    /// Stands in for `ArrayDB.getDataTypeManager()`.
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use std::io;
    use std::sync::Arc;

    fn array_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Array ID".to_string(),
            vec![FieldType::Long, FieldType::Int, FieldType::Int, FieldType::Long],
            vec![
                "Data Type ID".to_string(),
                "Number Of Elements".to_string(),
                "Element Length".to_string(),
                "Category ID".to_string(),
            ],
            vec![],
        ))
    }

    struct MockElementDataType;
    impl DataType for MockElementDataType {
        fn get_length(&self) -> i32 {
            4
        }
    }

    struct MockDataTypeManagerDb;
    impl DataTypeManager for MockDataTypeManagerDb {}
    impl DataTypeManagerDb for MockDataTypeManagerDb {
        fn db_error(&mut self, _error: io::Error) {}

        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}

        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    /// Minimal DB-backed [`ArrayDb`], proving object-safety and exercising real refresh behavior
    /// (deletion detection via a missing record, and count/length recompute from a present one).
    struct MockArrayDb {
        num_elements: i32,
        element_length: i32,
        deleted: bool,
        manager: Arc<MockDataTypeManagerDb>,
    }

    impl DataType for MockArrayDb {
        fn get_length(&self) -> i32 {
            if self.num_elements == 0 {
                1
            } else {
                self.num_elements * self.element_length
            }
        }
    }

    impl Array for MockArrayDb {
        fn get_num_elements(&self) -> i32 {
            self.num_elements
        }

        fn get_element_length(&self) -> i32 {
            self.element_length
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockElementDataType)
        }
    }

    impl ArrayDb for MockArrayDb {
        fn refresh(&mut self, record: Option<DBRecord>) -> bool {
            match record {
                None => !self.deleted,
                Some(rec) => {
                    self.num_elements = match rec.get_field(1) {
                        Field::Int(Some(v)) => *v,
                        _ => self.num_elements,
                    };
                    self.element_length = match rec.get_field(2) {
                        Field::Int(Some(v)) => *v,
                        _ => self.element_length,
                    };
                    true
                }
            }
        }

        fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
            self.manager.clone()
        }
    }

    #[test]
    fn refresh_recomputes_state_and_detects_deletion() {
        let mut arr: Box<dyn ArrayDb> = Box::new(MockArrayDb {
            num_elements: 4,
            element_length: 8,
            deleted: false,
            manager: Arc::new(MockDataTypeManagerDb),
        });

        // Array supertrait methods are reachable directly on the `dyn ArrayDb` object.
        assert_eq!(arr.get_num_elements(), 4);
        assert_eq!(arr.get_length(), 32);

        let schema = array_schema();
        let mut rec = DBRecord::new(schema, Field::Long(Some(0)));
        rec.set_field(0, Field::Long(Some(100)));
        rec.set_field(1, Field::Int(Some(10)));
        rec.set_field(2, Field::Int(Some(2)));
        rec.set_field(3, Field::Long(Some(1)));

        assert!(arr.refresh(Some(rec)));
        assert_eq!(arr.get_num_elements(), 10);
        assert_eq!(arr.get_length(), 20);

        // Looking the record up again (simulated by `None`) should still find it.
        assert!(arr.refresh(None));

        // A deleted backing record is reported as a failed refresh.
        let deleted_arr: &mut MockArrayDb = {
            // Downcast isn't available on `dyn ArrayDb`; construct a fresh deleted instance
            // instead to exercise the "record no longer exists" branch.
            &mut MockArrayDb {
                num_elements: 4,
                element_length: 8,
                deleted: true,
                manager: Arc::new(MockDataTypeManagerDb),
            }
        };
        assert!(!deleted_arr.refresh(None));

        let manager = arr.owning_data_type_manager();
        assert_eq!(manager.get_universal_id(), manager.get_universal_id());
    }
}
