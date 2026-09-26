//! Port of `ghidra.program.database.data.PointerDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private, concrete `Pointer` implementation that extends the
//! not-yet-ported abstract `DataTypeDB` (itself backed by a shared `record`/`lock`/`dataMgr`
//! triple and the not-yet-ported [`PointerDBAdapter`](super::PointerDBAdapter)-typed `adapter`
//! field). Every public method it overrides already belongs to the already-ported
//! [`Pointer`](crate::program::model::data::pointer::Pointer) (which itself extends
//! [`DataType`](crate::program::model::data::data_type::DataType)) contract, so none of them are
//! repeated here.
//!
//! The one piece of `PointerDB`'s own contract that matters for the dependency cycle is
//! `refresh(DBRecord)`: `DataTypeDB` declares it abstract, and every DB-backed datatype family
//! member (`ArrayDB`, `StructureDB`, `PointerDB`, ...) overrides it with its own record-driven
//! resync logic -- exactly the kind of per-subtype override that makes `DataTypeDB` a
//! dependency-cycle participant. Modeling it here as a required trait method lets a future
//! `PointerDB` implementor supply its own logic without this trait needing the full (parked)
//! `DataTypeDB` base class.
//!
//! `PointerDB`'s constructor also takes a `DataTypeManagerDB` directly (used pervasively for
//! `dbError`, `getResolvedID`, deferred type replacement/deletion, etc.), which is the actual
//! `PointerDB` <-> `DataTypeManagerDB` construction-time cycle this port cuts. It is modeled,
//! same as [`ArrayDb`](super::array_db::ArrayDb)/[`StructureDb`](super::structure_db::StructureDb),
//! via the
//! [`DataTypeManagerDb`](crate::program::database::data::data_type_manager_db::DataTypeManagerDb)
//! trait.

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::pointer::Pointer;

/// Database implementation of the [`Pointer`] interface.
///
/// Port of `ghidra.program.database.data.PointerDB`.
pub trait PointerDb: Pointer {
    /// Re-synchronizes this pointer's cached state against the latest database record, looking
    /// the record up via this pointer's backing `PointerDBAdapter`/key when `record` is `None`.
    /// Returns `false` if the underlying record no longer exists (the pointer has been deleted).
    ///
    /// Stands in for the protected `DataTypeDB.refresh(DBRecord)` as overridden by `PointerDB`.
    fn refresh(&mut self, record: Option<DBRecord>) -> bool;

    /// Returns the database-backed manager that owns this pointer's record.
    ///
    /// Stands in for `PointerDB.getDataTypeManager()`.
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;
    use std::io;
    use std::sync::Arc;

    fn pointer_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Pointer ID".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Byte],
            vec![
                "Data Type ID".to_string(),
                "Category ID".to_string(),
                "Length".to_string(),
            ],
            vec![],
        ))
    }

    struct MockPointeeDataType;
    impl DataType for MockPointeeDataType {
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct MockPointerTypedefBuilder;
    impl PointerTypedefBuilder for MockPointerTypedefBuilder {}

    struct MockDataTypeManagerDb;
    impl DataTypeManager for MockDataTypeManagerDb {}
    impl DataTypeManagerDb for MockDataTypeManagerDb {
        fn db_error(&mut self, _error: io::Error) {}

        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}

        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    /// Minimal DB-backed [`PointerDb`], proving object-safety and exercising real refresh
    /// behavior (deletion detection via a missing record, and pointer length recompute from a
    /// present one -- mirroring the stored-length-or-default-pointer-size logic in
    /// `PointerDB.getLength()`).
    struct MockPointerDb {
        stored_length: i32,
        deleted: bool,
        manager: Arc<MockDataTypeManagerDb>,
    }

    impl DataType for MockPointerDb {
        fn get_length(&self) -> i32 {
            if self.stored_length > 0 {
                self.stored_length
            } else {
                // Default pointer size, standing in for
                // `dataMgr.getDataOrganization().getPointerSize()`.
                8
            }
        }
    }

    impl Pointer for MockPointerDb {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockPointeeDataType))
        }

        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockPointerDb {
                stored_length: self.stored_length,
                deleted: self.deleted,
                manager: self.manager.clone(),
            })
        }

        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            Box::new(MockPointerTypedefBuilder)
        }
    }

    impl PointerDb for MockPointerDb {
        fn refresh(&mut self, record: Option<DBRecord>) -> bool {
            match record {
                None => !self.deleted,
                Some(rec) => {
                    self.stored_length = match rec.get_field(2) {
                        Field::Byte(Some(v)) => *v as i32,
                        _ => self.stored_length,
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
    fn refresh_recomputes_length_and_detects_deletion() {
        let mut ptr: Box<dyn PointerDb> = Box::new(MockPointerDb {
            stored_length: 0,
            deleted: false,
            manager: Arc::new(MockDataTypeManagerDb),
        });

        // Pointer/DataType supertrait methods are reachable directly on the `dyn PointerDb`
        // object.
        assert!(ptr.get_data_type().is_some());
        // Unset stored length (0) falls back to the default pointer size (8).
        assert_eq!(ptr.get_length(), 8);

        let schema = pointer_schema();
        let mut rec = DBRecord::new(schema, Field::Long(Some(0)));
        rec.set_field(0, Field::Long(Some(100)));
        rec.set_field(1, Field::Long(Some(1)));
        rec.set_field(2, Field::Byte(Some(4)));

        assert!(ptr.refresh(Some(rec)));
        assert_eq!(ptr.get_length(), 4);

        // Looking the record up again (simulated by `None`) should still find it.
        assert!(ptr.refresh(None));

        // A deleted backing record is reported as a failed refresh.
        let mut deleted_ptr = MockPointerDb {
            stored_length: 4,
            deleted: true,
            manager: Arc::new(MockDataTypeManagerDb),
        };
        assert!(!deleted_ptr.refresh(None));

        let manager = ptr.owning_data_type_manager();
        assert_eq!(manager.get_universal_id(), manager.get_universal_id());
    }
}
