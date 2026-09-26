//! Port of `ghidra.program.database.data.StructureDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private, concrete `Structure` implementation that extends the
//! not-yet-ported abstract `CompositeDB` (itself extending the not-yet-ported `DataTypeDB`, and
//! backed by a shared `record`/`lock`/`dataMgr` triple plus the not-yet-ported
//! [`CompositeDBAdapter`] and already-ported
//! [`ComponentDBAdapter`](crate::program::database::data::ComponentDBAdapter)). Every public
//! method it overrides already belongs to the already-ported
//! [`Structure`](crate::program::model::data::structure::Structure) /
//! [`Composite`](crate::program::model::data::composite::Composite) /
//! [`StructureInternal`](crate::program::model::data::structure_internal::StructureInternal) /
//! [`DataType`](crate::program::model::data::data_type::DataType) contracts, so none of them are
//! repeated here.
//!
//! The one piece of `StructureDB`'s own contract that matters for the dependency cycle is its
//! `initialize()` override: `CompositeDB.refresh(DBRecord)` (itself overriding the abstract
//! `DataTypeDB.refresh(DBRecord)`) delegates to `initialize()` to rebuild the in-memory component
//! list from the backing `ComponentDBAdapter` whenever the underlying database record changes --
//! exactly the kind of per-subtype resync override that makes `DataTypeDB`/`CompositeDB`
//! dependency-cycle participants. Modeling it here as a required trait method lets a future
//! `StructureDB` implementor supply its own logic without this trait needing the full (parked)
//! `CompositeDB`/`DataTypeDB` base classes.
//!
//! `StructureDB`'s constructor also takes a `DataTypeManagerDB` directly (used pervasively for
//! `dbError`, `getResolvedID`, deferred type replacement/deletion, etc.), which is the actual
//! `StructureDB` <-> `DataTypeManagerDB` construction-time cycle this port cuts. It is modeled,
//! same as [`ArrayDb`](super::array_db::ArrayDb), via the
//! [`DataTypeManagerDb`](crate::program::database::data::data_type_manager_db::DataTypeManagerDb)
//! trait.

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::structure_internal::StructureInternal;

/// Database implementation of the [`StructureInternal`] interface.
///
/// Port of `ghidra.program.database.data.StructureDB`.
pub trait StructureDb: StructureInternal {
    /// Re-synchronizes this structure's cached component list against the latest database
    /// record, looking the record up via this structure's backing key when `record` is `None`.
    /// Returns `false` if the underlying record no longer exists (the structure has been
    /// deleted).
    ///
    /// Stands in for `StructureDB.initialize()` as invoked by the inherited
    /// `CompositeDB.refresh(DBRecord)` / `DataTypeDB.refresh(DBRecord)` chain.
    fn refresh(&mut self, record: Option<DBRecord>) -> bool;

    /// Returns the database-backed manager that owns this structure's record.
    ///
    /// Stands in for `StructureDB`'s constructor-supplied `DataTypeManagerDB`.
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::structure::Structure;
    use std::io;
    use std::sync::Arc;

    fn structure_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Structure ID".to_string(),
            vec![FieldType::Int, FieldType::Int, FieldType::Int],
            vec![
                "Length".to_string(),
                "Alignment".to_string(),
                "Num Components".to_string(),
            ],
            vec![],
        ))
    }

    struct MockDataTypeManagerDb;
    impl DataTypeManager for MockDataTypeManagerDb {}
    impl DataTypeManagerDb for MockDataTypeManagerDb {
        fn db_error(&mut self, _error: io::Error) {}

        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}

        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    struct MockDataTypeComponent {
        ordinal: i32,
        offset: i32,
    }

    impl DataTypeComponent for MockDataTypeComponent {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    /// Minimal DB-backed [`StructureDb`], proving object-safety and exercising real
    /// `initialize()`-style refresh behavior (deletion detection via a missing record, and
    /// length/component-count recompute from a present one).
    struct MockStructureDb {
        struct_length: i32,
        num_components: i32,
        deleted: bool,
        manager: Arc<MockDataTypeManagerDb>,
    }

    impl DataType for MockStructureDb {
        fn get_length(&self) -> i32 {
            if self.struct_length == 0 {
                1
            } else {
                self.struct_length
            }
        }
    }

    impl Composite for MockStructureDb {
        fn get_num_components(&self) -> i32 {
            self.num_components
        }
    }

    impl CompositeInternal for MockStructureDb {}

    impl Structure for MockStructureDb {
        fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
            if ordinal < 0 || ordinal >= self.num_components {
                return Err(format!(
                    "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
                ));
            }
            Ok(Box::new(MockDataTypeComponent {
                ordinal,
                offset: ordinal,
            }))
        }
    }

    impl StructureInternal for MockStructureDb {}

    impl StructureDb for MockStructureDb {
        fn refresh(&mut self, record: Option<DBRecord>) -> bool {
            match record {
                None => !self.deleted,
                Some(rec) => {
                    self.struct_length = match rec.get_field(0) {
                        Field::Int(Some(v)) => *v,
                        _ => self.struct_length,
                    };
                    self.num_components = match rec.get_field(2) {
                        Field::Int(Some(v)) => *v,
                        _ => self.num_components,
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
        let mut s: Box<dyn StructureDb> = Box::new(MockStructureDb {
            struct_length: 4,
            num_components: 2,
            deleted: false,
            manager: Arc::new(MockDataTypeManagerDb),
        });

        // Structure/Composite supertrait methods are reachable directly on the `dyn StructureDb`
        // object.
        assert_eq!(s.get_num_components(), 2);
        assert_eq!(s.get_length(), 4);
        assert!(Structure::get_component(s.as_ref(), 1).is_ok());
        assert!(Structure::get_component(s.as_ref(), 5).is_err());

        let schema = structure_schema();
        let mut rec = DBRecord::new(schema, Field::Long(Some(0)));
        rec.set_field(0, Field::Int(Some(16)));
        rec.set_field(1, Field::Int(Some(4)));
        rec.set_field(2, Field::Int(Some(5)));

        assert!(s.refresh(Some(rec)));
        assert_eq!(s.get_length(), 16);
        assert_eq!(s.get_num_components(), 5);

        // Looking the record up again (simulated by `None`) should still find it.
        assert!(s.refresh(None));

        // A deleted backing record is reported as a failed refresh.
        let mut deleted_struct = MockStructureDb {
            struct_length: 4,
            num_components: 2,
            deleted: true,
            manager: Arc::new(MockDataTypeManagerDb),
        };
        assert!(!deleted_struct.refresh(None));

        let manager = s.owning_data_type_manager();
        assert_eq!(manager.get_universal_id(), manager.get_universal_id());
    }
}
