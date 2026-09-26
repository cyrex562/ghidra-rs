//! Port of `ghidra.program.database.OverlaySpaceDBAdapter`.
//!
//! The Java type is a package-private abstract class whose static factory methods
//! (`getOverlaySpaceAdapter`, `findReadOnlyAdapter`, `upgrade`, `copyRecords`) select and migrate
//! between concrete version-specific implementations (`OverlaySpaceDBAdapterV0`/
//! `OverlaySpaceDBAdapterV1`, both still `TODO`). As with
//! [`SettingsDBAdapter`](crate::program::database::data::settings_db_adapter::SettingsDBAdapter),
//! this port only models the abstract instance API each version implements, as an object-safe
//! trait; the version-selection/upgrade logic and the `getRecordCount`/`initializeOverlaySpaces`
//! helpers (which need `ProgramAddressFactory`'s inherited `AddressFactory.getAddressSpace`
//! lookup, not exposed by the already-ported
//! [`ProgramAddressFactory`](crate::program::database::program_address_factory::ProgramAddressFactory)
//! trait) belong with whichever type ends up owning the concrete adapters.
//!
//! This type was selected as a dependency-cycle cut point: `createOverlaySpace` and
//! `updateOverlaySpaces` take a `ProgramAddressFactory`, while `ProgramAddressFactory` in turn
//! needs an overlay-space adapter to load/persist its overlay spaces. Expressing this type as a
//! trait breaks that cycle.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::program_address_factory::ProgramAddressFactory;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::seam_stubs::ProgramOverlayAddressSpace;
use crate::program::util::language_translator::LanguageTranslator;
use crate::util::exception::{DuplicateNameException, InvalidNameException};

/// Name of the underlying database table, mirrors
/// `OverlaySpaceDBAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "Overlay Spaces";

/// Combines the checked exceptions declared on `OverlaySpaceDBAdapter.createOverlaySpace`.
#[derive(Debug, thiserror::Error)]
pub enum CreateOverlaySpaceError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Adapter to access the overlay address space database table.
///
/// Port of `ghidra.program.database.OverlaySpaceDBAdapter`.
pub trait OverlaySpaceDBAdapter {
    /// Provide overlay space record iterator. Older adapters must translate records into the
    /// latest schema format.
    fn get_overlay_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Update the overlay database table with the specified record, which must already be in
    /// the latest schema format.
    fn update_overlay_record(&mut self, rec: &DBRecord) -> io::Result<()>;

    /// Create a new overlay address space and associated record.
    ///
    /// `base_space` is the underlying physical/base address space which is to be overlaid (must
    /// not itself be an overlay space).
    ///
    /// Returns the new overlay space (without regions defined).
    fn create_overlay_space(
        &mut self,
        factory: &mut dyn ProgramAddressFactory,
        overlay_name: &str,
        base_space: Arc<AddressSpace>,
    ) -> Result<Arc<dyn ProgramOverlayAddressSpace>, CreateOverlaySpaceError>;

    /// Removes the named space from the database. Caller is responsible for updating the
    /// address factory. Returns `true` if an overlay record was updated, `false` if not found.
    fn remove_overlay_space(&mut self, name: &str) -> io::Result<bool>;

    /// Rename the overlay space from `old_name` to `new_name`. Caller is responsible for
    /// updating the address factory and ensuring that `new_name` does not duplicate that of
    /// another address space. Returns `true` if an overlay record was updated, `false` if not
    /// found.
    fn rename_overlay_space(&mut self, old_name: &str, new_name: &str) -> io::Result<bool>;

    /// Reconcile overlay spaces following cache invalidation (e.g. undo/redo).
    fn update_overlay_spaces(&mut self, factory: &mut dyn ProgramAddressFactory) -> io::Result<()>;

    /// Translate overlay address spaces for a new language provider and initialize
    /// `addr_factory` with the translated overlay spaces. All non-overlay address spaces within
    /// the address factory should already have been mapped to the new language.
    fn set_language(
        &mut self,
        new_language: &dyn Language,
        addr_factory: &mut dyn ProgramAddressFactory,
        translator: &dyn LanguageTranslator,
    ) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::program_address_factory::CheckOverlayNameError;
    use crate::program::model::address::{Address, AddressFactory, AddressSpaceType};
    use crate::program::seam_stubs::ProgramOverlayAddressSpace;
    use std::cell::RefCell;

    /// Minimal `ProgramAddressFactory` stand-in: none of its methods are exercised by these
    /// tests (`MockAdapter` below never calls into the factory it is handed), so every method
    /// panics if actually invoked.
    struct NoopFactory;

    impl ProgramAddressFactory for NoopFactory {
        fn invalidate_overlay_cache(&self) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_original_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_valid_overlay_base_space(&self, _base_space: &Arc<AddressSpace>) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_overlay_space(
            &mut self,
            _ov_space: Arc<dyn ProgramOverlayAddressSpace>,
        ) -> Result<(), DuplicateNameException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_overlay_space(
            &mut self,
            _key: i64,
            _overlay_name: &str,
            _base_space: Arc<AddressSpace>,
        ) -> Result<Arc<dyn ProgramOverlayAddressSpace>, DuplicateNameException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn check_valid_overlay_space_name(&self, _name: &str) -> Result<(), CheckOverlayNameError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove_overlay_space(&mut self, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }

        fn overlay_space_renamed(
            &mut self,
            _old_overlay_space_name: &str,
            _new_name: &str,
            _refresh_status_if_needed: bool,
        ) {
            unimplemented!("not exercised by this smoke test")
        }

        fn refresh_stale_overlay_status(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_stale_overlay_condition(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn generate_ordered_key(&mut self, _overlay_name: &str) -> String {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockOverlaySpace {
        ordered_key: String,
        name: RefCell<String>,
    }

    impl ProgramOverlayAddressSpace for MockOverlaySpace {
        fn get_ordered_key(&self) -> &str {
            &self.ordered_key
        }

        fn get_name(&self) -> &str {
            // SAFETY-free: RefCell borrow leaked for the lifetime of `&self`, mirroring the
            // simple test double used elsewhere in this crate for `get_name` accessors backed by
            // interior-mutable state.
            unsafe { &*self.name.as_ptr() }
        }

        fn invalidate(&self) {}
    }

    struct MockAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        overlays: RefCell<Vec<Arc<MockOverlaySpace>>>,
    }

    impl MockAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Key".to_string(),
                vec![FieldType::String, FieldType::String],
                vec!["Space Name".to_string(), "Base Space Name".to_string()],
                vec![],
            ));
            MockAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                overlays: RefCell::new(Vec::new()),
            }
        }
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    impl OverlaySpaceDBAdapter for MockAdapter {
        fn get_overlay_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn update_overlay_record(&mut self, rec: &DBRecord) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == rec.get_key()) {
                *existing = rec.clone();
            } else {
                records.push(rec.clone());
            }
            Ok(())
        }

        fn create_overlay_space(
            &mut self,
            _factory: &mut dyn ProgramAddressFactory,
            overlay_name: &str,
            _base_space: Arc<AddressSpace>,
        ) -> Result<Arc<dyn ProgramOverlayAddressSpace>, CreateOverlaySpaceError> {
            if self
                .overlays
                .borrow()
                .iter()
                .any(|ov| ov.get_name() == overlay_name)
            {
                return Err(DuplicateNameException::with_message(format!(
                    "duplicate overlay name: {overlay_name}"
                ))
                .into());
            }

            let key = self.records.borrow().len() as i64;
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            rec.set_field(0, Field::String(Some(overlay_name.to_string())));
            self.update_overlay_record(&rec)?;

            let mock = Arc::new(MockOverlaySpace {
                ordered_key: overlay_name.to_string(),
                name: RefCell::new(overlay_name.to_string()),
            });
            self.overlays.borrow_mut().push(mock.clone());
            Ok(mock)
        }

        fn remove_overlay_space(&mut self, name: &str) -> io::Result<bool> {
            let mut overlays = self.overlays.borrow_mut();
            let before = overlays.len();
            overlays.retain(|ov| ov.get_name() != name);
            Ok(overlays.len() != before)
        }

        fn rename_overlay_space(&mut self, old_name: &str, new_name: &str) -> io::Result<bool> {
            let overlays = self.overlays.borrow_mut();
            if let Some(ov) = overlays.iter().find(|ov| ov.get_name() == old_name) {
                *ov.name.borrow_mut() = new_name.to_string();
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn update_overlay_spaces(
            &mut self,
            _factory: &mut dyn ProgramAddressFactory,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_language(
            &mut self,
            _new_language: &dyn Language,
            _addr_factory: &mut dyn ProgramAddressFactory,
            _translator: &dyn LanguageTranslator,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    fn make_base_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    // Exercise the trait object surface to confirm object-safety, and that a mock adapter tracks
    // creation/rename/removal of overlay spaces through the real trait methods (not
    // trivially-true asserts).
    #[test]
    fn mock_adapter_tracks_overlay_lifecycle_through_trait_object() {
        let mut adapter: Box<dyn OverlaySpaceDBAdapter> = Box::new(MockAdapter::new());
        let mut factory = NoopFactory;

        let created = adapter
            .create_overlay_space(&mut factory, "OV", make_base_space())
            .expect("first create should succeed");
        assert_eq!(created.get_name(), "OV");

        let dup_err = adapter.create_overlay_space(&mut factory, "OV", make_base_space());
        assert!(dup_err.is_err());

        assert!(adapter
            .rename_overlay_space("OV", "OV_renamed")
            .expect("rename should succeed"));
        assert_eq!(created.get_name(), "OV_renamed");

        assert!(adapter
            .remove_overlay_space("OV_renamed")
            .expect("remove should succeed"));
        assert!(!adapter
            .remove_overlay_space("OV_renamed")
            .expect("second remove should not error"));

        let mut it = adapter.get_overlay_records().expect("iterator");
        let rec = it
            .next()
            .expect("no io error")
            .expect("one record should have been persisted by create_overlay_space");
        assert_eq!(rec.get_string(0), Some("OV"));
    }
}
