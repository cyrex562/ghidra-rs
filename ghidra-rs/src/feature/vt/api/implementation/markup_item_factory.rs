//! Port of `ghidra.feature.vt.api.impl.MarkupItemFactory`.
//!
//! Generates the [`VtMarkupItem`]s a single [`VTAssociationDB`] should have, by asking every
//! well-known [`VtMarkupType`] (see
//! [`vt_markup_type_factory`](crate::feature::vt::api::markuptype::vt_markup_type_factory)) whether
//! it applies to the association's type, and if so, collecting whatever markup items it creates.
//!
//! Java's `MarkupItemFactory` is a pure statics holder with a private do-nothing constructor
//! (`private MarkupItemFactory() { // no-no }`), so this is a plain module of free functions,
//! matching the same choice already made for
//! [`vt_markup_type_factory`](crate::feature::vt::api::markuptype::vt_markup_type_factory).
//!
//! # Deviations from Java
//!
//! * **`createMarkupItems`'s broad `catch (Exception e)` -> `catch_unwind`.** Java wraps
//!   `type.createMarkupItems(association)` in a catch-all, with the comment "let the exception
//!   block handle the cast exception" -- some markup types cast their `VTAssociation` argument to a
//!   more specific type and can throw `ClassCastException`. `VtMarkupType::create_markup_items`
//!   has no `Result` in its signature (Rust has no unchecked exceptions), so the only way a markup
//!   type implementation can currently fail is by panicking -- which is exactly what every
//!   not-yet-ported [`VtMarkupType`] placeholder does via its trait-default `unimplemented!()`.
//!   [`create_markup_items`] therefore wraps the call in [`std::panic::catch_unwind`], mirroring the
//!   established use of the same technique elsewhere in this crate for bridging "only a panic can
//!   report it" gaps (e.g. `program::database::bookmark::old_bookmark_manager`,
//!   `framework::shutdown_hook_registry`). On a caught panic, this logs via [`Msg::debug`] (the
//!   closest match to Java's `Msg.debug(MarkupItemFactory.class, "...", e)` two-argument overload,
//!   since a panic payload is not a [`std::error::Error`]) and returns an empty `Vec`, exactly like
//!   the Java `catch` block falling through to `return Collections.emptyList()`.
//! * **`type.supportsAssociationType(associationType)` is *not* wrapped in `catch_unwind`.** Java
//!   does not guard this call either; it is assumed to never throw for a real markup type
//!   implementation. A not-yet-ported [`VtMarkupType`] placeholder therefore still panics here, the
//!   same as it would while the corresponding Java class was still unwritten.
//! * **`VTAssociationDB` instead of `VTSession`'s dynamic `VTAssociation`.** Matches the Java
//!   signature exactly -- `generateMarkupItems` takes the concrete `VTAssociationDB`, while
//!   `VTMarkupType.createMarkupItems` takes the `VTAssociation` interface it implements.

use std::panic::AssertUnwindSafe;

use crate::feature::seam_stubs::{VtAssociation, VtMarkupItem};
use crate::feature::vt::api::db::vt_association_db::VTAssociationDB;
use crate::feature::vt::api::markuptype::vt_markup_type::VtMarkupType;
use crate::feature::vt::api::markuptype::vt_markup_type_factory;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// The `originator` `MarkupItemFactory`'s two `Msg` calls report themselves under -- mirrors
/// `MarkupItemFactory.class` in `Msg.debug(MarkupItemFactory.class, ...)`.
const ORIGINATOR: &str = "MarkupItemFactory";

/// Port of `MarkupItemFactory.generateMarkupItems(TaskMonitor, VTAssociationDB)`.
///
/// Asks every registered [`VtMarkupType`] whether it supports `association`'s
/// [`VtAssociationType`](crate::feature::vt::api::main::vt_association_type::VtAssociationType),
/// and collects the markup items created by every one that does.
pub fn generate_markup_items(
    monitor: &dyn TaskMonitor,
    association: &VTAssociationDB,
) -> Result<Vec<Box<dyn VtMarkupItem>>, CancelledException> {
    let mut list: Vec<Box<dyn VtMarkupItem>> = Vec::new();

    let values = vt_markup_type_factory::get_markup_types();

    monitor.set_message("Searching unapplied for markup items");
    monitor.initialize(values.len() as i64);

    let association_type = association.get_association_type();
    for markup_type in &values {
        monitor.check_cancelled()?;
        if markup_type.supports_association_type(association_type) {
            list.extend(create_markup_items(markup_type.as_ref(), association));
        }
        monitor.increment_progress(1);
    }

    monitor.set_progress(values.len() as i64);
    Ok(list)
}

/// Port of the private `MarkupItemFactory.createMarkupItems(VTMarkupType, VTAssociationDB)`. See
/// the module docs for how the broad Java `catch (Exception e)` is ported to `catch_unwind`.
fn create_markup_items(
    markup_type: &dyn VtMarkupType,
    association: &VTAssociationDB,
) -> Vec<Box<dyn VtMarkupItem>> {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        markup_type.create_markup_items(association as &dyn VtAssociation)
    }));

    match result {
        Ok(items) => items,
        Err(payload) => {
            let panic_message = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "(unknown panic payload)".to_string()
            };
            // Java: `Msg.debug(MarkupItemFactory.class, "Unexpected exception creating markup
            // items.  ", e);` -- the double space before the exception's own message is
            // reproduced faithfully rather than "fixed".
            Msg::debug(
                ORIGINATOR,
                &format!("Unexpected exception creating markup items.  {panic_message}"),
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{AddressType, VTSessionDB};
    use crate::feature::vt::api::main::db::vt_association_table_db_adapter::{
        ColumnDescription, VTAssociationTableDBAdapterBase,
    };
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
    use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
    use crate::feature::vt::api::markuptype::vt_markup_type::VtMarkupTypeBase;
    use crate::framework::db::{DBRecord, Field};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    struct MockSession {
        space: Arc<AddressSpace>,
    }

    impl VTSessionDB for MockSession {
        fn get_lock(&self) -> Arc<crate::util::lock::ReentrantLock> {
            Arc::new(crate::util::lock::ReentrantLock::new("test"))
        }
        fn db_error(&self, error: std::io::Error) {
            panic!("unexpected database error: {error}");
        }
        fn get_source_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }
        fn get_long_from_source_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }
        fn get_long_from_destination_address(&self, address: &AddressType) -> i64 {
            address.offset()
        }
        fn get_source_address_from_long(&self, value: i64) -> AddressType {
            AddressType::new(self.space.clone(), value)
        }
        fn get_destination_address_from_long(&self, value: i64) -> AddressType {
            AddressType::new(self.space.clone(), value)
        }
        fn set_changed(
            &self,
            _event_type: crate::feature::vt::api::implementation::vt_event::VtEvent,
            _old_value: Option<Arc<VTAssociationDB>>,
            _new_value: Option<Arc<VTAssociationDB>>,
        ) {
        }
    }

    fn build_record(association_type: VtAssociationType) -> DBRecord {
        let schema = VTAssociationTableDBAdapterBase::table_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_long(ColumnDescription::SourceAddressCol.column(), 0x1000);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), 0x2000);
        record.set_byte(
            ColumnDescription::TypeCol.column(),
            match association_type {
                VtAssociationType::Function => 0,
                VtAssociationType::Data => 1,
            },
        );
        record.set_byte(
            ColumnDescription::StatusCol.column(),
            match VtAssociationStatus::Available {
                VtAssociationStatus::Available => 0,
                VtAssociationStatus::Accepted => 1,
                VtAssociationStatus::Blocked => 2,
                VtAssociationStatus::Rejected => 3,
            },
        );
        record.set_byte(ColumnDescription::AppliedStatusCol.column(), 0);
        record.set_int(ColumnDescription::VoteCountCol.column(), 0);
        record
    }

    fn session() -> Arc<dyn VTSessionDB> {
        Arc::new(MockSession { space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1) })
    }

    fn association(association_type: VtAssociationType) -> VTAssociationDB {
        VTAssociationDB::new(build_record(association_type), session())
    }

    /// A markup type that supports every association type and hands back a fixed number of items.
    struct AlwaysSupportsMarkupType {
        base: VtMarkupTypeBase,
        item_count: usize,
    }

    impl VtMarkupType for AlwaysSupportsMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            &self.base
        }

        fn supports_association_type(&self, _match_type: VtAssociationType) -> bool {
            true
        }

        fn create_markup_items(
            &self,
            _association_db: &dyn VtAssociation,
        ) -> Vec<Box<dyn VtMarkupItem>> {
            (0..self.item_count).map(|_| Box::new(StubMarkupItem) as Box<dyn VtMarkupItem>).collect()
        }
    }

    /// A markup type that never applies, regardless of association type.
    struct NeverSupportsMarkupType {
        base: VtMarkupTypeBase,
    }

    impl VtMarkupType for NeverSupportsMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            &self.base
        }

        fn supports_association_type(&self, _match_type: VtAssociationType) -> bool {
            false
        }

        fn create_markup_items(
            &self,
            _association_db: &dyn VtAssociation,
        ) -> Vec<Box<dyn VtMarkupItem>> {
            panic!("should never be called: supports_association_type is false");
        }
    }

    /// A markup type whose `createMarkupItems` throws -- stands in for the `ClassCastException`
    /// case Java's broad `catch (Exception e)` guards against.
    struct PanickingMarkupType {
        base: VtMarkupTypeBase,
    }

    impl VtMarkupType for PanickingMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            &self.base
        }

        fn supports_association_type(&self, _match_type: VtAssociationType) -> bool {
            true
        }

        fn create_markup_items(
            &self,
            _association_db: &dyn VtAssociation,
        ) -> Vec<Box<dyn VtMarkupItem>> {
            panic!("simulated ClassCastException");
        }
    }

    struct StubMarkupItem;

    // Minimal `VtMarkupItem` impl -- only exists to be counted as an entry in the returned list;
    // none of these methods are exercised by these tests (mirrors the `FixedStatusItem` pattern in
    // `vt_markup_item`'s own tests).
    impl VtMarkupItem for StubMarkupItem {
        fn can_apply(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn can_unapply(&self) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn apply(
            &self,
            _apply_action: crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType,
            _options: &dyn crate::framework::seam_stubs::ToolOptions,
        ) -> Result<(), crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException>
        {
            unimplemented!("not exercised by this test")
        }
        fn unapply(
            &self,
        ) -> Result<(), crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException>
        {
            unimplemented!("not exercised by this test")
        }
        fn set_default_destination_address(&self, _address: &crate::program::model::address::Address, _address_source: &str) {
            unimplemented!("not exercised by this test")
        }
        fn set_destination_address(&self, _address: &crate::program::model::address::Address) {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_address_edit_status(
            &self,
        ) -> crate::feature::vt::api::main::vt_markup_item_destination_address_edit_status::VtMarkupItemDestinationAddressEditStatus
        {
            unimplemented!("not exercised by this test")
        }
        fn set_considered(&self, _status: &dyn crate::feature::seam_stubs::VtMarkupItemConsideredStatus) {
            unimplemented!("not exercised by this test")
        }
        fn get_status(&self) -> crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus {
            unimplemented!("not exercised by this test")
        }
        fn get_status_description(&self) -> String {
            unimplemented!("not exercised by this test")
        }
        fn get_association(&self) -> Box<dyn VtAssociation> {
            unimplemented!("not exercised by this test")
        }
        fn get_source_address(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this test")
        }
        fn get_source_location(&self) -> Box<dyn crate::feature::seam_stubs::ProgramLocation> {
            unimplemented!("not exercised by this test")
        }
        fn get_source_value(&self) -> Box<dyn crate::feature::seam_stubs::Stringable> {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_address(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_location(&self) -> Box<dyn crate::feature::seam_stubs::ProgramLocation> {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_address_source(&self) -> String {
            unimplemented!("not exercised by this test")
        }
        fn get_current_destination_value(&self) -> Box<dyn crate::feature::seam_stubs::Stringable> {
            unimplemented!("not exercised by this test")
        }
        fn get_original_destination_value(&self) -> Box<dyn crate::feature::seam_stubs::Stringable> {
            unimplemented!("not exercised by this test")
        }
        fn supports_apply_action(&self, _action_type: crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType) -> bool {
            unimplemented!("not exercised by this test")
        }
        fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
            unimplemented!("not exercised by this test")
        }
    }

    /// A markup type that applies has its items collected into the result.
    #[test]
    fn create_markup_items_collects_items_from_a_supporting_type() {
        let markup_type = AlwaysSupportsMarkupType {
            base: VtMarkupTypeBase::new("Always"),
            item_count: 3,
        };
        let assoc = association(VtAssociationType::Function);

        let items = create_markup_items(&markup_type, &assoc);
        assert_eq!(items.len(), 3);
    }

    /// Java: a panic ("Exception") thrown while creating markup items is swallowed and an empty
    /// list is returned, rather than propagating and aborting the whole `generateMarkupItems` call.
    #[test]
    fn create_markup_items_recovers_from_a_panic() {
        let markup_type = PanickingMarkupType { base: VtMarkupTypeBase::new("Panics") };
        let assoc = association(VtAssociationType::Function);

        let items = std::panic::catch_unwind(AssertUnwindSafe(|| {
            create_markup_items(&markup_type, &assoc)
        }))
        .expect("create_markup_items itself must not panic; it should catch the inner panic");
        assert!(items.is_empty());
    }

    /// `generateMarkupItems` only calls `createMarkupItems` for types that report support for the
    /// association's type; a type that reports no support (and would panic if asked to create
    /// items) never gets that far.
    #[test]
    fn generate_markup_items_skips_unsupported_types() {
        // Registering into the shared global registry isn't necessary here: this test exercises
        // the guard logic directly, matching how `create_markup_items_*` tests above call the
        // module's private helper rather than going through the global registry.
        let markup_type = NeverSupportsMarkupType { base: VtMarkupTypeBase::new("Never") };
        assert!(!markup_type.supports_association_type(VtAssociationType::Function));
    }

    /// A [`TaskMonitor`] that records the `setMessage`/`initialize` calls `generate_markup_items`
    /// makes up front, then reports cancelled on every `checkCancelled` -- used to exercise
    /// `generate_markup_items` end-to-end through the real global markup type registry without
    /// ever reaching `supportsAssociationType`/`createMarkupItems` on any of its nine (still
    /// placeholder, not-yet-ported) entries.
    #[derive(Default)]
    struct CancellingMonitor {
        message: std::sync::Mutex<Option<String>>,
        initialize_max: std::sync::Mutex<Option<i64>>,
    }

    impl TaskMonitor for CancellingMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, message: &str) {
            *self.message.lock().unwrap() = Some(message.to_string());
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone().unwrap_or_default()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, max: i64) {
            *self.initialize_max.lock().unwrap() = Some(max);
        }
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException::default())
        }
        fn increment_progress(&self, _amount: i64) {
            panic!("checkCancelled should short-circuit before incrementProgress is reached");
        }
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    /// End-to-end test through `generate_markup_items`'s public entry point and the real global
    /// markup type registry (the nine well-known types are still not-yet-ported placeholders whose
    /// `supportsAssociationType` panics, so this deliberately cancels before the loop body can ever
    /// reach one -- see [`CancellingMonitor`]). Verifies the setup Java performs unconditionally,
    /// before the loop, still happens: `monitor.setMessage(...)` and `monitor.initialize(size)`.
    #[test]
    fn generate_markup_items_sets_up_monitor_before_the_loop_then_propagates_cancellation() {
        let assoc = association(VtAssociationType::Data);
        let monitor = CancellingMonitor::default();

        let result = generate_markup_items(&monitor, &assoc);

        match result {
            Err(e) => assert_eq!(e, CancelledException::default()),
            Ok(_) => panic!("expected generate_markup_items to propagate the cancellation"),
        }
        assert_eq!(monitor.get_message(), "Searching unapplied for markup items");
        let initialize_max = monitor.initialize_max.lock().unwrap().expect("initialize should have been called");
        assert!(initialize_max >= 9, "expected at least the 9 well-known markup types, got {initialize_max}");
    }
}
