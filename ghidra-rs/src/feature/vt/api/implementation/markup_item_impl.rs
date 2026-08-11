//! Port of `ghidra.feature.vt.api.impl.MarkupItemImpl`.
//!
//! A single version-tracking markup item: the pairing of a [`VtMarkupType`] with one source
//! address inside an association, plus the persistent [`MarkupItemStorage`] that records what the
//! user has done with it.
//!
//! Deviations from the Java source, each forced by a seam that is already ported (and so not
//! renegotiable here) or by a type that is not ported yet:
//!
//!   - **The storage and value cache are interior-mutable.** Every method keeps Java's receiver:
//!     `apply`, `unapply` and the setters mutate through `&self`. They have to. Java's `unapply`
//!     reaches through the other `VTMarkupItem`s its association hands back and unapplies them
//!     too, and those arrive as shared trait objects; taking `&mut self` would make that central
//!     cascade unexpressible, and would also collide with the `&self` seam trait implemented at
//!     the bottom of this file (the trait method would silently win method resolution wherever
//!     both were in scope). This is the same shape `VTAssociationDB` and `MarkupItemStorageDB`
//!     already use for the same reason.
//!   - **Storage is never swapped for a different concrete type.** Java's storage setters return a
//!     `MarkupItemStorage` and each caller writes `markupItemStorage = markupItemStorage.setX(...)`,
//!     because an in-memory `MarkupItemStorageImpl` *promotes itself* into a database-backed
//!     `MarkupItemStorageDB` the first time anything user-defined is recorded. The ported trait's
//!     setters return `()` and cannot swap the caller's storage, so this port mutates in place;
//!     the promotion is left for the real `MarkupItemStorageImpl` port.
//!   - **`getStorage()` is narrowed rather than exposed.** Its only caller,
//!     `AssociationDatabaseManager.removeStoredMarkupItems`, tests the result with `instanceof
//!     MarkupItemStorageDB` and reads its key; handing out a borrow of storage that lives behind
//!     a lock is not possible, so [`get_storage_db_key`](MarkupItemImpl::get_storage_db_key)
//!     answers that question directly.
//!   - **A markup item's destination address may be absent.** Java models that as a `null`
//!     `Address`; the ported [`MarkupItemStorage`] trait returns a non-optional one, so the
//!     question is asked through [`MarkupItemStorage::has_destination_address`] and this type's
//!     own [`get_destination_address`](MarkupItemImpl::get_destination_address) returns an
//!     `Option`. Java's `setDestinationAddress(null)` reset has no counterpart for the same
//!     reason: the seam's setter takes a real address.
//!   - **Cached values are cached as strings.** The ported `Stringable` seam exposes nothing but
//!     `to_string()`, and `Box<dyn Stringable>` is not cloneable, so the three value caches hold
//!     the rendered string and each call hands back a fresh wrapper around it. This is the same
//!     simplification `MarkupItemStorageDB` already makes, and it makes an *unset* stored value
//!     indistinguishable from an empty one -- which is how Java's `null` checks in
//!     `getSourceValue`/`getOriginalDestinationValue` are read here.
//!   - **The re-entrancy flags are thread-local.** Java's `isUnApplyingItems`/`gettingStatus` are
//!     unsynchronized `static boolean`s used purely to stop a call from recursing into itself.
//!     A `thread_local!` gives that guarantee without the data race, and unlike the Java original
//!     it cannot have one thread's guard suppress another thread's work.
//!   - **Identity comparisons become value comparisons.** `unapply` skips `currentMarkupItem ==
//!     this` and tests `currentMarkupItem.getMarkupType() == markupType` by reference. The items
//!     an association hands back are freshly boxed trait objects, so neither pointer test is
//!     available: markup types are compared by name (they are registry singletons, one per name),
//!     and this item needs no explicit skip because its own status was set to `UNAPPLIED` just
//!     above, which makes its `can_unapply()` false.
//!   - **The two change events go through the association.** Java casts `association.getSession()`
//!     to `VTSessionDB` and calls `setObjectChanged`; the ported `VtAssociation::get_session` is
//!     not implementable by the database-backed association yet, so this port uses the
//!     `VtAssociation::get_session_db` narrowing (which `VTAssociationDB` answers with the very
//!     session it holds) and the two narrowed `VTSessionDB` event methods. The program
//!     modification numbers behind the value caches are read through the same narrowing.

use std::cell::Cell;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::feature::seam_stubs::{
    MarkupItemStorageImpl, ProgramLocation, Stringable, TaskMonitor, ToolOptions, VtAssociation,
    VtMarkupItemConsideredStatus, VtMarkupType, VtMarkupTypeBase,
};
use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::api::main::vt_markup_item::{VtMarkupItem, USER_DEFINED_ADDRESS_SOURCE};
use crate::feature::vt::api::main::vt_markup_item_apply_action_type::VtMarkupItemApplyActionType;
use crate::feature::vt::api::main::vt_markup_item_destination_address_edit_status::VtMarkupItemDestinationAddressEditStatus;
use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
use crate::feature::vt::api::util::version_tracking_apply_exception::VersionTrackingApplyException;
use crate::program::database::db_object::DbObject;
use crate::program::model::address::Address;

thread_local! {
    /// Java: `private static boolean isUnApplyingItems`. Stops the cascade in
    /// [`MarkupItemImpl::unapply`] -- which unapplies every sibling item at the same destination
    /// -- from recursing back through each of those siblings.
    static IS_UNAPPLYING_ITEMS: Cell<bool> = const { Cell::new(false) };

    /// Java: `private static boolean gettingStatus`. Stops the conflict check in
    /// [`MarkupItemImpl::get_status`] from re-entering `get_status` through the sibling items it
    /// hands to the markup type.
    static GETTING_STATUS: Cell<bool> = const { Cell::new(false) };
}

/// Sets one of the thread-local re-entrancy flags for as long as it is alive, mirroring the
/// `try { flag = true; ... } finally { flag = false; }` shape of the Java methods (including their
/// behaviour when the guarded body unwinds).
struct ReentrancyGuard(&'static std::thread::LocalKey<Cell<bool>>);

impl ReentrancyGuard {
    fn enter(flag: &'static std::thread::LocalKey<Cell<bool>>) -> Self {
        flag.with(|f| f.set(true));
        ReentrancyGuard(flag)
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        self.0.with(|f| f.set(false));
    }
}

/// The one markup-item implementation: a markup type, the storage that persists what has been
/// done with it, and a cache of the values on either side of the match.
///
/// Port of `ghidra.feature.vt.api.impl.MarkupItemImpl`. See the module docs for the deviations
/// this port makes.
pub struct MarkupItemImpl {
    markup_type: Box<dyn VtMarkupType>,
    storage: Mutex<Box<dyn MarkupItemStorage>>,
    cache: Mutex<ValueCache>,
}

/// Java: `MarkupItemImpl`'s `cachedSourceValue`/`cachedDestinationValue`/
/// `cachedOriginalDestinationValue`/`sourceModificationNumber`/`destinationModificationNumber`/
/// `hasSameValues` fields, which are invalidated together whenever the program they were read from
/// has been modified.
#[derive(Default)]
struct ValueCache {
    source_value: Option<String>,
    destination_value: Option<String>,
    original_destination_value: Option<String>,
    source_modification_number: i64,
    destination_modification_number: i64,
    has_same_values: Option<bool>,
}

impl MarkupItemImpl {
    /// Java: `MarkupItemImpl(VTAssociation, VTMarkupType, Address)`, which wraps its arguments in a
    /// fresh in-memory [`MarkupItemStorageImpl`].
    pub fn new(
        association: Arc<dyn VtAssociation>,
        markup_type: Arc<dyn VtMarkupType>,
        source_address: Address,
    ) -> Self {
        Self::from_storage(Box::new(MarkupItemStorageImpl::new(
            association,
            markup_type,
            source_address,
        )))
    }

    /// Java: `MarkupItemImpl(MarkupItemStorage)`.
    pub fn from_storage(storage: Box<dyn MarkupItemStorage>) -> Self {
        let markup_type = storage.get_markup_type();
        Self { markup_type, storage: Mutex::new(storage), cache: Mutex::new(ValueCache::default()) }
    }

    /// The storage, locked. Never held across a call back into the markup type or the association:
    /// both reach back into this item, and the lock is not reentrant.
    fn storage(&self) -> MutexGuard<'_, Box<dyn MarkupItemStorage>> {
        self.storage.lock().unwrap()
    }

    /// Java: `getMarkupType()`.
    pub fn get_markup_type(&self) -> &dyn VtMarkupType {
        &*self.markup_type
    }

    /// Java: `getDisplayName()`, which is `markupType.getDisplayName()`.
    pub fn get_display_name(&self) -> String {
        self.markup_type.get_display_name().to_string()
    }

    /// Java: `getStorage()` narrowed by its one caller's `instanceof MarkupItemStorageDB` test and
    /// the key that caller reads off it. See the module docs.
    pub fn get_storage_db_key(&self) -> Option<i64> {
        self.storage().as_storage_db().map(|storage_db| storage_db.get_key())
    }

    /// Java: `isStoredInDB()`, i.e. `markupItemStorage instanceof DbObject`.
    pub fn is_stored_in_db(&self) -> bool {
        self.storage().as_storage_db().is_some()
    }

    /// Java: `getAssociation()`.
    pub fn get_association(&self) -> Box<dyn VtAssociation> {
        self.storage().get_association()
    }

    /// Java: `getSourceAddress()`.
    pub fn get_source_address(&self) -> Address {
        self.storage().get_source_address()
    }

    /// Java: `getDestinationAddress()`, which returns `null` for an item whose destination has not
    /// been chosen yet.
    pub fn get_destination_address(&self) -> Option<Address> {
        let storage = self.storage();
        storage.has_destination_address().then(|| storage.get_destination_address())
    }

    /// Java: `getDestinationAddressSource()`.
    pub fn get_destination_address_source(&self) -> String {
        self.storage().get_destination_address_source()
    }

    /// Java: `getStatusDescription()`.
    pub fn get_status_description(&self) -> String {
        self.storage().get_status_description()
    }

    /// Java: `getSourceLocation()`.
    pub fn get_source_location(&self) -> Box<dyn ProgramLocation> {
        let (association, source_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_source_address())
        };
        self.markup_type.get_source_location(&*association, &source_address)
    }

    /// Java: `getDestinationLocation()`.
    pub fn get_destination_location(&self) -> Box<dyn ProgramLocation> {
        let (association, destination_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_destination_address())
        };
        self.markup_type.get_destination_location(&*association, &destination_address)
    }

    /// Java: `supportsApplyAction(VTMarkupItemApplyActionType)`.
    pub fn supports_apply_action(&self, action_type: VtMarkupItemApplyActionType) -> bool {
        self.markup_type.supports_apply_action(action_type)
    }

    /// Java: `getStatus()`.
    ///
    /// An unapplied item reports `CONFLICT` when another item of its markup type has already been
    /// applied over it, and `SAME` when the destination already holds the source's value.
    pub fn get_status(&self) -> VtMarkupItemStatus {
        self.validate_destination_cache();
        let status = self.storage().get_status();
        if status != VtMarkupItemStatus::Unapplied {
            return status;
        }

        if !GETTING_STATUS.with(|f| f.get()) {
            let _guard = ReentrancyGuard::enter(&GETTING_STATUS);
            let association = self.get_association();
            // Java catches `CancelledException` here and ignores it; the dummy monitor never
            // cancels, so the error arm is unreachable in practice.
            if let Ok(items) = association.get_markup_items(&DummyTaskMonitor) {
                if self.markup_type.conflicts_with_other_markup(self, &items) {
                    return VtMarkupItemStatus::Conflict;
                }
            }
        }

        if self.has_same_source_destination_values() {
            return VtMarkupItemStatus::Same;
        }
        status
    }

    /// Java: `hasSameSourceDestinationValues()` (private).
    fn has_same_source_destination_values(&self) -> bool {
        if let Some(cached) = self.cache.lock().unwrap().has_same_values {
            return cached;
        }
        // Computed without the cache lock held: the markup type reads back through this item.
        let has_same = self.markup_type.has_same_source_and_destination_values(self);
        self.cache.lock().unwrap().has_same_values = Some(has_same);
        has_same
    }

    /// Java: `getDestinationAddressEditStatus()`.
    pub fn get_destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus {
        if self.markup_type.is_function_entry_point_based() {
            return VtMarkupItemDestinationAddressEditStatus::UneditableFunctionEntryPoint;
        }
        if self.markup_type.is_data_type_based() {
            return VtMarkupItemDestinationAddressEditStatus::UneditableDataAddress;
        }

        if !self.association_status().can_apply() {
            return VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableAssociationStatus;
        }

        let status = self.get_status();
        if !status.is_appliable() && status != VtMarkupItemStatus::Same {
            return VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableMarkupStatus;
        }
        VtMarkupItemDestinationAddressEditStatus::Editable
    }

    /// Java: `getAssociation().getStatus()`, recovered as the real ported enum through the
    /// association seam's placeholder status.
    fn association_status(&self) -> VtAssociationStatus {
        self.get_association().get_status().association_status()
    }

    /// Java: `canApply()`.
    pub fn can_apply(&self) -> bool {
        let association = self.get_association();
        let association_status = association.get_status().association_status();
        match association.get_markup_items(&DummyTaskMonitor) {
            Ok(markup_items) => {
                association_status.can_apply()
                    && self.get_status().is_appliable()
                    && !self.markup_type.conflicts_with_other_markup(self, &markup_items)
            }
            // Java: `catch (CancelledException e) { return false; }`.
            Err(_) => false,
        }
    }

    /// Java: `canUnapply()`.
    pub fn can_unapply(&self) -> bool {
        self.storage().get_status().is_unappliable()
    }

    /// Java: `setDefaultDestinationAddress(Address, String)`, the transient address a markup type
    /// suggests for an item, which does not dirty the database.
    pub fn set_default_destination_address(&self, address: &Address, address_source: &str) {
        self.do_set_destination_address(address, address_source, true);
    }

    /// Java: `setDestinationAddress(Address)`, the address a user picked -- recorded as
    /// [`USER_DEFINED_ADDRESS_SOURCE`].
    pub fn set_destination_address(&self, destination_address: &Address) {
        self.do_set_destination_address(destination_address, USER_DEFINED_ADDRESS_SOURCE, false);
    }

    /// Java: `doSetDestinationAddress(Address, String, boolean)` (private).
    fn do_set_destination_address(&self, address: &Address, address_source: &str, is_default: bool) {
        if self.can_unapply() {
            panic!("Can't set destination address on applied markup item");
        }

        {
            let mut cache = self.cache.lock().unwrap();
            cache.destination_value = None;
            cache.original_destination_value = None;
        }

        let (association, source_address, old_destination_address, old_address_source) = {
            let storage = self.storage();
            (
                storage.get_association(),
                storage.get_source_address(),
                storage.has_destination_address().then(|| storage.get_destination_address()),
                storage.get_destination_address_source(),
            )
        };
        let is_resetting_address = old_address_source == USER_DEFINED_ADDRESS_SOURCE
            && address_source != USER_DEFINED_ADDRESS_SOURCE;

        // The markup type gets to move the address to one it can actually accept -- function name
        // markup, for instance, must sit on the entry point.
        let address =
            self.markup_type.validate_destination_address(&*association, &source_address, address);
        if old_destination_address.as_ref() == Some(&address) {
            // Either the address didn't change, or this markup won't let it change.
            return;
        }

        self.storage().set_destination_address(address.clone(), address_source.to_string());

        // Restoring a default address leaves nothing user-defined behind, so the row can go.
        self.maybe_reset();
        self.cache.lock().unwrap().has_same_values = None;

        if is_default && !is_resetting_address {
            // Don't fire the event: a default address is transient and must not dirty the DB.
            return;
        }

        if let Some(session) = association.get_session_db() {
            session.markup_item_destination_changed(
                self,
                old_destination_address.as_ref(),
                &address,
            );
        }
    }

    /// Java: `setConsidered(VTMarkupItemConsideredStatus)`, the user's "I've looked at this and
    /// I'm not applying it" verdict.
    ///
    /// # Panics
    ///
    /// Panics -- Java throws `IllegalArgumentException` -- if the item has already been applied.
    pub fn set_considered(&self, considered_status: &dyn VtMarkupItemConsideredStatus) {
        if self.can_unapply() {
            panic!("Cannot set an applied item to considered.");
        }

        let old_status = {
            let mut storage = self.storage();
            let old_status = storage.get_status();
            storage.set_status(considered_status.get_markup_item_status());
            old_status
        };

        self.maybe_reset();

        let new_status = self.storage().get_status();
        if old_status != new_status {
            self.fire_markup_item_status_changed(old_status, new_status);
        }
    }

    /// Java: `apply(VTMarkupItemApplyActionType, ToolOptions)`. Java's `applyType == null` guard
    /// has no counterpart: the ported action type is an enum. `options` stays optional, matching
    /// the Java method's own null handling.
    pub fn apply(
        &self,
        apply_type: VtMarkupItemApplyActionType,
        options: Option<&dyn ToolOptions>,
    ) -> Result<(), VersionTrackingApplyException> {
        if self.association_status() != VtAssociationStatus::Accepted {
            return Err(VersionTrackingApplyException::new(
                "Can't apply a markup item for a match that is not accepted.",
            ));
        }

        // Java: `options = new ToolOptions("VT Options Default")` to prevent NPEs.
        let default_options = DefaultToolOptions;
        let options: &dyn ToolOptions = options.unwrap_or(&default_options);

        let old_status = self.storage().get_status();
        let mut new_status = old_status;

        let destination_address = match self.get_destination_address() {
            Some(address) => address,
            None => {
                self.storage()
                    .set_apply_failed("Can't apply without a valid destination".to_string());
                self.fire_markup_item_status_changed(old_status, VtMarkupItemStatus::FailedApply);
                return Err(VersionTrackingApplyException::new(
                    "Cannot apply a markup item without first setting the destination address",
                ));
            }
        };

        if !self.can_apply() {
            return Ok(());
        }

        let (association, source_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_source_address())
        };
        let source_value = self.markup_type.get_source_value(&*association, &source_address);
        let original_destination_value =
            self.markup_type.get_original_destination_value(&*association, &destination_address);
        self.storage().set_source_destination_values(source_value, original_destination_value);

        let result = match self.markup_type.apply_markup(self, options) {
            Ok(true) => {
                new_status = apply_type.apply_status();
                self.storage().set_status(new_status);
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(error) => {
                new_status = VtMarkupItemStatus::FailedApply;
                self.storage().set_apply_failed(error.message().to_string());
                Err(error)
            }
        };

        // Java: `finally { if (oldStatus != newStatus) fire...; }` -- fires on both paths.
        if old_status != new_status {
            self.fire_markup_item_status_changed(old_status, new_status);
        }
        result
    }

    /// Java: `unapply()`. Also unapplies every other item of the same markup type sitting at the
    /// same destination address.
    pub fn unapply(&self) -> Result<(), VersionTrackingApplyException> {
        // Saved before the reset below drops it.
        let destination_address = self.get_destination_address();
        let old_status = self.storage().get_status();
        self.markup_type.unapply_markup(self)?;
        self.storage().set_status(VtMarkupItemStatus::Unapplied);

        self.maybe_reset();

        let new_status = self.storage().get_status();
        if old_status != new_status {
            // These two can only match if you unapply an already-unapplied item.
            self.fire_markup_item_status_changed(old_status, new_status);
        }

        // Only the first item to be unapplied sweeps up the rest.
        if IS_UNAPPLYING_ITEMS.with(|f| f.get()) {
            return Ok(());
        }

        let result = {
            let _guard = ReentrancyGuard::enter(&IS_UNAPPLYING_ITEMS);
            self.unapply_items_at_same_destination(destination_address.as_ref())
        };
        self.cache.lock().unwrap().has_same_values = None;
        result
    }

    /// The body of Java's `try { isUnApplyingItems = true; ... } finally { ... }` block in
    /// `unapply()`. This item is not skipped explicitly the way Java skips `currentMarkupItem ==
    /// this`: its status was set to `UNAPPLIED` above, so its own `can_unapply()` is already false.
    fn unapply_items_at_same_destination(
        &self,
        destination_address: Option<&Address>,
    ) -> Result<(), VersionTrackingApplyException> {
        let Some(destination_address) = destination_address else {
            return Ok(());
        };
        let association = self.get_association();
        // Java: `catch (CancelledException e)` -- can't happen with a dummy monitor.
        let Ok(markup_items) = association.get_markup_items(&DummyTaskMonitor) else {
            return Ok(());
        };

        for item in markup_items {
            if item.get_markup_type().get_display_name() != self.markup_type.get_display_name() {
                continue;
            }
            if !item.can_unapply() {
                continue;
            }
            if &item.get_destination_address() == destination_address {
                item.unapply()?;
            }
        }
        Ok(())
    }

    /// Java: `maybeReset()` (private).
    ///
    /// The storage row exists only to hold user-defined data -- an applied status, a considered
    /// status, or a user-chosen address. Once none of those is left, the row goes.
    fn maybe_reset(&self) {
        let status = self.get_status();
        if !status.is_default() {
            return; // user-defined status or an applied status
        }

        if self.get_destination_address_source() == USER_DEFINED_ADDRESS_SOURCE {
            return; // user-defined address value
        }

        self.cache.lock().unwrap().has_same_values = None;
        self.storage().reset();
    }

    /// Java: `getCurrentDestinationValue()`, the value the destination holds right now.
    pub fn get_current_destination_value(&self) -> Box<dyn Stringable> {
        self.validate_destination_cache();
        if let Some(cached) = self.cache.lock().unwrap().destination_value.clone() {
            return Box::new(CachedStringable(cached));
        }
        let (association, destination_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_destination_address())
        };
        let value = self
            .markup_type
            .get_current_destination_value(&*association, &destination_address)
            .to_string();
        self.cache.lock().unwrap().destination_value = Some(value.clone());
        Box::new(CachedStringable(value))
    }

    /// Java: `getOriginalDestinationValue()`, the value the destination held before this item was
    /// applied -- taken from storage once an apply has recorded it there.
    pub fn get_original_destination_value(&self) -> Box<dyn Stringable> {
        let stored = self.storage().get_destination_value();
        if !stored.to_string().is_empty() {
            return stored;
        }
        self.validate_destination_cache();
        if let Some(cached) = self.cache.lock().unwrap().original_destination_value.clone() {
            return Box::new(CachedStringable(cached));
        }
        let (association, destination_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_destination_address())
        };
        let value = self
            .markup_type
            .get_original_destination_value(&*association, &destination_address)
            .to_string();
        self.cache.lock().unwrap().original_destination_value = Some(value.clone());
        Box::new(CachedStringable(value))
    }

    /// Java: `getSourceValue()`.
    pub fn get_source_value(&self) -> Box<dyn Stringable> {
        let stored = self.storage().get_source_value();
        if !stored.to_string().is_empty() {
            return stored;
        }
        self.validate_source_cache();
        if let Some(cached) = self.cache.lock().unwrap().source_value.clone() {
            return Box::new(CachedStringable(cached));
        }
        let (association, source_address) = {
            let storage = self.storage();
            (storage.get_association(), storage.get_source_address())
        };
        let value =
            self.markup_type.get_source_value(&*association, &source_address).to_string();
        self.cache.lock().unwrap().source_value = Some(value.clone());
        Box::new(CachedStringable(value))
    }

    /// Java: `validateSourceCache()` (private).
    fn validate_source_cache(&self) {
        let current = self.get_source_modification_number();
        let mut cache = self.cache.lock().unwrap();
        if cache.source_modification_number != current {
            cache.source_value = None;
            cache.source_modification_number = current;
            cache.has_same_values = None;
        }
    }

    /// Java: `validateDestinationCache()` (private).
    fn validate_destination_cache(&self) {
        let current = self.get_destination_modification_number();
        let mut cache = self.cache.lock().unwrap();
        if cache.destination_modification_number != current {
            cache.destination_value = None;
            cache.original_destination_value = None;
            cache.destination_modification_number = current;
            cache.has_same_values = None;
        }
    }

    /// Java: `getSourceModificationNumber()` (private). Reports `0` for an association with no
    /// database-backed session, which keeps the cache valid rather than invalidating it on every
    /// read.
    fn get_source_modification_number(&self) -> i64 {
        self.get_association()
            .get_session_db()
            .map_or(0, |session| session.get_source_program().get_modification_number())
    }

    /// Java: `getDestinationModificationNumber()` (private). See
    /// [`get_source_modification_number`](Self::get_source_modification_number).
    fn get_destination_modification_number(&self) -> i64 {
        self.get_association()
            .get_session_db()
            .map_or(0, |session| session.get_destination_program().get_modification_number())
    }

    /// Java: `fireMarkupItemStatusChanged(VTMarkupItemStatus, VTMarkupItemStatus)` (private),
    /// whose `instanceof VTAssociationDB` guard is carried by the seam's defaulted no-op.
    fn fire_markup_item_status_changed(
        &self,
        old_status: VtMarkupItemStatus,
        new_status: VtMarkupItemStatus,
    ) {
        let association = self.get_association();
        association.markup_item_status_changed(self);
        if let Some(session) = association.get_session_db() {
            session.markup_item_status_changed(self, old_status, new_status);
        }
    }
}

/// Java: `toString()`, which delegates to `markupItemStorage.toString()`. The ported
/// [`MarkupItemStorage`] trait carries no `Display` bound, so the same field set is rendered here
/// through its accessors.
impl std::fmt::Display for MarkupItemImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let storage = self.storage();
        writeln!(f)?;
        writeln!(f, "MarkupItemImpl")?;
        writeln!(f, "\tSource Address          = {}", storage.get_source_address())?;
        writeln!(f, "\tMarkup Type             = {}", self.markup_type.get_display_name())?;
        writeln!(f, "\tStatus                  = {}", storage.get_status())?;
        writeln!(f, "\tStatus Description      = {}", storage.get_status_description())?;
        writeln!(f, "\tSource Value            = {}", storage.get_source_value().to_string())
    }
}

/// Java: `TaskMonitor.DUMMY`, the monitor `MarkupItemImpl` passes whenever it asks its association
/// for the other markup items. Never cancels.
struct DummyTaskMonitor;

impl TaskMonitor for DummyTaskMonitor {
    fn check_cancelled(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Java: `new ToolOptions("VT Options Default")`, the empty options
/// [`MarkupItemImpl::apply`] substitutes for a null argument.
struct DefaultToolOptions;

impl ToolOptions for DefaultToolOptions {
    fn get_option(&self, _key: &str) -> Option<String> {
        None
    }
}

/// A cached value, which the seam's [`Stringable`] reduces to its rendering. See the module docs.
struct CachedStringable(String);

impl Stringable for CachedStringable {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// Lets a `MarkupItemImpl` be handed to the seams typed against the placeholder `VTMarkupItem`
/// interface: the association hooks it notifies, and the sibling items an association returns for
/// [`MarkupItemImpl::unapply`] to sweep up. Every member forwards to the inherent method of the
/// same name above.
impl VtMarkupItem for MarkupItemImpl {
    fn can_apply(&self) -> bool {
        MarkupItemImpl::can_apply(self)
    }

    fn can_unapply(&self) -> bool {
        MarkupItemImpl::can_unapply(self)
    }

    fn apply(
        &self,
        apply_action: VtMarkupItemApplyActionType,
        options: &dyn ToolOptions,
    ) -> Result<(), VersionTrackingApplyException> {
        MarkupItemImpl::apply(self, apply_action, Some(options))
    }

    fn unapply(&self) -> Result<(), VersionTrackingApplyException> {
        MarkupItemImpl::unapply(self)
    }

    fn set_default_destination_address(&self, address: &Address, address_source: &str) {
        MarkupItemImpl::set_default_destination_address(self, address, address_source)
    }

    fn set_destination_address(&self, address: &Address) {
        MarkupItemImpl::set_destination_address(self, address)
    }

    fn set_considered(&self, status: &dyn VtMarkupItemConsideredStatus) {
        MarkupItemImpl::set_considered(self, status)
    }

    fn get_destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus {
        MarkupItemImpl::get_destination_address_edit_status(self)
    }

    fn get_status(&self) -> VtMarkupItemStatus {
        MarkupItemImpl::get_status(self)
    }

    fn get_status_description(&self) -> String {
        MarkupItemImpl::get_status_description(self)
    }

    fn get_association(&self) -> Box<dyn VtAssociation> {
        MarkupItemImpl::get_association(self)
    }

    fn get_source_address(&self) -> Address {
        MarkupItemImpl::get_source_address(self)
    }

    fn get_source_location(&self) -> Box<dyn ProgramLocation> {
        MarkupItemImpl::get_source_location(self)
    }

    fn get_source_value(&self) -> Box<dyn Stringable> {
        MarkupItemImpl::get_source_value(self)
    }

    /// Panics for an item with no destination address yet; the trait's non-optional return cannot
    /// express Java's `null`. Use the inherent accessor, which returns an `Option`.
    fn get_destination_address(&self) -> Address {
        MarkupItemImpl::get_destination_address(self)
            .expect("markup item has no destination address")
    }

    fn get_destination_location(&self) -> Box<dyn ProgramLocation> {
        MarkupItemImpl::get_destination_location(self)
    }

    fn get_destination_address_source(&self) -> String {
        MarkupItemImpl::get_destination_address_source(self)
    }

    fn get_current_destination_value(&self) -> Box<dyn Stringable> {
        MarkupItemImpl::get_current_destination_value(self)
    }

    fn get_original_destination_value(&self) -> Box<dyn Stringable> {
        MarkupItemImpl::get_original_destination_value(self)
    }

    fn supports_apply_action(&self, action_type: VtMarkupItemApplyActionType) -> bool {
        MarkupItemImpl::supports_apply_action(self, action_type)
    }

    fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
        self.storage().get_markup_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::feature::seam_stubs::{VtAssociationMarkupStatus, VtAssociationType};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    /// A markup type whose answers the tests can dictate, standing in for the real (unported)
    /// markup types.
    struct TestMarkupType {
        base: VtMarkupTypeBase,
        entry_point_based: bool,
        data_type_based: bool,
        conflicts: bool,
        same_values: bool,
        unapplied: AtomicUsize,
    }

    impl TestMarkupType {
        fn new(name: &'static str) -> Self {
            Self {
                base: VtMarkupTypeBase::new(name),
                entry_point_based: false,
                data_type_based: false,
                conflicts: false,
                same_values: false,
                unapplied: AtomicUsize::new(0),
            }
        }
    }

    impl VtMarkupType for TestMarkupType {
        fn base(&self) -> &VtMarkupTypeBase {
            &self.base
        }

        fn is_function_entry_point_based(&self) -> bool {
            self.entry_point_based
        }

        fn is_data_type_based(&self) -> bool {
            self.data_type_based
        }

        fn conflicts_with_other_markup(
            &self,
            _markup_item: &MarkupItemImpl,
            _markup_items: &[Box<dyn VtMarkupItem>],
        ) -> bool {
            self.conflicts
        }

        fn has_same_source_and_destination_values(&self, _markup_item: &MarkupItemImpl) -> bool {
            self.same_values
        }

        fn supports_apply_action(&self, apply_action: VtMarkupItemApplyActionType) -> bool {
            apply_action == VtMarkupItemApplyActionType::Replace
        }

        fn unapply_markup(
            &self,
            _markup_item: &MarkupItemImpl,
        ) -> Result<(), VersionTrackingApplyException> {
            self.unapplied.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// An association with a settable status and no markup items of its own.
    struct TestAssociation {
        status: VtAssociationStatus,
    }

    impl VtAssociation for TestAssociation {
        fn get_type(&self) -> Box<dyn VtAssociationType> {
            unimplemented!("not used by these tests")
        }

        fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession> {
            unimplemented!("not used by these tests")
        }

        fn get_markup_items(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>> {
            Ok(Vec::new())
        }

        fn has_applied_markup_items(&self) -> bool {
            false
        }

        fn get_source_address(&self) -> Address {
            address(0x1000)
        }

        fn get_destination_address(&self) -> Address {
            address(0x2000)
        }

        fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn set_markup_status(&self, _markup_items_status: &dyn VtAssociationMarkupStatus) {}

        fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus> {
            unimplemented!("not used by these tests")
        }

        fn get_status(&self) -> Box<dyn crate::feature::seam_stubs::VtAssociationStatus> {
            Box::new(self.status)
        }

        fn set_accepted(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn clear_status(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn set_rejected(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn get_vote_count(&self) -> i32 {
            0
        }

        fn set_vote_count(&self, _vote_count: i32) {}
    }

    /// Java: `VTMarkupItemConsideredStatus.IGNORE_DONT_CARE`.
    struct IgnoreDontCare;

    impl VtMarkupItemConsideredStatus for IgnoreDontCare {
        fn is_considered(&self) -> bool {
            true
        }

        fn get_markup_item_status(&self) -> VtMarkupItemStatus {
            VtMarkupItemStatus::DontCare
        }
    }

    fn item_with(
        markup_type: TestMarkupType,
        status: VtAssociationStatus,
    ) -> (MarkupItemImpl, Arc<TestMarkupType>) {
        let markup_type = Arc::new(markup_type);
        let item = MarkupItemImpl::new(
            Arc::new(TestAssociation { status }),
            markup_type.clone() as Arc<dyn VtMarkupType>,
            address(0x1000),
        );
        (item, markup_type)
    }

    fn item(markup_type: TestMarkupType) -> MarkupItemImpl {
        item_with(markup_type, VtAssociationStatus::Accepted).0
    }

    #[test]
    fn markup_type_and_display_name_come_from_the_storage() {
        let markup_item = item(TestMarkupType::new("EOL Comment"));
        assert_eq!(markup_item.get_markup_type().get_display_name(), "EOL Comment");
        assert_eq!(markup_item.get_display_name(), "EOL Comment");
        assert_eq!(markup_item.get_source_address(), address(0x1000));
    }

    #[test]
    fn a_fresh_item_is_unapplied_with_no_destination() {
        let markup_item = item(TestMarkupType::new("Label"));
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Unapplied);
        assert_eq!(markup_item.get_destination_address(), None);
        assert_eq!(markup_item.get_destination_address_source(), "");
        assert!(!markup_item.can_unapply());
        // Java: an in-memory MarkupItemStorageImpl is not a DbObject.
        assert!(!markup_item.is_stored_in_db());
        assert_eq!(markup_item.get_storage_db_key(), None);
    }

    #[test]
    fn status_reports_same_when_the_markup_type_says_the_values_match() {
        let mut markup_type = TestMarkupType::new("Label");
        markup_type.same_values = true;
        let markup_item = item(markup_type);
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Same);
    }

    #[test]
    fn status_reports_conflict_when_the_markup_type_finds_one() {
        let mut markup_type = TestMarkupType::new("Label");
        markup_type.conflicts = true;
        // Conflict wins over SAME, matching the order of the Java checks.
        markup_type.same_values = true;
        let markup_item = item(markup_type);
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Conflict);
    }

    #[test]
    fn set_considered_records_the_status_it_carries() {
        let markup_item = item(TestMarkupType::new("Label"));
        markup_item.set_considered(&IgnoreDontCare);
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::DontCare);
        // DONT_CARE is not a default status, so the storage is kept rather than reset.
        assert!(!markup_item.get_status().is_default());
    }

    #[test]
    fn setting_a_user_defined_destination_records_the_address_and_its_source() {
        let markup_item = item(TestMarkupType::new("Label"));
        markup_item.set_destination_address(&address(0x2000));
        assert_eq!(markup_item.get_destination_address(), Some(address(0x2000)));
        assert_eq!(markup_item.get_destination_address_source(), USER_DEFINED_ADDRESS_SOURCE);
    }

    #[test]
    fn a_default_destination_keeps_the_correlator_as_its_address_source() {
        let markup_item = item(TestMarkupType::new("Label"));
        // Java: an address whose source is not USER_DEFINED leaves the storage resettable, and
        // the in-memory storage's reset() is a no-op that keeps the recorded address.
        markup_item.set_default_destination_address(&address(0x2000), "Correlator");
        assert_eq!(markup_item.get_destination_address(), Some(address(0x2000)));
        assert_eq!(markup_item.get_destination_address_source(), "Correlator");
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Unapplied);
    }

    #[test]
    fn destination_address_edit_status_follows_the_markup_type_then_the_association() {
        let mut entry_point_based = TestMarkupType::new("Function Name");
        entry_point_based.entry_point_based = true;
        assert_eq!(
            item(entry_point_based).get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::UneditableFunctionEntryPoint
        );

        let mut data_type_based = TestMarkupType::new("Data Type");
        data_type_based.data_type_based = true;
        assert_eq!(
            item(data_type_based).get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::UneditableDataAddress
        );

        let (blocked, _) = item_with(TestMarkupType::new("Label"), VtAssociationStatus::Blocked);
        assert_eq!(
            blocked.get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableAssociationStatus
        );

        assert_eq!(
            item(TestMarkupType::new("Label")).get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::Editable
        );
    }

    #[test]
    fn a_same_valued_item_still_allows_editing_its_destination() {
        // Java: SAME is not appliable, but it is excluded from the unappliable-status check.
        let mut markup_type = TestMarkupType::new("Label");
        markup_type.same_values = true;
        let markup_item = item(markup_type);
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Same);
        assert_eq!(
            markup_item.get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::Editable
        );
    }

    #[test]
    fn a_conflicting_item_cannot_have_its_destination_edited() {
        let mut markup_type = TestMarkupType::new("Label");
        markup_type.conflicts = true;
        let markup_item = item(markup_type);
        assert_eq!(
            markup_item.get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::UneditableUnappliableMarkupStatus
        );
    }

    #[test]
    fn can_apply_requires_an_appliable_association_an_appliable_status_and_no_conflict() {
        assert!(item(TestMarkupType::new("Label")).can_apply());

        let (blocked, _) = item_with(TestMarkupType::new("Label"), VtAssociationStatus::Blocked);
        assert!(!blocked.can_apply());

        let mut conflicting = TestMarkupType::new("Label");
        conflicting.conflicts = true;
        assert!(!item(conflicting).can_apply());
    }

    #[test]
    fn apply_refuses_an_association_that_is_not_accepted() {
        let (markup_item, _) =
            item_with(TestMarkupType::new("Label"), VtAssociationStatus::Available);
        let error = markup_item
            .apply(VtMarkupItemApplyActionType::Replace, None)
            .expect_err("an available association cannot be applied");
        assert_eq!(error.message(), "Can't apply a markup item for a match that is not accepted.");
    }

    #[test]
    fn apply_without_a_destination_address_fails_the_item() {
        let markup_item = item(TestMarkupType::new("Label"));
        let error = markup_item
            .apply(VtMarkupItemApplyActionType::Replace, None)
            .expect_err("an item with no destination cannot be applied");
        assert_eq!(
            error.message(),
            "Cannot apply a markup item without first setting the destination address"
        );
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::FailedApply);
        assert_eq!(markup_item.get_status_description(), "Can't apply without a valid destination");
    }

    #[test]
    fn unapply_returns_the_item_to_unapplied_through_the_markup_type() {
        let (markup_item, markup_type) =
            item_with(TestMarkupType::new("Label"), VtAssociationStatus::Accepted);
        markup_item.set_destination_address(&address(0x2000));
        markup_item.unapply().expect("unapply should succeed");

        assert_eq!(markup_type.unapplied.load(Ordering::SeqCst), 1);
        assert_eq!(markup_item.get_status(), VtMarkupItemStatus::Unapplied);
    }

    #[test]
    fn supports_apply_action_delegates_to_the_markup_type() {
        let markup_item = item(TestMarkupType::new("Label"));
        assert!(markup_item.supports_apply_action(VtMarkupItemApplyActionType::Replace));
        assert!(!markup_item.supports_apply_action(VtMarkupItemApplyActionType::Add));
    }

    #[test]
    fn display_renders_the_storage_fields_java_prints() {
        let rendered = item(TestMarkupType::new("EOL Comment")).to_string();
        assert!(rendered.contains("Markup Type             = EOL Comment"), "{rendered}");
        assert!(rendered.contains("Status                  = Unapplied"), "{rendered}");
    }

    #[test]
    fn the_seam_trait_reports_what_the_inherent_accessors_do() {
        let mut markup_type = TestMarkupType::new("Label");
        markup_type.same_values = true;
        let markup_item = item(markup_type);
        let seam: &dyn VtMarkupItem = &markup_item;
        assert_eq!(seam.get_status(), VtMarkupItemStatus::Same);
        assert_eq!(seam.get_markup_type().get_display_name(), "Label");
        assert!(!seam.can_unapply());
        assert_eq!(
            seam.get_destination_address_edit_status(),
            VtMarkupItemDestinationAddressEditStatus::Editable
        );
    }

    #[test]
    fn the_seam_trait_can_drive_a_mutation() {
        let markup_item = item(TestMarkupType::new("Label"));
        let seam: &dyn VtMarkupItem = &markup_item;
        seam.set_destination_address(&address(0x2000));
        assert_eq!(markup_item.get_destination_address(), Some(address(0x2000)));
    }
}
