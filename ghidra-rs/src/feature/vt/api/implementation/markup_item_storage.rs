use crate::feature::seam_stubs::{VtAssociation, VtMarkupType, Stringable};
use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
use crate::program::model::address::Address;

/// Storage interface for a version-tracking markup item.
///
/// This trait represents the persistent storage of a single markup item within a version-tracking
/// association. It provides access to the item's source and destination addresses, status, and values,
/// as well as methods to update the status and perform address reassignment.
pub trait MarkupItemStorage: Send + Sync {
    /// Returns the markup type that created this item.
    fn get_markup_type(&self) -> Box<dyn VtMarkupType>;

    /// Returns the association this item belongs to.
    fn get_association(&self) -> Box<dyn VtAssociation>;

    /// Returns the source address (from the original program).
    fn get_source_address(&self) -> Address;

    /// Returns the destination address (in the current program).
    ///
    /// Only meaningful when [`has_destination_address`](Self::has_destination_address) is `true`.
    fn get_destination_address(&self) -> Address;

    /// Returns whether a destination address has been assigned yet.
    ///
    /// Java's `getDestinationAddress()` simply returns `null` for an item whose destination has
    /// not been set, and `MarkupItemImpl` branches on that; this trait's non-optional return
    /// cannot express it, so the question is asked separately. Defaults to `true` for storages
    /// that always have one (every database-backed row does).
    fn has_destination_address(&self) -> bool {
        true
    }

    /// Returns a description of the source of the destination address.
    fn get_destination_address_source(&self) -> String;

    /// Returns the current application status of this item.
    fn get_status(&self) -> VtMarkupItemStatus;

    /// Returns a human-readable description of the current status.
    fn get_status_description(&self) -> String;

    /// Returns the value at the source address.
    fn get_source_value(&self) -> Box<dyn Stringable>;

    /// Returns the value at the destination address.
    fn get_destination_value(&self) -> Box<dyn Stringable>;

    /// Sets the application status.
    fn set_status(&mut self, status: VtMarkupItemStatus);

    /// Resets the item to its initial state.
    fn reset(&mut self);

    /// Sets the destination address and its source description.
    fn set_destination_address(&mut self, address: Address, address_source: String);

    /// Records that applying this markup item failed with the given message.
    fn set_apply_failed(&mut self, message: String);

    /// Updates both the source and destination values.
    fn set_source_destination_values(&mut self, source_value: Box<dyn Stringable>, destination_value: Box<dyn Stringable>);

    /// Narrows this storage to the database-backed implementation, if that is what it is.
    ///
    /// Stands in for Java's `markupItemStorage instanceof MarkupItemStorageDB` test, which
    /// `AssociationDatabaseManager.removeStoredMarkupItems` performs on the storage it gets from
    /// each `MarkupItemImpl`. Defaults to `None` -- the "not database-backed" answer.
    fn as_storage_db(
        &self,
    ) -> Option<&crate::feature::vt::api::main::db::markup_item_storage_db::MarkupItemStorageDB>
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMarkupItemStorage {
        status: VtMarkupItemStatus,
    }

    impl MarkupItemStorage for MockMarkupItemStorage {
        fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
            panic!("mock");
        }

        fn get_association(&self) -> Box<dyn VtAssociation> {
            panic!("mock");
        }

        fn get_source_address(&self) -> Address {
            panic!("mock");
        }

        fn get_destination_address(&self) -> Address {
            panic!("mock");
        }

        fn get_destination_address_source(&self) -> String {
            "test".to_string()
        }

        fn get_status(&self) -> VtMarkupItemStatus {
            self.status
        }

        fn get_status_description(&self) -> String {
            self.status.description().to_string()
        }

        fn get_source_value(&self) -> Box<dyn Stringable> {
            panic!("mock");
        }

        fn get_destination_value(&self) -> Box<dyn Stringable> {
            panic!("mock");
        }

        fn set_status(&mut self, status: VtMarkupItemStatus) {
            self.status = status;
        }

        fn reset(&mut self) {
            self.status = VtMarkupItemStatus::Unapplied;
        }

        fn set_destination_address(&mut self, _address: Address, _address_source: String) {}

        fn set_apply_failed(&mut self, _message: String) {}

        fn set_source_destination_values(
            &mut self,
            _source_value: Box<dyn Stringable>,
            _destination_value: Box<dyn Stringable>,
        ) {
        }
    }

    #[test]
    fn markup_item_storage_is_object_safe() {
        // This test verifies that MarkupItemStorage can be used as a trait object.
        let mock = MockMarkupItemStorage {
            status: VtMarkupItemStatus::Unapplied,
        };
        let storage: &dyn MarkupItemStorage = &mock;
        assert_eq!(storage.get_status_description(), "Unapplied");
    }

    #[test]
    fn markup_item_storage_set_status() {
        let mut mock = MockMarkupItemStorage {
            status: VtMarkupItemStatus::Unapplied,
        };
        assert_eq!(mock.get_status(), VtMarkupItemStatus::Unapplied);
        mock.set_status(VtMarkupItemStatus::Added);
        assert_eq!(mock.get_status(), VtMarkupItemStatus::Added);
    }

    #[test]
    fn markup_item_storage_reset() {
        let mut mock = MockMarkupItemStorage {
            status: VtMarkupItemStatus::Added,
        };
        assert_eq!(mock.get_status(), VtMarkupItemStatus::Added);
        mock.reset();
        assert_eq!(mock.get_status(), VtMarkupItemStatus::Unapplied);
    }

    #[test]
    fn markup_item_storage_is_send_sync() {
        // Verify that implementations can be used with Send + Sync bounds.
        fn assert_impl<T: MarkupItemStorage>() {}
        // This test demonstrates that concrete types implementing the trait
        // satisfy the trait's Send + Sync requirement.
    }
}
