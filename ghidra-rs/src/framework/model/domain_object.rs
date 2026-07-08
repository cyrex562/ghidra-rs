use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::framework::data::domain_object_file_listener::DomainObjectFileListener;
use crate::framework::model::aborted_transaction_listener::AbortedTransactionListener;
use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_object_closed_listener::DomainObjectClosedListener;
use crate::framework::model::domain_object_listener::DomainObjectListener;
use crate::framework::model::event_queue_id::EventQueueID;
use crate::framework::model::transaction_info::TransactionInfo;
use crate::framework::options::Options;
use crate::framework::seam_stubs::TransactionListener;
use crate::framework::store::LockException;
use crate::program::seam_stubs::Transaction;
use crate::util::exception::CancelledException;
use crate::util::function::{ExceptionalCallback, ExceptionalSupplier};
use crate::util::task::TaskMonitor;
use crate::util::ReadOnlyException;

/// Opaque identity token standing in for Java's identity-compared `Object consumer` parameter
/// used by [`DomainObject::add_consumer`], [`DomainObject::release`], and
/// [`DomainObject::is_used_by`].
pub type DomainObjectConsumer = Arc<dyn Any + Send + Sync>;

/// Combines the checked exceptions declared on `DomainObject.save`/`DomainObject.saveToPackedFile`
/// (`IOException`, `CancelledException`), plus `ReadOnlyException` (a subclass of `IOException`
/// in Java, called out explicitly in `save`'s documentation).
#[derive(Error, Debug)]
pub enum SaveError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ReadOnly(#[from] ReadOnlyException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// <CODE>DomainObject</CODE> is the interface that must be supported by
/// data objects that are persistent. <CODE>DomainObject</CODE>s maintain an
/// association with a <CODE>DomainFile</CODE>. A <CODE>DomainObject</CODE> that
/// has never been saved will have a `None` domain file.
///
/// Supports transactions and the ability to undo/redo changes made within a stack of recent
/// transactions. Each transaction may contain many sub-transactions which reflect concurrent
/// changes to the domain object. If any sub-transaction fails to commit, all concurrent
/// sub-transaction changes will be rolled back.
///
/// NOTE: A *transaction* must be started in order to make any change to this domain object.
///
/// Port of `ghidra.framework.model.DomainObject`.
///
/// This trait was promoted from a minimal placeholder (see `program::seam_stubs`) that declared
/// no methods, so there is nothing to retain as a superset here. Every method is given a default
/// so that the existing bare `impl DomainObject for MockX {}` block (in
/// [`DataTypeManagerDomainObject`](crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject)'s
/// tests) keeps compiling unmodified. Concrete implementations (`DomainObjectAdapterDB`, etc.)
/// will override these with real behavior once they are ported. Where a Java default method
/// exists (the two `withTransaction` overloads), the Rust default mirrors it exactly. Where no
/// Java default exists, a trivial fallback describing a fresh, unshared, never-saved domain
/// object is used.
///
/// The deprecated `DO_OBJECT_*` event type constants and the `undoLock` synchronization object
/// declared on the Java interface are omitted: they are slated for removal upstream and carry no
/// behavior of their own (they only alias `DomainObjectEvent`/`EventType` values, neither of which
/// is ported yet).
pub trait DomainObject {
    /// Returns whether the object has changed.
    fn is_changed(&self) -> bool {
        false
    }

    /// Set the temporary state of this object. If this object is temporary, [`Self::is_changed`]
    /// will always return false.
    fn set_temporary(&mut self, state: bool) {
        let _ = state;
    }

    /// Returns true if this object has been marked as Temporary.
    fn is_temporary(&self) -> bool {
        false
    }

    /// Returns true if changes are permitted.
    fn is_changeable(&self) -> bool {
        true
    }

    /// Returns true if this object can be saved; a read-only file cannot be saved.
    fn can_save(&self) -> bool {
        false
    }

    /// Saves changes to the DomainFile.
    ///
    /// # Errors
    /// Returns `Err` if an I/O error occurs, this object is read-only, or the user cancels via
    /// `monitor`.
    fn save(&mut self, comment: &str, monitor: &dyn TaskMonitor) -> Result<(), SaveError> {
        let _ = (comment, monitor);
        Ok(())
    }

    /// Saves (i.e., serializes) the current content to a packed file.
    ///
    /// # Errors
    /// Returns `Err` if an I/O error occurs or the user cancels via `monitor`.
    fn save_to_packed_file(
        &mut self,
        output_file: &Path,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SaveError> {
        let _ = (output_file, monitor);
        Ok(())
    }

    /// Notify the domain object that the specified consumer is no longer using it. When the last
    /// consumer invokes this method, the domain object will be closed and will become invalid.
    fn release(&mut self, consumer: DomainObjectConsumer) {
        let _ = consumer;
    }

    /// Adds a listener for this object.
    fn add_listener(&mut self, listener: Box<dyn DomainObjectListener>) {
        let _ = listener;
    }

    /// Remove the listener for this object.
    fn remove_listener(&mut self, listener: &dyn DomainObjectListener) {
        let _ = listener;
    }

    /// Adds a listener that will be notified when this DomainObject is closed. This is meant for
    /// clients to have a chance to cleanup, such as reference removal.
    fn add_close_listener(&mut self, listener: Box<dyn DomainObjectClosedListener>) {
        let _ = listener;
    }

    /// Removes the given close listener.
    fn remove_close_listener(&mut self, listener: &dyn DomainObjectClosedListener) {
        let _ = listener;
    }

    /// Adds a listener that will be notified when the DomainFile associated with this
    /// DomainObject changes, such as when a 'Save As' action occurs.
    fn add_domain_file_listener(&mut self, listener: Box<dyn DomainObjectFileListener>) {
        let _ = listener;
    }

    /// Removes the given DomainObjectFileListener listener.
    fn remove_domain_file_listener(&mut self, listener: &dyn DomainObjectFileListener) {
        let _ = listener;
    }

    /// Creates a private event queue that can be flushed independently from the main event
    /// queue, returning a unique identifier for the queue.
    fn create_private_event_queue(
        &mut self,
        listener: Box<dyn DomainObjectListener>,
        max_delay: i32,
    ) -> EventQueueID {
        let _ = (listener, max_delay);
        EventQueueID
    }

    /// Removes the specified private event queue, returning true if the id represented a valid
    /// queue that was removed.
    fn remove_private_event_queue(&mut self, id: EventQueueID) -> bool {
        let _ = id;
        false
    }

    /// Returns a word or short phrase that best describes or categorizes the object in terms
    /// that a user will understand.
    fn get_description(&self) -> String {
        String::new()
    }

    /// Get the name of this domain object.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Set the name for this domain object.
    fn set_name(&mut self, name: &str) {
        let _ = name;
    }

    /// Get the domain file for this domain object, or `None` if it has never been saved.
    fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
        None
    }

    /// Adds the given object as a consumer, returning false if this domain object has already
    /// been closed.
    fn add_consumer(&mut self, consumer: DomainObjectConsumer) -> bool {
        let _ = consumer;
        !self.is_closed()
    }

    /// Returns the list of consumers on this domainObject.
    fn get_consumer_list(&self) -> Vec<DomainObjectConsumer> {
        Vec::new()
    }

    /// Returns true if the given consumer is using (has open) this domain object.
    fn is_used_by(&self, consumer: &DomainObjectConsumer) -> bool {
        let _ = consumer;
        false
    }

    /// If true, domain object change events are sent. If false, no events are sent.
    fn set_events_enabled(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Returns true if this object is sending out events as it is changed. The default is true.
    fn is_sending_events(&self) -> bool {
        true
    }

    /// Makes sure all pending domainEvents have been sent.
    fn flush_events(&mut self) {}

    /// Flush events from the specified event queue.
    fn flush_private_event_queue(&mut self, id: EventQueueID) {
        let _ = id;
    }

    /// Returns true if a modification lock can be obtained on this domain object.
    fn can_lock(&self) -> bool {
        true
    }

    /// Returns true if the domain object currently has a modification lock enabled.
    fn is_locked(&self) -> bool {
        false
    }

    /// Attempt to obtain a modification lock on the domain object, returning true if the lock
    /// was granted.
    fn lock(&mut self, reason: &str) -> bool {
        let _ = reason;
        true
    }

    /// Force transaction lock and terminate current transaction.
    fn force_lock(&mut self, rollback: bool, reason: &str) {
        let _ = (rollback, reason);
    }

    /// Release a modification lock previously granted with the lock method.
    fn unlock(&mut self) {}

    /// Returns all properties lists contained by this domain object.
    fn get_options_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get the property list for the given name.
    fn get_options(&self, property_list_name: &str) -> Box<dyn Options> {
        let _ = property_list_name;
        Box::new(EmptyOptions)
    }

    /// Returns true if this domain object has been closed as a result of the last release.
    fn is_closed(&self) -> bool {
        false
    }

    /// Returns true if the user has exclusive access to the domain object.
    fn has_exclusive_access(&self) -> bool {
        false
    }

    /// Returns a map containing all the stored metadata associated with this domain object.
    fn get_metadata(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Returns a value that gets incremented every time a change, undo, or redo takes place.
    fn get_modification_number(&self) -> i64 {
        0
    }

    /// Open new transaction.
    ///
    /// # Errors
    /// Returns `Err` if this [`DomainObject`] has already been closed (mirrors
    /// `IllegalStateException`).
    fn open_transaction(&mut self, description: &str) -> Result<Box<dyn Transaction>, String> {
        let _ = description;
        Ok(Box::new(NoOpTransaction))
    }

    /// Performs the given callback inside of a transaction. The transaction created by this
    /// method is always committed when the call is finished.
    ///
    /// # Errors
    /// Propagates any error returned by `callback`.
    fn with_transaction(
        &mut self,
        description: &str,
        callback: ExceptionalCallback<String>,
    ) -> Result<(), String> {
        let id = self.start_transaction(description);
        let result = callback();
        self.end_transaction(id, true);
        result
    }

    /// Calls the given supplier inside of a transaction, committing only if it succeeds.
    ///
    /// # Errors
    /// Propagates any error returned by `supplier`.
    fn with_transaction_result<T>(
        &mut self,
        description: &str,
        supplier: ExceptionalSupplier<T, String>,
    ) -> Result<T, String>
    where
        Self: Sized,
    {
        let id = self.start_transaction(description);
        let result = supplier();
        let success = result.is_ok();
        self.end_transaction(id, success);
        result
    }

    /// Start a new transaction in order to make changes to this domain object, returning the
    /// transaction ID. If a transaction is already in progress, a sub-transaction of the current
    /// transaction will be returned.
    fn start_transaction(&mut self, description: &str) -> i32 {
        let _ = description;
        0
    }

    /// Start a new transaction, notifying `listener` if the transaction is aborted.
    fn start_transaction_with_listener(
        &mut self,
        description: &str,
        listener: Box<dyn AbortedTransactionListener>,
    ) -> i32 {
        let _ = listener;
        self.start_transaction(description)
    }

    /// Terminate the specified transaction for this domain object, returning true if this
    /// invocation was the final transaction and all changes were committed.
    fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
        let _ = transaction_id;
        commit
    }

    /// Returns the current transaction info, or `None` if no transaction is active.
    fn get_current_transaction_info(&self) -> Option<Box<dyn TransactionInfo>> {
        None
    }

    /// Returns true if the last transaction was terminated from the action that started it.
    fn has_terminated_transaction(&self) -> bool {
        false
    }

    /// Return all domain objects synchronized with a shared transaction manager, or `None` if
    /// this domain object is not synchronized with others.
    fn get_synchronized_domain_objects(&self) -> Option<Vec<Box<dyn DomainObject>>> {
        None
    }

    /// Synchronize the specified domain object with this domain object using a shared
    /// transaction manager.
    ///
    /// # Errors
    /// Returns `Err` if a lock or open transaction is active on either this or the specified
    /// domain object.
    fn add_synchronized_domain_object(
        &mut self,
        domain_obj: Box<dyn DomainObject>,
    ) -> Result<(), LockException> {
        let _ = domain_obj;
        Ok(())
    }

    /// Remove this domain object from a shared transaction manager.
    ///
    /// # Errors
    /// Returns `Err` if a lock or open transaction is active.
    fn release_synchronized_domain_object(&mut self) -> Result<(), LockException> {
        Ok(())
    }

    /// Returns true if there is a previous state to "undo" to.
    fn can_undo(&self) -> bool {
        false
    }

    /// Returns true if there is a later state to "redo" to.
    fn can_redo(&self) -> bool {
        false
    }

    /// Clear all undoable/redoable transactions.
    fn clear_undo(&mut self) {}

    /// Returns to the previous state. Does nothing if there are no previous states to "undo".
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs.
    fn undo(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Returns to a latter state that exists because of an undo. Does nothing if there are no
    /// latter states to "redo".
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs.
    fn redo(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Returns a description of the change that would be "undone".
    fn get_undo_name(&self) -> String {
        String::new()
    }

    /// Returns a description of the change that would be "redone".
    fn get_redo_name(&self) -> String {
        String::new()
    }

    /// Returns a list of the names of all current undo transactions.
    fn get_all_undo_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Returns a list of the names of all current redo transactions.
    fn get_all_redo_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Adds the given transaction listener to this domain object.
    fn add_transaction_listener(&mut self, listener: Box<dyn TransactionListener>) {
        let _ = listener;
    }

    /// Removes the given transaction listener from this domain object.
    fn remove_transaction_listener(&mut self, listener: &dyn TransactionListener) {
        let _ = listener;
    }
}

/// Trivial fallback used by [`DomainObject::get_options`]'s default implementation: an options
/// list with no properties.
struct EmptyOptions;
impl Options for EmptyOptions {}

/// Trivial fallback used by [`DomainObject::open_transaction`]'s default implementation.
struct NoOpTransaction;
impl Transaction for NoOpTransaction {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDomainObject {
        name: String,
        changed: bool,
    }

    impl DomainObject for MockDomainObject {
        fn is_changed(&self) -> bool {
            self.changed
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut obj = MockDomainObject::default();
        let dyn_obj: &mut dyn DomainObject = &mut obj;
        assert!(!dyn_obj.is_changed());
        dyn_obj.set_name("prog1");
        assert_eq!(dyn_obj.get_name(), "prog1");
        assert!(dyn_obj.is_sending_events());
        assert!(dyn_obj.can_lock());
        assert!(!dyn_obj.is_closed());
    }

    #[test]
    fn with_transaction_commits_and_propagates_result() {
        let mut obj = MockDomainObject::default();

        let ok: ExceptionalCallback<String> = Box::new(|| Ok(()));
        assert!(obj.with_transaction("test", ok).is_ok());

        let err: ExceptionalCallback<String> = Box::new(|| Err("boom".to_string()));
        assert!(obj.with_transaction("test", err).is_err());
    }

    #[test]
    fn with_transaction_result_returns_supplier_value() {
        let mut obj = MockDomainObject::default();
        let supplier: ExceptionalSupplier<i32, String> = Box::new(|| Ok(42));
        assert_eq!(obj.with_transaction_result("test", supplier), Ok(42));
    }

    #[test]
    fn add_consumer_fails_when_closed() {
        struct ClosedDomainObject;
        impl DomainObject for ClosedDomainObject {
            fn is_closed(&self) -> bool {
                true
            }
        }

        let mut obj = ClosedDomainObject;
        let consumer: DomainObjectConsumer = Arc::new(42i32);
        assert!(!obj.add_consumer(consumer));
    }
}
