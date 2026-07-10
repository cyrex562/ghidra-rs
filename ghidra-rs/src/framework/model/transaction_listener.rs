use crate::framework::model::transaction_info::TransactionInfo;
use crate::framework::seam_stubs::DomainObjectAdapterDB;

/// An interface for listening to transactions.
///
/// Port of `ghidra.framework.model.TransactionListener`.
///
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that declared
/// no methods, so there is nothing to retain as a superset here.
pub trait TransactionListener {
    /// Invoked when a transaction is started.
    fn transaction_started(&mut self, domain_obj: &dyn DomainObjectAdapterDB, tx: &dyn TransactionInfo);

    /// Invoked when a transaction is ended.
    fn transaction_ended(&mut self, domain_obj: &dyn DomainObjectAdapterDB);

    /// Invoked when the stack of available undo/redo's has changed.
    fn undo_stack_changed(&mut self, domain_obj: &dyn DomainObjectAdapterDB);

    /// Notification that undo or redo has occurred.
    fn undo_redo_occurred(&mut self, domain_obj: &dyn DomainObjectAdapterDB);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::transaction_info::TransactionStatus;

    struct MockDomainObjectAdapterDB;
    impl DomainObjectAdapterDB for MockDomainObjectAdapterDB {}

    struct MockTransactionInfo;
    impl TransactionInfo for MockTransactionInfo {
        fn get_id(&self) -> i64 {
            1
        }

        fn get_description(&self) -> &str {
            "test"
        }

        fn get_open_sub_transactions(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_status(&self) -> TransactionStatus {
            TransactionStatus::NotDone
        }

        fn has_committed_db_transaction(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct RecordingListener {
        started: usize,
        ended: usize,
        undo_stack_changed: usize,
        undo_redo: usize,
    }

    impl TransactionListener for RecordingListener {
        fn transaction_started(
            &mut self,
            _domain_obj: &dyn DomainObjectAdapterDB,
            _tx: &dyn TransactionInfo,
        ) {
            self.started += 1;
        }

        fn transaction_ended(&mut self, _domain_obj: &dyn DomainObjectAdapterDB) {
            self.ended += 1;
        }

        fn undo_stack_changed(&mut self, _domain_obj: &dyn DomainObjectAdapterDB) {
            self.undo_stack_changed += 1;
        }

        fn undo_redo_occurred(&mut self, _domain_obj: &dyn DomainObjectAdapterDB) {
            self.undo_redo += 1;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener = RecordingListener::default();
        let dyn_listener: &mut dyn TransactionListener = &mut listener;
        let domain_obj = MockDomainObjectAdapterDB;
        let tx = MockTransactionInfo;

        dyn_listener.transaction_started(&domain_obj, &tx);
        dyn_listener.transaction_ended(&domain_obj);
        dyn_listener.undo_stack_changed(&domain_obj);
        dyn_listener.undo_redo_occurred(&domain_obj);

        assert_eq!(listener.started, 1);
        assert_eq!(listener.ended, 1);
        assert_eq!(listener.undo_stack_changed, 1);
        assert_eq!(listener.undo_redo, 1);
    }
}
