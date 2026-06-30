/// Commit status of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    NotDone,
    Committed,
    Aborted,
    NotDoneButAborted,
}

/// Describes a transaction and its current state.
pub trait TransactionInfo {
    /// Returns the unique identifier for this transaction.
    fn get_id(&self) -> i64;

    /// Returns the description of this transaction.
    fn get_description(&self) -> &str;

    /// Returns the list of open sub-transactions contained inside this transaction.
    fn get_open_sub_transactions(&self) -> Vec<String>;

    /// Returns the status of this transaction.
    fn get_status(&self) -> TransactionStatus;

    /// Returns `true` if this transaction and all sub-transactions have been committed
    /// to the underlying database.
    fn has_committed_db_transaction(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransaction {
        id: i64,
        description: String,
        sub_transactions: Vec<String>,
        status: TransactionStatus,
        committed: bool,
    }

    impl TransactionInfo for MockTransaction {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_description(&self) -> &str {
            &self.description
        }

        fn get_open_sub_transactions(&self) -> Vec<String> {
            self.sub_transactions.clone()
        }

        fn get_status(&self) -> TransactionStatus {
            self.status
        }

        fn has_committed_db_transaction(&self) -> bool {
            self.committed
        }
    }

    fn make_tx(status: TransactionStatus, committed: bool) -> MockTransaction {
        MockTransaction {
            id: 1,
            description: "test".to_string(),
            sub_transactions: vec![],
            status,
            committed,
        }
    }

    #[test]
    fn test_get_id() {
        let tx = MockTransaction {
            id: 42,
            description: String::new(),
            sub_transactions: vec![],
            status: TransactionStatus::NotDone,
            committed: false,
        };
        assert_eq!(tx.get_id(), 42);
    }

    #[test]
    fn test_get_description() {
        let tx = MockTransaction {
            id: 0,
            description: "my transaction".to_string(),
            sub_transactions: vec![],
            status: TransactionStatus::NotDone,
            committed: false,
        };
        assert_eq!(tx.get_description(), "my transaction");
    }

    #[test]
    fn test_get_open_sub_transactions() {
        let tx = MockTransaction {
            id: 0,
            description: String::new(),
            sub_transactions: vec!["sub1".to_string(), "sub2".to_string()],
            status: TransactionStatus::NotDone,
            committed: false,
        };
        assert_eq!(tx.get_open_sub_transactions(), vec!["sub1", "sub2"]);
    }

    #[test]
    fn test_empty_sub_transactions() {
        let tx = make_tx(TransactionStatus::Committed, true);
        assert!(tx.get_open_sub_transactions().is_empty());
    }

    #[test]
    fn test_status_variants() {
        assert_eq!(make_tx(TransactionStatus::NotDone, false).get_status(), TransactionStatus::NotDone);
        assert_eq!(make_tx(TransactionStatus::Committed, true).get_status(), TransactionStatus::Committed);
        assert_eq!(make_tx(TransactionStatus::Aborted, false).get_status(), TransactionStatus::Aborted);
        assert_eq!(
            make_tx(TransactionStatus::NotDoneButAborted, false).get_status(),
            TransactionStatus::NotDoneButAborted
        );
    }

    #[test]
    fn test_has_committed_db_transaction() {
        assert!(!make_tx(TransactionStatus::NotDone, false).has_committed_db_transaction());
        assert!(make_tx(TransactionStatus::Committed, true).has_committed_db_transaction());
    }
}
