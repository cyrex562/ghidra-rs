use crate::framework::model::DomainObject;

/// A factory for creating transactions.
///
/// Equivalent to Java's `BiFunction<T, String, U>` where T is a DomainObject.
/// Takes a reference to a DomainObject and a description string, producing a value of type U.
pub trait TxFactory<T: DomainObject, U>: Send + Sync {
    /// Applies this factory to produce a result given a domain object and description.
    fn apply(&self, obj: &T, description: &str) -> U;
}

/// Represents a coalesced transaction that can be closed.
///
/// Equivalent to Java's `AutoCloseable` interface. Implementations should
/// handle cleanup when dropped or when `close()` is explicitly called.
pub trait CoalescedTx: Send + Sync {
    /// Closes this coalesced transaction, performing any necessary cleanup.
    fn close(&mut self);
}

/// A transaction coalescer manages coalesced transactions on domain objects.
///
/// Port of `ghidra.app.plugin.core.debug.utils.TransactionCoalescer`.
pub trait TransactionCoalescer {
    /// Starts a new coalesced transaction with the given description.
    ///
    /// # Arguments
    /// * `description` - A description of the transaction
    ///
    /// # Returns
    /// A boxed trait object implementing `CoalescedTx` that must be closed
    /// when the transaction is complete.
    fn start(&self, description: &str) -> Box<dyn CoalescedTx>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of CoalescedTx for testing.
    struct MockCoalescedTx {
        closed: bool,
    }

    impl MockCoalescedTx {
        fn new() -> Self {
            MockCoalescedTx { closed: false }
        }
    }

    impl CoalescedTx for MockCoalescedTx {
        fn close(&mut self) {
            self.closed = true;
        }
    }

    /// Mock implementation of TxFactory for testing.
    struct MockTxFactory;

    impl<T: DomainObject> TxFactory<T, MockCoalescedTx> for MockTxFactory {
        fn apply(&self, _obj: &T, _description: &str) -> MockCoalescedTx {
            MockCoalescedTx::new()
        }
    }

    /// Mock implementation of TransactionCoalescer for testing.
    struct MockTransactionCoalescer;

    impl TransactionCoalescer for MockTransactionCoalescer {
        fn start(&self, _description: &str) -> Box<dyn CoalescedTx> {
            Box::new(MockCoalescedTx::new())
        }
    }

    #[test]
    fn test_mock_transaction_coalescer_start() {
        let coalescer = MockTransactionCoalescer;
        let mut tx = coalescer.start("test description");
        tx.close();
    }

    #[test]
    fn test_mock_coalesced_tx_close() {
        let mut tx = MockCoalescedTx::new();
        assert!(!tx.closed);
        tx.close();
        assert!(tx.closed);
    }

    #[test]
    fn test_tx_factory_apply() {
        // This test just verifies that the trait can be implemented
        // A real implementation would be tested with actual domain objects
        let _factory = MockTxFactory;
    }
}
