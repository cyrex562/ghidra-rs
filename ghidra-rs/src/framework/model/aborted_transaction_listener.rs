/// Listener notified when a transaction is aborted.
pub trait AbortedTransactionListener {
    /// Called when the transaction with the given ID has been aborted.
    fn transaction_aborted(&mut self, transaction_id: i64);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        aborted: Vec<i64>,
    }

    impl AbortedTransactionListener for RecordingListener {
        fn transaction_aborted(&mut self, transaction_id: i64) {
            self.aborted.push(transaction_id);
        }
    }

    #[test]
    fn test_transaction_aborted_called_with_id() {
        let mut listener = RecordingListener { aborted: Vec::new() };
        listener.transaction_aborted(42);
        assert_eq!(listener.aborted, vec![42]);
    }

    #[test]
    fn test_multiple_aborts_recorded() {
        let mut listener = RecordingListener { aborted: Vec::new() };
        listener.transaction_aborted(1);
        listener.transaction_aborted(2);
        listener.transaction_aborted(3);
        assert_eq!(listener.aborted, vec![1, 2, 3]);
    }

    #[test]
    fn test_negative_transaction_id() {
        let mut listener = RecordingListener { aborted: Vec::new() };
        listener.transaction_aborted(-1);
        assert_eq!(listener.aborted, vec![-1]);
    }

    #[test]
    fn test_zero_transaction_id() {
        let mut listener = RecordingListener { aborted: Vec::new() };
        listener.transaction_aborted(0);
        assert_eq!(listener.aborted, vec![0]);
    }
}
