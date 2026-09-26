use crate::feature::bsim::query::protocol::QueryResponseRecord;

/// A listener that will be called as incremental results arrive from database queries.
///
/// The results given to this listener are always a subset of the complete results.
/// Consumer should be able to safely cast response based upon the type of query being performed.
///
/// Port of `ghidra.features.bsim.query.facade.SFResultsUpdateListener<R>`.
///
/// # Generic Parameter
///
/// * `R` - the final result implementation class
pub trait SFResultsUpdateListener<R>: Send + Sync {
    /// Called as incremental results arrive from database queries.
    ///
    /// The results given to this listener are always a subset of the complete results—they
    /// are not comprehensive.
    ///
    /// Java: `resultAdded(QueryResponseRecord partialResponse)`.
    fn result_added(&self, partial_response: &dyn QueryResponseRecord);

    /// Callback to supply the final accumulated result.
    ///
    /// Java: `setFinalResult(R result)`.
    fn set_final_result(&self, result: Option<R>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct MockResponse;

    impl QueryResponseRecord for MockResponse {
        fn base(&self) -> &crate::feature::bsim::query::protocol::QueryResponseRecordBase {
            unimplemented!("mock")
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MockListener {
        result_added_called: std::sync::atomic::AtomicBool,
        set_final_result_called: std::sync::atomic::AtomicBool,
    }

    impl MockListener {
        fn new() -> Self {
            Self {
                result_added_called: std::sync::atomic::AtomicBool::new(false),
                set_final_result_called: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl SFResultsUpdateListener<String> for MockListener {
        fn result_added(&self, _partial_response: &dyn QueryResponseRecord) {
            self.result_added_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_final_result(&self, _result: Option<String>) {
            self.set_final_result_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_listener_result_added_called() {
        let listener = MockListener::new();
        let mock_response = MockResponse;

        listener.result_added(&mock_response);
        assert!(listener.result_added_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_listener_set_final_result_with_some() {
        let listener = MockListener::new();

        listener.set_final_result(Some("final_result".to_string()));
        assert!(listener.set_final_result_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_listener_set_final_result_with_none() {
        let listener = MockListener::new();

        listener.set_final_result(None);
        assert!(listener.set_final_result_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_listener_both_methods() {
        let listener = MockListener::new();
        let mock_response = MockResponse;

        listener.result_added(&mock_response);
        listener.set_final_result(Some("result".to_string()));

        assert!(listener.result_added_called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(listener.set_final_result_called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
