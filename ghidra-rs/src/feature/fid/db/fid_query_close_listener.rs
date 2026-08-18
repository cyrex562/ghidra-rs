//! Port of `ghidra.feature.fid.db.FidQueryCloseListener`.

use crate::feature::seam_stubs::FidQueryService;

/// Listener notified when a [`FidQueryService`] is closed.
///
/// Port of `ghidra.feature.fid.db.FidQueryCloseListener`. This is a listener interface
/// (Java: `public interface FidQueryCloseListener`) that gets invoked when a FID query
/// service is closed.
pub trait FidQueryCloseListener {
    /// Called when the specified FID query service has been closed.
    fn fid_query_closed(&mut self, service: &dyn FidQueryService);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockFidQueryService;

    impl FidQueryService for MockFidQueryService {
        fn add_close_listener(&self, _listener: &dyn FidQueryCloseListener) {}
        fn remove_close_listener(&self, _listener: &dyn FidQueryCloseListener) {}
        fn get_function_by_id(&self, _function_id: i64) -> Option<Arc<crate::feature::fid::db::function_record::FunctionRecord>> {
            None
        }
        fn get_superior_full_relation(
            &self,
            _superior_function: &crate::feature::fid::db::function_record::FunctionRecord,
            _inferior_function: &dyn crate::feature::fid::hash::fid_hash_quad::FidHashQuad,
        ) -> bool {
            false
        }
        fn get_inferior_full_relation(
            &self,
            _superior_function: &dyn crate::feature::fid::hash::fid_hash_quad::FidHashQuad,
            _inferior_function: &crate::feature::fid::db::function_record::FunctionRecord,
        ) -> bool {
            false
        }
        fn get_library_for_function(
            &self,
            _function_record: &crate::feature::fid::db::function_record::FunctionRecord,
        ) -> Option<Arc<crate::feature::fid::db::library_record::LibraryRecord>> {
            None
        }
        fn find_full_hash_value_at_or_after(&self, _value: i64) -> Option<i64> {
            None
        }
        fn find_functions_by_specific_hash(&self, _specific_hash: i64) -> Vec<Arc<crate::feature::fid::db::function_record::FunctionRecord>> {
            vec![]
        }
        fn find_functions_by_full_hash(&self, _full_hash: i64) -> Vec<Arc<crate::feature::fid::db::function_record::FunctionRecord>> {
            vec![]
        }
        fn find_functions_by_name_substring(&self, _name: &str) -> Vec<Arc<crate::feature::fid::db::function_record::FunctionRecord>> {
            vec![]
        }
        fn find_functions_by_domain_path_substring(&self, _domain_path: &str) -> Vec<Arc<crate::feature::fid::db::function_record::FunctionRecord>> {
            vec![]
        }
        fn close(&self) {}
    }

    struct RecordingListener {
        close_count: usize,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener { close_count: 0 }
        }
    }

    impl FidQueryCloseListener for RecordingListener {
        fn fid_query_closed(&mut self, _service: &dyn FidQueryService) {
            self.close_count += 1;
        }
    }

    #[test]
    fn test_fid_query_closed_called() {
        let mut listener = RecordingListener::new();
        let service = MockFidQueryService;
        listener.fid_query_closed(&service);
        assert_eq!(listener.close_count, 1);
    }

    #[test]
    fn test_multiple_close_notifications() {
        let mut listener = RecordingListener::new();
        let service = MockFidQueryService;
        listener.fid_query_closed(&service);
        listener.fid_query_closed(&service);
        listener.fid_query_closed(&service);
        assert_eq!(listener.close_count, 3);
    }
}
