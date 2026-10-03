//! Port of `ghidra.feature.fid.db.FidQueryCloseListener`.

use crate::feature::fid::db::fid_query_service::FidQueryService;

/// Listener notified when a [`FidQueryService`] is closed.
///
/// Port of `ghidra.feature.fid.db.FidQueryCloseListener`. This is a listener interface
/// (Java: `public interface FidQueryCloseListener`) that gets invoked when a FID query
/// service is closed.
pub trait FidQueryCloseListener {
    /// Called when the specified FID query service has been closed.
    fn fid_query_closed(&mut self, service: &FidQueryService);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        close_count: usize,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener { close_count: 0 }
        }
    }

    impl FidQueryCloseListener for RecordingListener {
        fn fid_query_closed(&mut self, _service: &FidQueryService) {
            self.close_count += 1;
        }
    }

    #[test]
    fn test_fid_query_closed_called() {
        let mut listener = RecordingListener::new();
        let mut service = FidQueryService::new(&[], None, false).expect("build service");
        listener.fid_query_closed(&service);
        assert_eq!(listener.close_count, 1);
        service.close();
    }

    #[test]
    fn test_multiple_close_notifications() {
        let mut listener = RecordingListener::new();
        let mut service = FidQueryService::new(&[], None, false).expect("build service");
        listener.fid_query_closed(&service);
        listener.fid_query_closed(&service);
        listener.fid_query_closed(&service);
        assert_eq!(listener.close_count, 3);
        service.close();
    }
}
