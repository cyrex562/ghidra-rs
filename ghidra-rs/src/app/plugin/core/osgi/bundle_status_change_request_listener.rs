use crate::app::seam_stubs::BundleStatus;

/// Listener for bundle status change requests.
///
/// Port of `ghidra.app.plugin.core.osgi.BundleStatusChangeRequestListener`. Events are thrown by
/// `BundleStatus` component when buttons are clicked. Every method has a Java `default` body, so
/// every method here has a default too -- implementors override only the events they care about.
pub trait BundleStatusChangeRequestListener: Send + Sync {
    /// Invoked when the user requests that a bundle is enabled/disabled.
    ///
    /// # Arguments
    ///
    /// * `status` - the current status
    /// * `new_value` - `true` if enabled, `false` if disabled
    fn bundle_enablement_change_request(&self, status: &dyn BundleStatus, new_value: bool) {
        let _ = (status, new_value);
    }

    /// Invoked when the user requests that a bundle is activated/deactivated.
    ///
    /// # Arguments
    ///
    /// * `status` - the current status
    /// * `new_value` - `true` if activated, `false` if deactivated
    fn bundle_activation_change_request(&self, status: &dyn BundleStatus, new_value: bool) {
        let _ = (status, new_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener that overrides both methods, matching an implementor that handles all events.
    struct TrackingListener {
        enablement_calls: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
        activation_calls: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
    }

    impl BundleStatusChangeRequestListener for TrackingListener {
        fn bundle_enablement_change_request(&self, _status: &dyn BundleStatus, new_value: bool) {
            self.enablement_calls.lock().unwrap().push(new_value);
        }

        fn bundle_activation_change_request(&self, _status: &dyn BundleStatus, new_value: bool) {
            self.activation_calls.lock().unwrap().push(new_value);
        }
    }

    #[test]
    fn enablement_change_request_calls_override() {
        let enablement_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let activation_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TrackingListener {
            enablement_calls: enablement_calls.clone(),
            activation_calls: activation_calls.clone(),
        };

        // Mock BundleStatus
        struct MockBundleStatus;
        impl BundleStatus for MockBundleStatus {
            fn compare_to(&self, _o: &dyn BundleStatus) -> i32 {
                0
            }
            fn is_enabled(&self) -> bool {
                false
            }
            fn set_enabled(&self, _is_enabled: bool) {}
            fn is_read_only(&self) -> bool {
                false
            }
            fn get_type(&self) -> Box<dyn crate::program::seam_stubs::Type> {
                Box::new(MockType)
            }
            fn is_active(&self) -> bool {
                false
            }
            fn set_active(&self, _is_active: bool) {}
            fn set_summary(&self, _summary: &str) {}
            fn get_summary(&self) -> String {
                String::new()
            }
            fn get_file(&self) -> Box<dyn crate::util::seam_stubs::ResourceFile> {
                Box::new(MockResourceFile)
            }
            fn file_exists(&self) -> bool {
                false
            }
            fn get_path_as_string(&self) -> String {
                String::new()
            }
            fn get_location_identifier(&self) -> String {
                String::new()
            }
        }

        struct MockType;
        impl crate::program::seam_stubs::Type for MockType {}

        struct MockResourceFile;
        impl crate::util::seam_stubs::ResourceFile for MockResourceFile {}

        let status = MockBundleStatus;
        listener.bundle_enablement_change_request(&status, true);
        listener.bundle_activation_change_request(&status, false);

        assert_eq!(enablement_calls.lock().unwrap().as_slice(), &[true]);
        assert_eq!(activation_calls.lock().unwrap().as_slice(), &[false]);
    }

    /// A listener that overrides nothing, mirroring an implementor that only cares about one
    /// event -- every method here must still be callable with no observable effect.
    struct SilentListener;
    impl BundleStatusChangeRequestListener for SilentListener {}

    #[test]
    fn unoverridden_methods_are_no_ops() {
        struct MockBundleStatus;
        impl BundleStatus for MockBundleStatus {
            fn compare_to(&self, _o: &dyn BundleStatus) -> i32 {
                0
            }
            fn is_enabled(&self) -> bool {
                false
            }
            fn set_enabled(&self, _is_enabled: bool) {}
            fn is_read_only(&self) -> bool {
                false
            }
            fn get_type(&self) -> Box<dyn crate::program::seam_stubs::Type> {
                Box::new(MockType)
            }
            fn is_active(&self) -> bool {
                false
            }
            fn set_active(&self, _is_active: bool) {}
            fn set_summary(&self, _summary: &str) {}
            fn get_summary(&self) -> String {
                String::new()
            }
            fn get_file(&self) -> Box<dyn crate::util::seam_stubs::ResourceFile> {
                Box::new(MockResourceFile)
            }
            fn file_exists(&self) -> bool {
                false
            }
            fn get_path_as_string(&self) -> String {
                String::new()
            }
            fn get_location_identifier(&self) -> String {
                String::new()
            }
        }

        struct MockType;
        impl crate::program::seam_stubs::Type for MockType {}

        struct MockResourceFile;
        impl crate::util::seam_stubs::ResourceFile for MockResourceFile {}

        let listener = SilentListener;
        let status = MockBundleStatus;
        listener.bundle_enablement_change_request(&status, true);
        listener.bundle_activation_change_request(&status, false);

        let listener: Box<dyn BundleStatusChangeRequestListener> = Box::new(SilentListener);
        listener.bundle_enablement_change_request(&status, true);
        listener.bundle_activation_change_request(&status, false);
    }
}
