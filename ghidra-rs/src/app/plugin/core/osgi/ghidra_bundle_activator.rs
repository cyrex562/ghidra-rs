use super::{BundleActivator, BundleContext};

/// Abstract base trait for Ghidra bundle activators.
///
/// This trait extends the OSGi BundleActivator interface to provide a more convenient
/// API for Ghidra plugins. Implementations define their own lifecycle behavior via the
/// `start` and `stop` methods, which receive both a bundle context and an optional API object.
///
/// The `GhidraBundleActivator` trait handles the bridging between the OSGi interface and
/// the Ghidra-specific lifecycle, passing `None` for the API parameter when calling the
/// abstract methods.
pub trait GhidraBundleActivator: Send + Sync {
    /// Called when the bundle is started.
    ///
    /// # Arguments
    /// * `context` - The bundle context
    /// * `api` - An optional API object (typically `None` in standard Ghidra deployments)
    fn start(&self, context: &BundleContext, api: Option<&dyn std::any::Any>) -> Result<(), String>;

    /// Called when the bundle is stopped.
    ///
    /// # Arguments
    /// * `context` - The bundle context
    /// * `api` - An optional API object (typically `None` in standard Ghidra deployments)
    fn stop(&self, context: &BundleContext, api: Option<&dyn std::any::Any>) -> Result<(), String>;
}

/// Default adapter implementing BundleActivator for any GhidraBundleActivator.
///
/// This struct provides a bridge between the `GhidraBundleActivator` trait and the
/// `BundleActivator` interface by automatically passing `None` for the API parameter.
pub struct GhidraBundleActivatorAdapter<T: GhidraBundleActivator> {
    inner: T,
}

impl<T: GhidraBundleActivator> GhidraBundleActivatorAdapter<T> {
    /// Creates a new adapter wrapping a GhidraBundleActivator implementation.
    pub fn new(activator: T) -> Self {
        GhidraBundleActivatorAdapter { inner: activator }
    }
}

impl<T: GhidraBundleActivator> BundleActivator for GhidraBundleActivatorAdapter<T> {
    fn start(&self, context: &BundleContext) -> Result<(), String> {
        self.inner.start(context, None)
    }

    fn stop(&self, context: &BundleContext) -> Result<(), String> {
        self.inner.stop(context, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct TestActivator {
        start_called: Arc<AtomicBool>,
        stop_called: Arc<AtomicBool>,
    }

    impl GhidraBundleActivator for TestActivator {
        fn start(&self, _context: &BundleContext, _api: Option<&dyn std::any::Any>) -> Result<(), String> {
            self.start_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn stop(&self, _context: &BundleContext, _api: Option<&dyn std::any::Any>) -> Result<(), String> {
            self.stop_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_ghidra_bundle_activator_adapter_calls_start() {
        let start_called = Arc::new(AtomicBool::new(false));
        let stop_called = Arc::new(AtomicBool::new(false));
        let activator = TestActivator {
            start_called: start_called.clone(),
            stop_called: stop_called.clone(),
        };
        let adapter = GhidraBundleActivatorAdapter::new(activator);
        let context = BundleContext;

        let result = adapter.start(&context);
        assert!(result.is_ok());
        assert!(start_called.load(Ordering::SeqCst));
        assert!(!stop_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_ghidra_bundle_activator_adapter_calls_stop() {
        let start_called = Arc::new(AtomicBool::new(false));
        let stop_called = Arc::new(AtomicBool::new(false));
        let activator = TestActivator {
            start_called: start_called.clone(),
            stop_called: stop_called.clone(),
        };
        let adapter = GhidraBundleActivatorAdapter::new(activator);
        let context = BundleContext;

        let result = adapter.stop(&context);
        assert!(result.is_ok());
        assert!(!start_called.load(Ordering::SeqCst));
        assert!(stop_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_bundle_context_is_cloneable() {
        let context = BundleContext;
        let _cloned = context.clone();
    }

    #[test]
    fn test_adapter_passes_none_api() {
        struct ApiCheckActivator;
        impl GhidraBundleActivator for ApiCheckActivator {
            fn start(&self, _context: &BundleContext, api: Option<&dyn std::any::Any>) -> Result<(), String> {
                // Check that api is None as per the contract
                assert!(api.is_none());
                Ok(())
            }

            fn stop(&self, _context: &BundleContext, api: Option<&dyn std::any::Any>) -> Result<(), String> {
                assert!(api.is_none());
                Ok(())
            }
        }

        let adapter = GhidraBundleActivatorAdapter::new(ApiCheckActivator);
        let context = BundleContext;

        let _ = adapter.start(&context);
        let _ = adapter.stop(&context);
    }
}
