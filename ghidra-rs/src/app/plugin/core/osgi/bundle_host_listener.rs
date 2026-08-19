use super::{GhidraBundle, GhidraBundleException};

/// Listener for OSGi framework events.
///
/// Port of `ghidra.app.plugin.core.osgi.BundleHostListener`. Every method has a Java `default`
/// body, so every method here has a default too -- implementors override only the events they
/// care about.
pub trait BundleHostListener: Send + Sync {
    /// Invoked when a bundle is built.
    ///
    /// `summary` is `None` if nothing changed (build returned false).
    fn bundle_built(&self, bundle: &dyn GhidraBundle, summary: Option<&str>) {
        let _ = (bundle, summary);
    }

    /// Invoked when a bundle is enabled or disabled.
    fn bundle_enablement_change(&self, bundle: &dyn GhidraBundle, new_enablement: bool) {
        let _ = (bundle, new_enablement);
    }

    /// Invoked when a bundle is activated or deactivated.
    fn bundle_activation_change(&self, bundle: &dyn GhidraBundle, new_activation: bool) {
        let _ = (bundle, new_activation);
    }

    /// Invoked when a bundle is added to `BundleHost`.
    fn bundle_added(&self, bundle: &dyn GhidraBundle) {
        let _ = bundle;
    }

    /// Invoked when a number of bundles is added at once. A listener should override this
    /// method to avoid repeated invocation of [`bundle_added`](Self::bundle_added) in quick
    /// succession.
    fn bundles_added(&self, bundles: &[&dyn GhidraBundle]) {
        for bundle in bundles {
            self.bundle_added(*bundle);
        }
    }

    /// Invoked when a bundle is removed from `BundleHost`.
    fn bundle_removed(&self, bundle: &dyn GhidraBundle) {
        let _ = bundle;
    }

    /// Invoked when a number of bundles is removed at once. A listener should override this
    /// method to avoid repeated invocation of [`bundle_removed`](Self::bundle_removed) in quick
    /// succession.
    fn bundles_removed(&self, bundles: &[&dyn GhidraBundle]) {
        for bundle in bundles {
            self.bundle_removed(*bundle);
        }
    }

    /// Invoked when `BundleHost` excepts during bundle activation/deactivation.
    fn bundle_exception(&self, exception: &GhidraBundleException) {
        let _ = exception;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::osgi::{BundleCapability, BundleRequirement, GhidraBundleBase};
    use crate::app::seam_stubs::BundleHost;
    use crate::generic::jar::ResourceFile;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Minimal `GhidraBundle` implementer for exercising `BundleHostListener` defaults --
    /// mirrors the pattern used by `ghidra_bundle`'s own tests.
    struct MockBundle {
        base: GhidraBundleBase,
    }

    impl MockBundle {
        fn new() -> Self {
            let bundle_file = ResourceFile::new(std::path::PathBuf::from("/bundles/example.jar"));
            MockBundle {
                base: GhidraBundleBase::new(Arc::new(BundleHost), bundle_file, true, false),
            }
        }
    }

    impl GhidraBundle for MockBundle {
        fn base(&self) -> &GhidraBundleBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut GhidraBundleBase {
            &mut self.base
        }

        fn clean(&mut self) -> bool {
            true
        }

        fn build(&mut self, _writer: &mut dyn Write) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(true)
        }

        fn get_location_identifier(&self) -> String {
            "file:/bundles/example.jar".to_string()
        }

        fn get_all_requirements(&self) -> Result<Vec<BundleRequirement>, GhidraBundleException> {
            Ok(Vec::new())
        }

        fn get_all_capabilities(&self) -> Result<Vec<BundleCapability>, GhidraBundleException> {
            Ok(Vec::new())
        }
    }

    /// A listener that only overrides `bundle_added`/`bundle_removed`, matching the common Java
    /// pattern of relying on the default `bundlesAdded`/`bundlesRemoved` loop.
    struct CountingListener {
        added: AtomicUsize,
        removed: AtomicUsize,
    }

    impl BundleHostListener for CountingListener {
        fn bundle_added(&self, _bundle: &dyn GhidraBundle) {
            self.added.fetch_add(1, Ordering::SeqCst);
        }

        fn bundle_removed(&self, _bundle: &dyn GhidraBundle) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn default_bundles_added_invokes_bundle_added_per_element() {
        let listener = CountingListener { added: AtomicUsize::new(0), removed: AtomicUsize::new(0) };
        let a = MockBundle::new();
        let b = MockBundle::new();
        let c = MockBundle::new();
        let bundles: [&dyn GhidraBundle; 3] = [&a, &b, &c];

        listener.bundles_added(&bundles);

        assert_eq!(listener.added.load(Ordering::SeqCst), 3);
        assert_eq!(listener.removed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn default_bundles_removed_invokes_bundle_removed_per_element() {
        let listener = CountingListener { added: AtomicUsize::new(0), removed: AtomicUsize::new(0) };
        let a = MockBundle::new();
        let b = MockBundle::new();
        let bundles: [&dyn GhidraBundle; 2] = [&a, &b];

        listener.bundles_removed(&bundles);

        assert_eq!(listener.removed.load(Ordering::SeqCst), 2);
        assert_eq!(listener.added.load(Ordering::SeqCst), 0);
    }

    /// A listener that overrides nothing, mirroring an implementor that only cares about one
    /// event Java doesn't have a default no-op body issue for -- every method here must still be
    /// callable with no observable effect.
    struct SilentListener;
    impl BundleHostListener for SilentListener {}

    #[test]
    fn unoverridden_methods_are_no_ops() {
        let listener = SilentListener;
        let bundle = MockBundle::new();
        listener.bundle_built(&bundle, Some("summary"));
        listener.bundle_built(&bundle, None);
        listener.bundle_enablement_change(&bundle, true);
        listener.bundle_activation_change(&bundle, false);
        listener.bundle_added(&bundle);
        listener.bundle_removed(&bundle);
        listener.bundle_exception(&GhidraBundleException::with_location("file:/bundle.jar", "boom"));

        let listener: Box<dyn BundleHostListener> = Box::new(SilentListener);
        listener.bundles_added(&[&bundle]);
        listener.bundles_removed(&[&bundle]);
    }
}
