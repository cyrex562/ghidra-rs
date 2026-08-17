use crate::app::seam_stubs::GhidraBundle;

use super::GhidraBundleException;

/// Listener for OSGi framework events.
///
/// Port of `ghidra.app.plugin.core.osgi.BundleHostListener`. Every method has a Java `default`
/// body, so every method here has a default too -- implementors override only the events they
/// care about.
pub trait BundleHostListener: Send + Sync {
    /// Invoked when a bundle is built.
    ///
    /// `summary` is `None` if nothing changed (build returned false).
    fn bundle_built(&self, bundle: &GhidraBundle, summary: Option<&str>) {
        let _ = (bundle, summary);
    }

    /// Invoked when a bundle is enabled or disabled.
    fn bundle_enablement_change(&self, bundle: &GhidraBundle, new_enablement: bool) {
        let _ = (bundle, new_enablement);
    }

    /// Invoked when a bundle is activated or deactivated.
    fn bundle_activation_change(&self, bundle: &GhidraBundle, new_activation: bool) {
        let _ = (bundle, new_activation);
    }

    /// Invoked when a bundle is added to `BundleHost`.
    fn bundle_added(&self, bundle: &GhidraBundle) {
        let _ = bundle;
    }

    /// Invoked when a number of bundles is added at once. A listener should override this
    /// method to avoid repeated invocation of [`bundle_added`](Self::bundle_added) in quick
    /// succession.
    fn bundles_added(&self, bundles: &[GhidraBundle]) {
        for bundle in bundles {
            self.bundle_added(bundle);
        }
    }

    /// Invoked when a bundle is removed from `BundleHost`.
    fn bundle_removed(&self, bundle: &GhidraBundle) {
        let _ = bundle;
    }

    /// Invoked when a number of bundles is removed at once. A listener should override this
    /// method to avoid repeated invocation of [`bundle_removed`](Self::bundle_removed) in quick
    /// succession.
    fn bundles_removed(&self, bundles: &[GhidraBundle]) {
        for bundle in bundles {
            self.bundle_removed(bundle);
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A listener that only overrides `bundle_added`/`bundle_removed`, matching the common Java
    /// pattern of relying on the default `bundlesAdded`/`bundlesRemoved` loop.
    struct CountingListener {
        added: AtomicUsize,
        removed: AtomicUsize,
    }

    impl BundleHostListener for CountingListener {
        fn bundle_added(&self, _bundle: &GhidraBundle) {
            self.added.fetch_add(1, Ordering::SeqCst);
        }

        fn bundle_removed(&self, _bundle: &GhidraBundle) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn default_bundles_added_invokes_bundle_added_per_element() {
        let listener = CountingListener { added: AtomicUsize::new(0), removed: AtomicUsize::new(0) };
        let bundles = [GhidraBundle, GhidraBundle, GhidraBundle];

        listener.bundles_added(&bundles);

        assert_eq!(listener.added.load(Ordering::SeqCst), 3);
        assert_eq!(listener.removed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn default_bundles_removed_invokes_bundle_removed_per_element() {
        let listener = CountingListener { added: AtomicUsize::new(0), removed: AtomicUsize::new(0) };
        let bundles = [GhidraBundle, GhidraBundle];

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
        listener.bundle_built(&GhidraBundle, Some("summary"));
        listener.bundle_built(&GhidraBundle, None);
        listener.bundle_enablement_change(&GhidraBundle, true);
        listener.bundle_activation_change(&GhidraBundle, false);
        listener.bundle_added(&GhidraBundle);
        listener.bundle_removed(&GhidraBundle);
        listener.bundle_exception(&GhidraBundleException::with_location("file:/bundle.jar", "boom"));

        let listener: Box<dyn BundleHostListener> = Box::new(SilentListener);
        listener.bundles_added(&[GhidraBundle]);
        listener.bundles_removed(&[GhidraBundle]);
    }
}
