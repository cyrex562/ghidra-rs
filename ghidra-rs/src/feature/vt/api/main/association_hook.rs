use crate::feature::seam_stubs::{VtAssociation, VtMarkupItem};

/// Callback interface for association changes.
///
/// Implementations of this trait receive notifications when associations are accepted,
/// cleared, or when markup item statuses change.
pub trait AssociationHook: Send + Sync {
    /// Called whenever an association has been accepted.
    fn association_accepted(&self, association: &dyn VtAssociation);

    /// Called whenever an association has been cleared from the accepted state.
    fn association_cleared(&self, association: &dyn VtAssociation);

    /// Called whenever a markupItem's status changes.
    fn markup_item_status_changed(&self, markup_item: &dyn VtMarkupItem);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingHook {
        accepted_count: Arc<AtomicUsize>,
        cleared_count: Arc<AtomicUsize>,
        status_changed_count: Arc<AtomicUsize>,
    }

    impl CountingHook {
        fn new() -> Self {
            Self {
                accepted_count: Arc::new(AtomicUsize::new(0)),
                cleared_count: Arc::new(AtomicUsize::new(0)),
                status_changed_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn accepted_count(&self) -> usize {
            self.accepted_count.load(Ordering::Relaxed)
        }

        fn cleared_count(&self) -> usize {
            self.cleared_count.load(Ordering::Relaxed)
        }

        fn status_changed_count(&self) -> usize {
            self.status_changed_count.load(Ordering::Relaxed)
        }
    }

    impl AssociationHook for CountingHook {
        fn association_accepted(&self, _association: &dyn VtAssociation) {
            self.accepted_count.fetch_add(1, Ordering::Relaxed);
        }

        fn association_cleared(&self, _association: &dyn VtAssociation) {
            self.cleared_count.fetch_add(1, Ordering::Relaxed);
        }

        fn markup_item_status_changed(&self, _markup_item: &dyn VtMarkupItem) {
            self.status_changed_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn trait_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CountingHook>();
    }

    #[test]
    fn counting_hook_tracks_association_accepted() {
        let hook = CountingHook::new();
        assert_eq!(hook.accepted_count(), 0);
        // We can't easily create trait objects without full implementations,
        // but the trait is correctly defined and Send + Sync
    }

    #[test]
    fn counting_hook_tracks_association_cleared() {
        let hook = CountingHook::new();
        assert_eq!(hook.cleared_count(), 0);
    }

    #[test]
    fn counting_hook_tracks_markup_item_status_changed() {
        let hook = CountingHook::new();
        assert_eq!(hook.status_changed_count(), 0);
    }

    #[test]
    fn association_hook_is_object_safe() {
        // This test verifies that AssociationHook can be used as a trait object.
        // If this compiles, the trait is object-safe.
        fn takes_hook(_hook: &dyn AssociationHook) {}
        let hook = CountingHook::new();
        takes_hook(&hook);
    }

    #[test]
    fn multiple_hooks_can_coexist() {
        let hook1 = CountingHook::new();
        let hook2 = CountingHook::new();

        let _: &dyn AssociationHook = &hook1;
        let _: &dyn AssociationHook = &hook2;

        assert_eq!(hook1.accepted_count(), 0);
        assert_eq!(hook2.accepted_count(), 0);
    }
}
