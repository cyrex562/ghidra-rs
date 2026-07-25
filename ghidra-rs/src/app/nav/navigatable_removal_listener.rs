//! Port of `ghidra.app.nav.NavigatableRemovalListener`.
//!
//! `Navigatable` is not yet ported; it is represented by the placeholder trait in
//! [`crate::app::seam_stubs`] (added for
//! [`MemorySearchService`](crate::app::services::memory_search_service::MemorySearchService)).

use crate::app::seam_stubs::Navigatable;

/// Listener notified when a [`Navigatable`] is removed.
///
/// Port of `NavigatableRemovalListener`.
pub trait NavigatableRemovalListener {
    /// Called when the given navigatable has been removed.
    ///
    /// Port of `NavigatableRemovalListener.navigatableRemoved(Navigatable)`.
    fn navigatable_removed(&mut self, navigatable: &dyn Navigatable);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeNavigatable;
    impl Navigatable for FakeNavigatable {
        fn is_connected(&self) -> bool {
            false
        }
    }

    struct RecordingListener {
        removed_count: usize,
    }

    impl NavigatableRemovalListener for RecordingListener {
        fn navigatable_removed(&mut self, _navigatable: &dyn Navigatable) {
            self.removed_count += 1;
        }
    }

    #[test]
    fn listener_is_notified_on_removal() {
        let mut listener = RecordingListener { removed_count: 0 };
        let navigatable = FakeNavigatable;

        listener.navigatable_removed(&navigatable);
        listener.navigatable_removed(&navigatable);

        assert_eq!(listener.removed_count, 2);
    }
}
