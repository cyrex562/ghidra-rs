//! Service for tracking a set of published targets.
//!
//! Port of `ghidra.app.services.DebuggerTargetService`. Services capable of creating targets
//! should publish them using this service. The Java `@ServiceInfo` annotation (default provider
//! `DebuggerTargetServicePlugin`) has no Rust equivalent and is omitted.

use crate::app::seam_stubs::{Target, TargetPublicationListener};
use crate::trace::model::trace::Trace;

/// A service for tracking a set of published targets.
///
/// Port of `ghidra.app.services.DebuggerTargetService`.
pub trait DebuggerTargetService {
    /// Publish a target to the service and its listeners.
    fn publish_target(&mut self, target: Box<dyn Target>);

    /// Withdraw a target from the service and its listeners.
    fn withdraw_target(&mut self, target: &dyn Target);

    /// Get a list of all published targets, in no particular order.
    fn get_published_targets(&self) -> Vec<Box<dyn Target>>;

    /// Get the target for the given trace, or `None` if there is no such target.
    fn get_target(&self, trace: &dyn Trace) -> Option<Box<dyn Target>>;

    /// Add a listener for target publication and withdrawal events.
    fn add_target_publication_listener(&mut self, listener: Box<dyn TargetPublicationListener>);

    /// Remove a listener for target publication and withdrawal events.
    fn remove_target_publication_listener(&mut self, listener: &dyn TargetPublicationListener);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTarget;
    impl Target for MockTarget {}

    struct MockListener;
    impl TargetPublicationListener for MockListener {}

    struct MockDebuggerTargetService {
        targets: Vec<()>,
    }

    impl DebuggerTargetService for MockDebuggerTargetService {
        fn publish_target(&mut self, _target: Box<dyn Target>) {
            self.targets.push(());
        }

        fn withdraw_target(&mut self, _target: &dyn Target) {
            self.targets.pop();
        }

        fn get_published_targets(&self) -> Vec<Box<dyn Target>> {
            self.targets.iter().map(|_| Box::new(MockTarget) as Box<dyn Target>).collect()
        }

        fn get_target(&self, _trace: &dyn Trace) -> Option<Box<dyn Target>> {
            None
        }

        fn add_target_publication_listener(
            &mut self,
            _listener: Box<dyn TargetPublicationListener>,
        ) {
        }

        fn remove_target_publication_listener(&mut self, _listener: &dyn TargetPublicationListener) {}
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerTargetService> =
            Box::new(MockDebuggerTargetService { targets: Vec::new() });
        service.publish_target(Box::new(MockTarget));
        assert_eq!(service.get_published_targets().len(), 1);
    }
}
