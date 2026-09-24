//! Listener for changes reported by a program [`DiffController`].
//!
//! Maps to `ghidra.app.plugin.core.diff.DiffControllerListener`.

use crate::app::seam_stubs::DiffController;
use crate::program::model::address::Address;

/// Receives notifications when a [`DiffController`]'s current diff location or its set of
/// differences changes.
pub trait DiffControllerListener {
    /// Called when the diff controller's current location changes to `location`.
    fn diff_location_changed(&mut self, diff_control: &DiffController, location: &Address);

    /// Called when the set of differences computed by the diff controller changes.
    fn differences_changed(&mut self, diff_control: &DiffController);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[derive(Default)]
    struct RecordingListener {
        locations: Vec<i64>,
        differences_changed: usize,
    }

    impl DiffControllerListener for RecordingListener {
        fn diff_location_changed(&mut self, _diff_control: &DiffController, location: &Address) {
            self.locations.push(location.offset());
        }

        fn differences_changed(&mut self, _diff_control: &DiffController) {
            self.differences_changed += 1;
        }
    }

    #[test]
    fn notifications_reach_listener() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let controller = DiffController;
        let mut listener = RecordingListener::default();

        listener.diff_location_changed(&controller, &Address::new(space.clone(), 0x1000));
        listener.diff_location_changed(&controller, &Address::new(space, 0x2004));
        listener.differences_changed(&controller);

        assert_eq!(listener.locations, vec![0x1000, 0x2004]);
        assert_eq!(listener.differences_changed, 1);
    }

    #[test]
    fn dispatches_through_trait_object() {
        let controller = DiffController;
        let mut listeners: Vec<Box<dyn DiffControllerListener>> =
            vec![Box::new(RecordingListener::default())];
        for l in &mut listeners {
            l.differences_changed(&controller);
        }
    }
}
