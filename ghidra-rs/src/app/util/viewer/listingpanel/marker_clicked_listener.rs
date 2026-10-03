//! Listener interface for notifications when the user double-clicks in the marker margin.

use crate::app::seam_stubs::MarkerLocation;

/// Notified whenever the user double-clicks in the marker margin.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.MarkerClickedListener`.
pub trait MarkerClickedListener {
    /// Called when the user double-clicks in the marker margin.
    ///
    /// # Arguments
    ///
    /// * `location` - The location where the user double-clicked, containing program, address,
    ///   marker set, and pixel coordinates.
    fn marker_double_clicked(&mut self, location: &dyn MarkerLocation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::MarkerLocation;
    use std::any::Any;
    use std::sync::Arc;

    struct MockMarkerLocation {
        x: i32,
        y: i32,
    }

    impl MarkerLocation for MockMarkerLocation {
        fn get_program(&self) -> Box<dyn crate::program::model::listing::Program> {
            panic!("Not implemented for mock");
        }

        fn get_addr(&self) -> crate::program::model::address::Address {
            panic!("Not implemented for mock");
        }

        fn get_marker_set(&self) -> Box<dyn crate::app::seam_stubs::MarkerSet> {
            panic!("Not implemented for mock");
        }

        fn get_x(&self) -> i32 {
            self.x
        }

        fn get_y(&self) -> i32 {
            self.y
        }

        fn hash_code(&self) -> i32 {
            ((self.x as i64) * 31 + (self.y as i64)) as i32
        }

        fn equals(&self, obj: &dyn Any) -> bool {
            if let Some(other) = obj.downcast_ref::<MockMarkerLocation>() {
                self.x == other.x && self.y == other.y
            } else {
                false
            }
        }
    }

    struct RecordingListener {
        calls: Vec<(i32, i32)>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self { calls: Vec::new() }
        }
    }

    impl MarkerClickedListener for RecordingListener {
        fn marker_double_clicked(&mut self, location: &dyn MarkerLocation) {
            self.calls.push((location.get_x(), location.get_y()));
        }
    }

    #[test]
    fn test_marker_double_clicked_called() {
        let mut listener = RecordingListener::new();
        let location = MockMarkerLocation { x: 100, y: 200 };
        listener.marker_double_clicked(&location);
        assert_eq!(listener.calls.len(), 1);
        assert_eq!(listener.calls[0], (100, 200));
    }

    #[test]
    fn test_marker_double_clicked_multiple_calls() {
        let mut listener = RecordingListener::new();
        let location1 = MockMarkerLocation { x: 100, y: 200 };
        let location2 = MockMarkerLocation { x: 150, y: 250 };
        listener.marker_double_clicked(&location1);
        listener.marker_double_clicked(&location2);
        assert_eq!(listener.calls.len(), 2);
        assert_eq!(listener.calls[0], (100, 200));
        assert_eq!(listener.calls[1], (150, 250));
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn MarkerClickedListener> = Box::new(RecordingListener::new());
        let location = MockMarkerLocation { x: 50, y: 75 };
        listener.marker_double_clicked(&location);
    }

    #[test]
    fn test_marker_location_hash_and_equals() {
        let loc1 = MockMarkerLocation { x: 10, y: 20 };
        let loc2 = MockMarkerLocation { x: 10, y: 20 };
        let loc3 = MockMarkerLocation { x: 10, y: 30 };

        assert!(loc1.equals(&loc2 as &dyn Any));
        assert!(!loc1.equals(&loc3 as &dyn Any));
        assert_eq!(loc1.hash_code(), loc2.hash_code());
    }
}
