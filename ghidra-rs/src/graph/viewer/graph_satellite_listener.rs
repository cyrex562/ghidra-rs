/// Listener for notifications about changes to a satellite graph viewer.
///
/// Mirrors `ghidra.graph.viewer.GraphSatelliteListener`.
pub trait GraphSatelliteListener {
    /// Called when the visibility and/or docked state of the watched satellite changes.
    ///
    /// # Arguments
    /// * `docked` - true if the satellite is now docked
    /// * `visible` - true if the satellite is now visible
    fn satellite_visibility_changed(&mut self, docked: bool, visible: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListener {
        last_docked: Option<bool>,
        last_visible: Option<bool>,
    }

    impl GraphSatelliteListener for MockListener {
        fn satellite_visibility_changed(&mut self, docked: bool, visible: bool) {
            self.last_docked = Some(docked);
            self.last_visible = Some(visible);
        }
    }

    #[test]
    fn test_docked_visible() {
        let mut l = MockListener {
            last_docked: None,
            last_visible: None,
        };
        l.satellite_visibility_changed(true, true);
        assert_eq!(l.last_docked, Some(true));
        assert_eq!(l.last_visible, Some(true));
    }

    #[test]
    fn test_docked_invisible() {
        let mut l = MockListener {
            last_docked: None,
            last_visible: None,
        };
        l.satellite_visibility_changed(true, false);
        assert_eq!(l.last_docked, Some(true));
        assert_eq!(l.last_visible, Some(false));
    }

    #[test]
    fn test_undocked_visible() {
        let mut l = MockListener {
            last_docked: None,
            last_visible: None,
        };
        l.satellite_visibility_changed(false, true);
        assert_eq!(l.last_docked, Some(false));
        assert_eq!(l.last_visible, Some(true));
    }

    #[test]
    fn test_undocked_invisible() {
        let mut l = MockListener {
            last_docked: None,
            last_visible: None,
        };
        l.satellite_visibility_changed(false, false);
        assert_eq!(l.last_docked, Some(false));
        assert_eq!(l.last_visible, Some(false));
    }
}
