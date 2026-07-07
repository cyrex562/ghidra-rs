/// Called when a path highlight changes in the visual graph.
pub trait PathHighlightListener {
    /// Called when the highlighted path changes.
    ///
    /// `hover_change` is `true` if the change was triggered by a hover action,
    /// or `false` if it was triggered by a selection change.
    fn path_highlight_changed(&mut self, hover_change: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListener {
        last_hover: Option<bool>,
    }

    impl PathHighlightListener for MockListener {
        fn path_highlight_changed(&mut self, hover_change: bool) {
            self.last_hover = Some(hover_change);
        }
    }

    #[test]
    fn test_hover_change() {
        let mut l = MockListener { last_hover: None };
        l.path_highlight_changed(true);
        assert_eq!(l.last_hover, Some(true));
    }

    #[test]
    fn test_selection_change() {
        let mut l = MockListener { last_hover: None };
        l.path_highlight_changed(false);
        assert_eq!(l.last_hover, Some(false));
    }

    #[test]
    fn test_trait_object() {
        let mut l: Box<dyn PathHighlightListener> = Box::new(MockListener { last_hover: None });
        l.path_highlight_changed(true);
    }
}
