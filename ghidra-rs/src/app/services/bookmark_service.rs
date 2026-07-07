/// The BookmarkService manages bookmark visibility and lifecycle within Ghidra.
///
/// This trait defines the interface for controlling bookmark visibility in the UI.
pub trait BookmarkService {
    /// Sets whether bookmarks should be visible in the UI.
    ///
    /// # Arguments
    ///
    /// * `visible` - If true, bookmarks will be displayed; if false, they will be hidden.
    fn set_bookmarks_visible(&mut self, visible: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple test implementation of BookmarkService for unit testing.
    struct TestBookmarkService {
        visible: bool,
    }

    impl TestBookmarkService {
        fn new() -> Self {
            TestBookmarkService { visible: false }
        }

        fn is_visible(&self) -> bool {
            self.visible
        }
    }

    impl BookmarkService for TestBookmarkService {
        fn set_bookmarks_visible(&mut self, visible: bool) {
            self.visible = visible;
        }
    }

    #[test]
    fn test_set_bookmarks_visible_true() {
        let mut service = TestBookmarkService::new();
        assert!(!service.is_visible());
        service.set_bookmarks_visible(true);
        assert!(service.is_visible());
    }

    #[test]
    fn test_set_bookmarks_visible_false() {
        let mut service = TestBookmarkService::new();
        service.set_bookmarks_visible(true);
        assert!(service.is_visible());
        service.set_bookmarks_visible(false);
        assert!(!service.is_visible());
    }

    #[test]
    fn test_set_bookmarks_visible_multiple_toggles() {
        let mut service = TestBookmarkService::new();
        service.set_bookmarks_visible(true);
        service.set_bookmarks_visible(false);
        service.set_bookmarks_visible(true);
        service.set_bookmarks_visible(false);
        assert!(!service.is_visible());
    }
}
