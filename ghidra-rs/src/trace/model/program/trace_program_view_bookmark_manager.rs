use crate::program::model::listing::BookmarkManager;
use crate::trace::model::program::snap_specific_trace_view::SnapSpecificTraceView;
use crate::trace::model::program::trace_program_view::TraceProgramView;

/// A [`BookmarkManager`] as seen through a [`TraceProgramView`], specific to a snapshot.
///
/// Port of `ghidra.trace.model.program.TraceProgramViewBookmarkManager`.
///
/// The Java interface overrides `BookmarkManager::getProgram()` to covariantly narrow its return
/// type to `TraceProgramView`. Rust does not support covariant trait-method overrides, so --
/// following the same convention already established by
/// [`TraceProgramView`](crate::trace::model::program::trace_program_view::TraceProgramView) for
/// its own covariant override of `Program::getMemory()` -- that override is exposed here under a
/// distinct name, [`TraceProgramViewBookmarkManager::get_trace_program_view`], rather than
/// redeclaring [`BookmarkManager::get_program`]. Implementors should still implement
/// `BookmarkManager::get_program` (delegating to `get_trace_program_view`), mirroring the Java
/// override.
pub trait TraceProgramViewBookmarkManager: BookmarkManager + SnapSpecificTraceView {
    /// Returns the trace program view that owns this bookmark manager.
    ///
    /// This is the covariant override of `BookmarkManager::getProgram()` in the Java source; see
    /// the trait-level documentation for why it is exposed under a distinct name here.
    fn get_trace_program_view(&self) -> Box<dyn TraceProgramView>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView};
    use crate::program::model::data::playable::Icon;
    use crate::program::model::listing::bookmark_type::MarkerColor;
    use crate::program::model::listing::{Bookmark, BookmarkType, Program};
    use crate::trace::model::trace::Trace;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    struct MockTraceProgramView;

    impl crate::framework::model::DomainObject for MockTraceProgramView {}
    impl Program for MockTraceProgramView {
        fn get_name(&self) -> String {
            "mock-view".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }
    impl TraceProgramView for MockTraceProgramView {
        fn get_trace_program_view_memory(
            &self,
        ) -> Box<dyn crate::trace::model::program::TraceProgramViewMemory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_snap(&self) -> i64 {
            0
        }
        fn get_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_snap(&self) -> Option<i64> {
            None
        }
    }

    /// Minimal implementor proving `TraceProgramViewBookmarkManager` is object-safe and that its
    /// covariant `get_trace_program_view` override coexists with `BookmarkManager::get_program`.
    struct MockBookmarkManager {
        snap: i64,
    }

    impl BookmarkManager for MockBookmarkManager {
        fn define_type(
            &mut self,
            _type_name: &str,
            _icon: Box<dyn Icon>,
            _color: MarkerColor,
            _priority: i32,
        ) -> Arc<dyn BookmarkType> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_types(&self) -> Vec<Arc<dyn BookmarkType>> {
            Vec::new()
        }
        fn get_bookmark_type(&self, _type_name: &str) -> Option<Arc<dyn BookmarkType>> {
            None
        }
        fn get_categories(&self, _type_name: &str) -> Vec<String> {
            Vec::new()
        }
        fn set_bookmark(
            &mut self,
            _addr: Address,
            _type_name: &str,
            _category: &str,
            _comment: &str,
        ) -> Arc<dyn Bookmark> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark(&self, _addr: Address, _type_name: &str, _category: &str) -> Option<Arc<dyn Bookmark>> {
            None
        }
        fn remove_bookmark(&mut self, _bookmark: &dyn Bookmark) {}
        fn remove_bookmarks_of_type(&mut self, _type_name: &str) {}
        fn remove_bookmarks_of_type_and_category(
            &mut self,
            _type_name: &str,
            _category: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn remove_bookmarks_in_set(
            &mut self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn remove_bookmarks_in_set_of_type(
            &mut self,
            _set: &dyn AddressSetView,
            _type_name: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn remove_bookmarks_in_set_of_type_and_category(
            &mut self,
            _set: &dyn AddressSetView,
            _type_name: &str,
            _category: &str,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn get_bookmarks_at_of_type(&self, _address: Address, _type_name: &str) -> Vec<Arc<dyn Bookmark>> {
            Vec::new()
        }
        fn get_bookmarks_at(&self, _addr: Address) -> Vec<Arc<dyn Bookmark>> {
            Vec::new()
        }
        fn get_bookmark_addresses(&self, _type_name: &str) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmarks_iterator_of_type(
            &self,
            _type_name: &str,
        ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            Box::new(std::iter::empty())
        }
        fn get_bookmarks_iterator(&self) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            Box::new(std::iter::empty())
        }
        fn get_bookmarks_iterator_from(
            &self,
            _start_address: Address,
            _forward: bool,
        ) -> Box<dyn Iterator<Item = Arc<dyn Bookmark>> + '_> {
            Box::new(std::iter::empty())
        }
        fn get_bookmark_by_id(&self, _id: i64) -> Option<Arc<dyn Bookmark>> {
            None
        }
        fn has_bookmarks(&self, _type_name: &str) -> bool {
            false
        }
        fn get_bookmark_count_of_type(&self, _type_name: &str) -> usize {
            0
        }
        fn get_bookmark_count(&self) -> usize {
            0
        }
        fn get_program(&self) -> Arc<dyn Program> {
            // Mirrors the Java override delegating to the covariant accessor.
            Arc::new(MockTraceProgramView)
        }
    }

    impl SnapSpecificTraceView for MockBookmarkManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    impl TraceProgramViewBookmarkManager for MockBookmarkManager {
        fn get_trace_program_view(&self) -> Box<dyn TraceProgramView> {
            Box::new(MockTraceProgramView)
        }
    }

    #[test]
    fn get_snap_reflects_snap_specific_trace_view() {
        let manager = MockBookmarkManager { snap: 7 };
        assert_eq!(manager.get_snap(), 7);
    }

    #[test]
    fn get_trace_program_view_returns_covariant_program() {
        let manager = MockBookmarkManager { snap: 0 };
        let view = manager.get_trace_program_view();
        assert_eq!(Program::get_name(view.as_ref()), "mock-view");
    }

    #[test]
    fn get_program_still_reachable_via_bookmark_manager_supertrait() {
        let manager = MockBookmarkManager { snap: 0 };
        let program = BookmarkManager::get_program(&manager);
        assert_eq!(Program::get_name(program.as_ref()), "mock-view");
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let manager: Box<dyn TraceProgramViewBookmarkManager> = Box::new(MockBookmarkManager { snap: 3 });
        assert_eq!(manager.get_snap(), 3);
        assert_eq!(Program::get_name(manager.get_trace_program_view().as_ref()), "mock-view");
    }
}
