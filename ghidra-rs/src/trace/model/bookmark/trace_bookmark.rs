//! A bookmark within a trace.
//!
//! Java source: `ghidra.trace.model.bookmark.TraceBookmark`.
use crate::app::seam_stubs::TraceThread;
use crate::program::model::listing::bookmark::Bookmark;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceBookmarkType;

/// A bookmark that additionally carries a lifespan (the range of snapshots over which it
/// applies) and belongs to a specific [`Trace`].
///
/// Port of `ghidra.trace.model.bookmark.TraceBookmark`.
///
/// The Java interface overrides `Bookmark::getType()` to covariantly narrow its return type to
/// `TraceBookmarkType`. Rust does not support covariant trait-method overrides, so that override
/// is exposed here under a distinct name, [`TraceBookmark::get_trace_bookmark_type`], rather than
/// redeclaring [`Bookmark::get_type`]. Implementors should still implement
/// [`Bookmark::get_type`] (delegating to `get_trace_bookmark_type`, mirroring the Java override).
pub trait TraceBookmark: Bookmark {
    /// Returns the trace this bookmark belongs to.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// If this bookmark is in a register space, identifies the containing thread.
    ///
    /// Returns `None` if this bookmark is not in register space.
    fn get_thread(&self) -> Option<Box<dyn TraceThread>>;

    /// Sets the lifespan (range of snapshots) over which this bookmark applies.
    fn set_lifespan(&mut self, lifespan: Box<dyn Lifespan>);

    /// Returns the lifespan (range of snapshots) over which this bookmark applies.
    fn get_lifespan(&self) -> Box<dyn Lifespan>;

    /// Returns the type of this bookmark, narrowed to a [`TraceBookmarkType`].
    ///
    /// This is the covariant override of `Bookmark::getType()` in the Java source; see the
    /// trait-level documentation for why it is exposed under a distinct name here.
    fn get_trace_bookmark_type(&self) -> Box<dyn TraceBookmarkType>;

    /// Deletes this bookmark.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::listing::bookmark_type::{BookmarkType, MarkerColor};
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceBreakpointManager, TraceEquateManager, TraceMemoryManager,
        TraceModuleManager, TraceObjectManager, TracePlatformManager,
        TraceReferenceManager, TraceRegisterContextManager, TraceStackManager,
        TraceStaticMappingManager, TraceSymbolManager, TraceThreadManager,
        TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};
    use std::cmp::Ordering;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.min,
                max,
            })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    struct MockLock;
    impl Lock for MockLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockTrace {
        lock: MockLock,
    }

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            Vec::new()
        }

        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }
    }

    struct MockThread;
    impl TraceThread for MockThread {}

    struct MockBookmarkType;
    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            "Mock"
        }

        fn get_icon(&self) -> Option<Box<dyn crate::program::model::data::playable::Icon>> {
            None
        }

        fn get_marker_color(&self) -> Option<MarkerColor> {
            None
        }

        fn get_marker_priority(&self) -> i32 {
            -1
        }

        fn has_bookmarks(&self) -> bool {
            false
        }

        fn get_type_id(&self) -> i32 {
            0
        }
    }

    struct MockTraceBookmarkType;
    impl TraceBookmarkType for MockTraceBookmarkType {}

    struct MockTraceBookmark {
        id: i64,
        address: Address,
        category: String,
        comment: String,
        lifespan: MockLifespan,
        thread: Option<()>,
        deleted: bool,
    }

    impl Bookmark for MockTraceBookmark {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_type(&self) -> &dyn BookmarkType {
            &MockBookmarkType
        }

        fn get_type_string(&self) -> &str {
            "Mock"
        }

        fn get_category(&self) -> &str {
            &self.category
        }

        fn get_comment(&self) -> &str {
            &self.comment
        }

        fn set(&mut self, category: &str, comment: &str) {
            self.category = category.to_string();
            self.comment = comment.to_string();
        }

        fn compare_to(&self, other: &dyn Bookmark) -> Ordering {
            self.get_address()
                .offset()
                .cmp(&other.get_address().offset())
        }
    }

    impl TraceBookmark for MockTraceBookmark {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace { lock: MockLock })
        }

        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            self.thread.map(|_| Box::new(MockThread) as Box<dyn TraceThread>)
        }

        fn set_lifespan(&mut self, lifespan: Box<dyn Lifespan>) {
            self.lifespan = MockLifespan {
                min: lifespan.lmin(),
                max: lifespan.lmax(),
            };
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.lifespan.min,
                max: self.lifespan.max,
            })
        }

        fn get_trace_bookmark_type(&self) -> Box<dyn TraceBookmarkType> {
            Box::new(MockTraceBookmarkType)
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn make_bookmark() -> MockTraceBookmark {
        MockTraceBookmark {
            id: 1,
            address: test_address(0x1000),
            category: String::new(),
            comment: String::new(),
            lifespan: MockLifespan { min: 0, max: 10 },
            thread: None,
            deleted: false,
        }
    }

    #[test]
    fn set_lifespan_updates_bounds() {
        let mut bookmark = make_bookmark();
        bookmark.set_lifespan(Box::new(MockLifespan { min: 5, max: 20 }));
        let span = bookmark.get_lifespan();
        assert_eq!(span.lmin(), 5);
        assert_eq!(span.lmax(), 20);
    }

    #[test]
    fn get_thread_is_none_when_not_in_register_space() {
        let bookmark = make_bookmark();
        assert!(bookmark.get_thread().is_none());
    }

    #[test]
    fn delete_marks_bookmark_deleted() {
        let mut bookmark = make_bookmark();
        assert!(!bookmark.deleted);
        bookmark.delete();
        assert!(bookmark.deleted);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut bookmark: Box<dyn TraceBookmark> = Box::new(make_bookmark());
        assert_eq!(bookmark.get_id(), 1);
        let _ = bookmark.get_trace_bookmark_type();
        let _ = bookmark.get_trace();
        bookmark.delete();
    }
}
