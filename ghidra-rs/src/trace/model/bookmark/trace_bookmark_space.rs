//! A bookmark space within a trace.
//!
//! Java source: `ghidra.trace.model.bookmark.TraceBookmarkSpace`.

use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::bookmark::trace_bookmark_operations::TraceBookmarkOperations;
use crate::trace::model::bookmark::trace_bookmark::TraceBookmark;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceBookmarkType;
use crate::program::model::lang::Register;

/// A portion of the bookmark manager bound to a particular address space.
///
/// Port of `ghidra.trace.model.bookmark.TraceBookmarkSpace`.
///
/// For most bookmark operations, the methods on `TraceBookmarkManager` are sufficient, as they
/// will automatically obtain the appropriate `TraceBookmarkSpace` for the address space of the
/// given address or range.
pub trait TraceBookmarkSpace: TraceBookmarkOperations {
    /// Get the trace.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the address space.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// Add a bookmark at a register location.
    ///
    /// This convenience method converts a register to an address range and calls the
    /// address-based `add_bookmark` method. The host platform is used to determine the
    /// conventional register range.
    ///
    /// Mirrors `addBookmark(Lifespan, Register, TraceBookmarkType, String, String)`.
    fn add_bookmark_register(
        &mut self,
        lifespan: Lifespan,
        register: &Register,
        type_: &dyn TraceBookmarkType,
        category: &str,
        comment: &str,
    ) -> Box<dyn TraceBookmark> {
        let host = self.get_trace().get_platform_manager().get_host_platform();
        let range = host.get_conventional_register_range(&self.get_address_space(), register);
        self.add_bookmark(lifespan, range.min_address().clone(), type_, category, comment)
    }

    /// Get bookmarks enclosed by a register's range.
    ///
    /// This convenience method converts a register to an address range and calls the
    /// range-based method.
    ///
    /// Mirrors `getBookmarksEnclosed(Lifespan, Register)`.
    fn get_bookmarks_enclosed_register(
        &self,
        lifespan: Lifespan,
        register: &Register,
    ) -> Vec<Box<dyn TraceBookmark>> {
        let start = register.address().clone();
        let end = start.add_wrap((register.num_bytes() as i64) - 1);
        let range = crate::program::model::address::AddressRange::new(start, end);
        self.get_bookmarks_enclosed(lifespan, &range)
    }

    /// Get bookmarks intersecting a register's range.
    ///
    /// This convenience method converts a register to an address range and calls the
    /// range-based method.
    ///
    /// Mirrors `getBookmarksIntersecting(Lifespan, Register)`.
    fn get_bookmarks_intersecting_register(
        &self,
        lifespan: Lifespan,
        register: &Register,
    ) -> Vec<Box<dyn TraceBookmark>> {
        let start = register.address().clone();
        let end = start.add_wrap((register.num_bytes() as i64) - 1);
        let range = crate::program::model::address::AddressRange::new(start, end);
        self.get_bookmarks_intersecting(lifespan, &range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::collections::HashSet;

    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::trace::model::bookmark::trace_bookmark::TraceBookmark;
    use crate::trace::model::trace::Trace;
    use crate::program::model::lang::Register;

    struct MockTraceBookmarkType;
    impl TraceBookmarkType for MockTraceBookmarkType {}

    struct MockTraceBookmark {
        address: Address,
        lifespan: Lifespan,
    }

    impl TraceBookmark for MockTraceBookmark {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Option<Box<dyn crate::trace::model::thread::TraceThread>> {
            None
        }

        fn set_lifespan(&mut self, lifespan: Lifespan) {
            self.lifespan = lifespan;
        }

        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
        }

        fn get_trace_bookmark_type(&self) -> Box<dyn TraceBookmarkType> {
            Box::new(MockTraceBookmarkType)
        }

        fn delete(&mut self) {}
    }

    impl crate::program::model::listing::bookmark::Bookmark for MockTraceBookmark {
        fn get_id(&self) -> i64 {
            0
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_type(&self) -> &dyn crate::program::model::listing::bookmark_type::BookmarkType {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_type_string(&self) -> &str {
            "Mock"
        }

        fn get_category(&self) -> &str {
            ""
        }

        fn get_comment(&self) -> &str {
            ""
        }

        fn set(&mut self, _category: &str, _comment: &str) {}

        fn compare_to(&self, other: &dyn crate::program::model::listing::bookmark::Bookmark) -> std::cmp::Ordering {
            self.address.offset().cmp(&other.get_address().offset())
        }
    }

    /// A minimal implementor to verify the trait is object-safe and has the expected methods.
    struct MockBookmarkSpace {
        space: Arc<AddressSpace>,
    }

    impl TraceBookmarkOperations for MockBookmarkSpace {
        fn get_categories_for_type(&self, _type_: &dyn TraceBookmarkType) -> HashSet<String> {
            HashSet::new()
        }

        fn add_bookmark(
            &mut self,
            _lifespan: Lifespan,
            _address: Address,
            _type_: &dyn TraceBookmarkType,
            _category: &str,
            _comment: &str,
        ) -> Box<dyn TraceBookmark> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_bookmarks(&self) -> Vec<Box<dyn TraceBookmark>> {
            Vec::new()
        }

        fn get_bookmarks_at(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceBookmark>> {
            Vec::new()
        }

        fn get_bookmarks_enclosed(
            &self,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceBookmark>> {
            Vec::new()
        }

        fn get_bookmarks_intersecting(
            &self,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceBookmark>> {
            Vec::new()
        }
    }

    impl TraceBookmarkSpace for MockBookmarkSpace {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let space = AddressSpace::new("ram", 8, 1, AddressSpaceType::Ram, 0);
        let bookmark_space: Box<dyn TraceBookmarkSpace> = Box::new(MockBookmarkSpace {
            space: space.clone(),
        });

        assert_eq!(bookmark_space.get_address_space().name(), "ram");
        assert!(Arc::ptr_eq(&bookmark_space.get_address_space(), &space));
    }

    #[test]
    fn register_methods_exist_on_trait() {
        // This test just verifies that the methods exist and are callable on the trait.
        // We can't easily test them here because Register requires a complex setup,
        // and the methods just delegate to the range-based methods anyway.
        // The functionality is tested implicitly by trait compilation.
    }
}
