//! Operations for managing bookmarks within a trace.
//!
//! Java source: `ghidra.trace.model.bookmark.TraceBookmarkOperations`.
//!
//! Adaptations from a literal translation:
//!
//! - Java `Collection<? extends TraceBookmark>` / `Iterable<? extends TraceBookmark>` become
//!   `Vec<Box<dyn TraceBookmark>>`, following the convention established by other operation traits
//!   like [`TraceMemoryOperations`](crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations).
//! - Java `Set<String>` becomes `HashSet<String>`.

use std::collections::HashSet;

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::bookmark::trace_bookmark::TraceBookmark;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::TraceBookmarkType;

/// Operations for managing bookmarks within a trace.
///
/// Port of `ghidra.trace.model.bookmark.TraceBookmarkOperations`. See the module documentation
/// for the collection-naming and return-type deviations from a literal translation.
pub trait TraceBookmarkOperations: Send + Sync {
    /// Get all the categories used for a given type.
    ///
    /// Mirrors `getCategoriesForType(TraceBookmarkType)`.
    fn get_categories_for_type(&self, type_: &dyn TraceBookmarkType) -> HashSet<String>;

    /// Add a bookmark at the given location.
    ///
    /// The category need not be created explicitly beforehand. It will be created implicitly if it
    /// does not already exist.
    ///
    /// Mirrors `addBookmark(Lifespan, Address, TraceBookmarkType, String, String)`.
    fn add_bookmark(
        &mut self,
        lifespan: Lifespan,
        address: Address,
        type_: &dyn TraceBookmarkType,
        category: &str,
        comment: &str,
    ) -> Box<dyn TraceBookmark>;

    /// Get all bookmarks in this trace.
    ///
    /// Mirrors `getAllBookmarks()`.
    fn get_all_bookmarks(&self) -> Vec<Box<dyn TraceBookmark>>;

    /// Get all bookmarks at the given snap and address.
    ///
    /// Mirrors `getBookmarksAt(long, Address)`.
    fn get_bookmarks_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceBookmark>>;

    /// Get all bookmarks enclosed within the given lifespan and address range.
    ///
    /// Mirrors `getBookmarksEnclosed(Lifespan, AddressRange)`.
    fn get_bookmarks_enclosed(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceBookmark>>;

    /// Get all bookmarks intersecting the given lifespan and address range.
    ///
    /// Mirrors `getBookmarksIntersecting(Lifespan, AddressRange)`.
    fn get_bookmarks_intersecting(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceBookmark>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};

    struct MockTraceBookmarkType;
    impl TraceBookmarkType for MockTraceBookmarkType {}

    struct MockTraceBookmark {
        id: i64,
        address: Address,
        lifespan: Lifespan,
    }

    impl TraceBookmark for MockTraceBookmark {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
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
            self.id
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

    struct MockBookmarkData {
        id: i64,
        address: Address,
        lifespan: Lifespan,
    }

    struct MockTraceBookmarkOperations {
        bookmarks: Vec<MockBookmarkData>,
    }

    impl TraceBookmarkOperations for MockTraceBookmarkOperations {
        fn get_categories_for_type(&self, _type_: &dyn TraceBookmarkType) -> HashSet<String> {
            HashSet::new()
        }

        fn add_bookmark(
            &mut self,
            lifespan: Lifespan,
            address: Address,
            _type_: &dyn TraceBookmarkType,
            _category: &str,
            _comment: &str,
        ) -> Box<dyn TraceBookmark> {
            let id = self.bookmarks.len() as i64;
            self.bookmarks.push(MockBookmarkData {
                id,
                address: address.clone(),
                lifespan,
            });
            Box::new(MockTraceBookmark {
                id,
                address,
                lifespan,
            })
        }

        fn get_all_bookmarks(&self) -> Vec<Box<dyn TraceBookmark>> {
            self.bookmarks
                .iter()
                .map(|b| {
                    Box::new(MockTraceBookmark {
                        id: b.id,
                        address: b.address.clone(),
                        lifespan: b.lifespan,
                    }) as Box<dyn TraceBookmark>
                })
                .collect()
        }

        fn get_bookmarks_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceBookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| b.address == *address && b.lifespan.contains(snap))
                .map(|b| {
                    Box::new(MockTraceBookmark {
                        id: b.id,
                        address: b.address.clone(),
                        lifespan: b.lifespan,
                    }) as Box<dyn TraceBookmark>
                })
                .collect()
        }

        fn get_bookmarks_enclosed(
            &self,
            lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceBookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| {
                    range.contains(&b.address)
                        && b.lifespan.min_snap().map_or(false, |min| min >= lifespan.min_snap().unwrap_or(i64::MIN))
                        && b.lifespan.max_snap().map_or(false, |max| max <= lifespan.max_snap().unwrap_or(i64::MAX))
                })
                .map(|b| {
                    Box::new(MockTraceBookmark {
                        id: b.id,
                        address: b.address.clone(),
                        lifespan: b.lifespan,
                    }) as Box<dyn TraceBookmark>
                })
                .collect()
        }

        fn get_bookmarks_intersecting(
            &self,
            lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceBookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| {
                    range.contains(&b.address)
                        && b.lifespan.min_snap()
                            .zip(lifespan.max_snap())
                            .map_or(false, |(b_min, l_max)| b_min <= l_max)
                        && b.lifespan.max_snap()
                            .zip(lifespan.min_snap())
                            .map_or(false, |(b_max, l_min)| b_max >= l_min)
                })
                .map(|b| {
                    Box::new(MockTraceBookmark {
                        id: b.id,
                        address: b.address.clone(),
                        lifespan: b.lifespan,
                    }) as Box<dyn TraceBookmark>
                })
                .collect()
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn add_bookmark_returns_bookmark() {
        let mut ops = MockTraceBookmarkOperations {
            bookmarks: Vec::new(),
        };
        let addr = test_address(0x1000);
        let type_ = MockTraceBookmarkType;
        let bookmark = ops.add_bookmark(Lifespan::span(0, 10), addr.clone(), &type_, "test", "comment");
        assert_eq!(bookmark.get_address(), addr);
        assert_eq!(bookmark.get_lifespan(), Lifespan::span(0, 10));
    }

    #[test]
    fn get_all_bookmarks_returns_all() {
        let mut ops = MockTraceBookmarkOperations {
            bookmarks: Vec::new(),
        };
        let addr = test_address(0x1000);
        let type_ = MockTraceBookmarkType;
        ops.add_bookmark(Lifespan::span(0, 10), addr.clone(), &type_, "test", "comment");
        let bookmarks = ops.get_all_bookmarks();
        assert_eq!(bookmarks.len(), 1);
    }

    #[test]
    fn get_bookmarks_at_filters_by_snap_and_address() {
        let mut ops = MockTraceBookmarkOperations {
            bookmarks: Vec::new(),
        };
        let addr1 = test_address(0x1000);
        let addr2 = test_address(0x2000);
        let type_ = MockTraceBookmarkType;
        ops.add_bookmark(Lifespan::span(0, 10), addr1.clone(), &type_, "test", "comment");
        ops.add_bookmark(Lifespan::span(5, 15), addr2.clone(), &type_, "test", "comment");

        let at_snap_5_addr1 = ops.get_bookmarks_at(5, &addr1);
        assert_eq!(at_snap_5_addr1.len(), 1);

        let at_snap_5_addr2 = ops.get_bookmarks_at(5, &addr2);
        assert_eq!(at_snap_5_addr2.len(), 1);

        let at_snap_15_addr1 = ops.get_bookmarks_at(15, &addr1);
        assert_eq!(at_snap_15_addr1.len(), 0);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let ops: Box<dyn TraceBookmarkOperations> = Box::new(MockTraceBookmarkOperations {
            bookmarks: Vec::new(),
        });
        let _ = ops.get_all_bookmarks();
    }
}
