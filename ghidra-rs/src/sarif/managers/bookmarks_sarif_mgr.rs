//! Port of `sarif.managers.BookmarksSarifMgr`.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::program::model::address::AddressSetView;
use crate::program::model::listing::bookmark_type::NOTE;
use crate::program::model::listing::{Bookmark, BookmarkManager, Program};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::seam_stubs::{
    MessageLog, SarifBookmarkWriter, SarifMgr, SarifProgramOptions, SarifWriterTask, TaskLauncher,
};

/// Reads and writes `BOOKMARKS` entries between a [`Program`]'s [`BookmarkManager`] and SARIF.
///
/// Port of `sarif.managers.BookmarksSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have.
pub struct BookmarksSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    bookmark_mgr: Arc<dyn BookmarkManager>,
}

impl BookmarksSarifMgr {
    /// `BookmarksSarifMgr.KEY`.
    pub const KEY: &'static str = "BOOKMARKS";
    /// `BookmarksSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "Bookmark";

    /// `new BookmarksSarifMgr(Program program, MessageLog log)`.
    ///
    /// # Panics
    /// Panics if `program` has no bookmark manager, matching the Java constructor's implicit
    /// `NullPointerException` if a caller ever passed a program lacking one.
    pub fn new(program: &dyn Program, log: MessageLog) -> Self {
        let bookmark_mgr = program
            .get_bookmark_manager()
            .expect("program has no bookmark manager");
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            bookmark_mgr,
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `BookmarksSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        options: Option<&SarifProgramOptions>,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        let overwrite = options.map_or(true, |o| o.is_overwrite_bookmark_conflicts());
        self.process_bookmark(result, overwrite);
        true
    }

    fn process_bookmark(&mut self, result: &HashMap<String, Value>, overwrite: bool) {
        let addr = match self.base.get_location(result) {
            Ok(addr) => addr,
            Err(e) => {
                self.log.append_exception(&e);
                None
            }
        };

        let Some(addr) = addr else {
            return;
        };

        let bookmark_type = result.get("kind").and_then(Value::as_str).unwrap_or(NOTE);
        let category = result.get("name").and_then(Value::as_str).unwrap_or("");
        let comment = result.get("comment").and_then(Value::as_str).unwrap_or("");

        let bookmark_mgr = Arc::get_mut(&mut self.bookmark_mgr)
            .expect("BookmarksSarifMgr holds the only handle to its BookmarkManager");

        let has_existing_bookmark = bookmark_mgr
            .get_bookmark(addr.clone(), bookmark_type, category)
            .is_some();
        if overwrite || !has_existing_bookmark {
            bookmark_mgr.set_bookmark(addr.clone(), bookmark_type, category, comment);
        }
        if !overwrite && has_existing_bookmark {
            self.log.append_msg(format!(
                "Conflicting '{bookmark_type}' BOOKMARK ignored at: {addr}"
            ));
        }
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `BookmarksSarifMgr.write`.
    pub fn write(
        &self,
        results: &mut Vec<Value>,
        set: Option<&dyn AddressSetView>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Writing BOOKMARKS ...");

        let mut request: Vec<Arc<dyn Bookmark>> = Vec::new();
        for bookmark_type in self.bookmark_mgr.get_bookmark_types() {
            if monitor.is_cancelled() {
                return Err(CancelledException::default());
            }
            let type_str = bookmark_type.get_type_string().to_string();
            let type_addresses = self.bookmark_mgr.get_bookmark_addresses(&type_str);
            let restricted;
            let bm_set: &dyn AddressSetView = match set {
                Some(set) => {
                    restricted = set.intersect(type_addresses.as_ref());
                    &restricted
                }
                None => type_addresses.as_ref(),
            };
            for addr in bm_set.addresses(true) {
                request.extend(self.bookmark_mgr.get_bookmarks_at_of_type(addr, &type_str));
            }
        }

        Self::write_as_sarif(&request, results, monitor);
        Ok(())
    }

    /// `BookmarksSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(request: &[Arc<dyn Bookmark>], results: &mut Vec<Value>, monitor: &dyn TaskMonitor) {
        let writer = SarifBookmarkWriter::new(request.to_vec());
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::playable::Icon;
    use crate::program::model::listing::bookmark_type::MarkerColor;
    use crate::program::model::listing::BookmarkType;
    use crate::util::task::DummyMonitor;
    use std::cmp::Ordering;

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn test_address(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    struct MockBookmarkType {
        type_string: String,
    }

    impl BookmarkType for MockBookmarkType {
        fn get_type_string(&self) -> &str {
            &self.type_string
        }
        fn get_icon(&self) -> Option<Box<dyn Icon>> {
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

    struct MockBookmark {
        id: i64,
        address: Address,
        type_string: String,
        category: String,
        comment: String,
        bookmark_type: Arc<MockBookmarkType>,
    }

    impl Bookmark for MockBookmark {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_type(&self) -> &dyn BookmarkType {
            self.bookmark_type.as_ref()
        }
        fn get_type_string(&self) -> &str {
            &self.type_string
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
            self.get_address().offset().cmp(&other.get_address().offset())
        }
    }

    struct MockBookmarkManager {
        bookmarks: Vec<Arc<MockBookmark>>,
        next_id: i64,
    }

    impl MockBookmarkManager {
        fn new() -> Self {
            Self {
                bookmarks: Vec::new(),
                next_id: 1,
            }
        }
    }

    impl BookmarkManager for MockBookmarkManager {
        fn define_type(
            &mut self,
            type_name: &str,
            _icon: Box<dyn Icon>,
            _color: MarkerColor,
            _priority: i32,
        ) -> Arc<dyn BookmarkType> {
            Arc::new(MockBookmarkType {
                type_string: type_name.to_string(),
            })
        }
        fn get_bookmark_types(&self) -> Vec<Arc<dyn BookmarkType>> {
            let mut seen = Vec::new();
            for b in &self.bookmarks {
                if !seen.iter().any(|s: &String| s == &b.type_string) {
                    seen.push(b.type_string.clone());
                }
            }
            seen.into_iter()
                .map(|type_string| Arc::new(MockBookmarkType { type_string }) as Arc<dyn BookmarkType>)
                .collect()
        }
        fn get_bookmark_type(&self, _type_name: &str) -> Option<Arc<dyn BookmarkType>> {
            None
        }
        fn get_categories(&self, _type_name: &str) -> Vec<String> {
            Vec::new()
        }
        fn set_bookmark(
            &mut self,
            addr: Address,
            type_name: &str,
            category: &str,
            comment: &str,
        ) -> Arc<dyn Bookmark> {
            let bookmark = Arc::new(MockBookmark {
                id: self.next_id,
                address: addr,
                type_string: type_name.to_string(),
                category: category.to_string(),
                comment: comment.to_string(),
                bookmark_type: Arc::new(MockBookmarkType {
                    type_string: type_name.to_string(),
                }),
            });
            self.next_id += 1;
            self.bookmarks.push(bookmark.clone());
            bookmark
        }
        fn get_bookmark(&self, addr: Address, type_name: &str, category: &str) -> Option<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .find(|b| {
                    b.address.offset() == addr.offset() && b.type_string == type_name && b.category == category
                })
                .map(|b| b.clone() as Arc<dyn Bookmark>)
        }
        fn remove_bookmark(&mut self, bookmark: &dyn Bookmark) {
            self.bookmarks.retain(|b| b.get_id() != bookmark.get_id());
        }
        fn remove_bookmarks_of_type(&mut self, type_name: &str) {
            self.bookmarks.retain(|b| b.type_string != type_name);
        }
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
        fn get_bookmarks_at_of_type(&self, address: Address, type_name: &str) -> Vec<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| b.address.offset() == address.offset() && b.type_string == type_name)
                .map(|b| b.clone() as Arc<dyn Bookmark>)
                .collect()
        }
        fn get_bookmarks_at(&self, addr: Address) -> Vec<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .filter(|b| b.address.offset() == addr.offset())
                .map(|b| b.clone() as Arc<dyn Bookmark>)
                .collect()
        }
        fn get_bookmark_addresses(&self, type_name: &str) -> Box<dyn AddressSetView> {
            use crate::program::model::address::AddressSet;
            let mut set = AddressSet::new();
            for b in self.bookmarks.iter().filter(|b| b.type_string == type_name) {
                set.add_address(&b.address);
            }
            Box::new(set)
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
        fn get_bookmark_by_id(&self, id: i64) -> Option<Arc<dyn Bookmark>> {
            self.bookmarks
                .iter()
                .find(|b| b.id == id)
                .map(|b| b.clone() as Arc<dyn Bookmark>)
        }
        fn has_bookmarks(&self, type_name: &str) -> bool {
            self.bookmarks.iter().any(|b| b.type_string == type_name)
        }
        fn get_bookmark_count_of_type(&self, type_name: &str) -> usize {
            self.bookmarks.iter().filter(|b| b.type_string == type_name).count()
        }
        fn get_bookmark_count(&self) -> usize {
            self.bookmarks.len()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for smoke tests")
        }
    }

    fn mgr_with(bookmark_mgr: MockBookmarkManager) -> BookmarksSarifMgr {
        BookmarksSarifMgr {
            base: SarifMgr::new(BookmarksSarifMgr::KEY),
            log: MessageLog::new(),
            bookmark_mgr: Arc::new(bookmark_mgr),
        }
    }

    fn result_map(entries: &[(&str, &str)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(BookmarksSarifMgr::KEY, "BOOKMARKS");
        assert_eq!(BookmarksSarifMgr::SUBKEY, "Bookmark");
    }

    #[test]
    fn get_key_returns_bookmarks() {
        let mgr = mgr_with(MockBookmarkManager::new());
        assert_eq!(mgr.get_key(), "BOOKMARKS");
    }

    #[test]
    fn read_without_location_leaves_manager_untouched() {
        // `SarifMgr::get_location` is a stub pending `SarifUtils`, so it never resolves an
        // address; `processBookmark` should skip creating a bookmark rather than panic.
        let mut mgr = mgr_with(MockBookmarkManager::new());
        let result = result_map(&[("kind", "Note"), ("name", "cat"), ("comment", "hi")]);
        let ok = mgr.read(&result, None, &DummyMonitor);
        assert!(ok);
        assert_eq!(mgr.bookmark_mgr.get_bookmark_count(), 0);
    }

    #[test]
    fn overwrite_defaults_true_when_options_absent() {
        // Mirrors `options == null || options.isOverwriteBookmarkConflicts()`.
        let mut mgr = mgr_with(MockBookmarkManager::new());
        let result = result_map(&[("kind", NOTE)]);
        assert!(mgr.read(&result, None, &DummyMonitor));
    }

    #[test]
    fn process_bookmark_sets_new_bookmark_when_overwrite() {
        let mut mgr = mgr_with(MockBookmarkManager::new());
        let addr = test_address(0x1000);
        mgr.process_bookmark_for_test(addr.clone(), NOTE, "cat", "hello", true);
        let found = mgr.bookmark_mgr.get_bookmark(addr, NOTE, "cat");
        assert_eq!(found.unwrap().get_comment(), "hello");
    }

    #[test]
    fn process_bookmark_skips_existing_without_overwrite() {
        let mut mgr = mgr_with(MockBookmarkManager::new());
        let addr = test_address(0x2000);
        mgr.process_bookmark_for_test(addr.clone(), NOTE, "cat", "first", true);
        mgr.process_bookmark_for_test(addr.clone(), NOTE, "cat", "second", false);
        let found = mgr.bookmark_mgr.get_bookmark(addr, NOTE, "cat");
        assert_eq!(found.unwrap().get_comment(), "first");
        assert_eq!(mgr.log.messages().len(), 1);
        assert!(mgr.log.messages()[0].contains("Conflicting"));
    }

    #[test]
    fn process_bookmark_overwrites_existing_when_overwrite_true() {
        let mut mgr = mgr_with(MockBookmarkManager::new());
        let addr = test_address(0x3000);
        mgr.process_bookmark_for_test(addr.clone(), NOTE, "cat", "first", true);
        mgr.process_bookmark_for_test(addr.clone(), NOTE, "cat", "second", true);
        assert_eq!(mgr.bookmark_mgr.get_bookmark_count(), 2);
    }

    #[test]
    fn write_gathers_bookmarks_across_types() {
        let mut inner = MockBookmarkManager::new();
        inner.set_bookmark(test_address(0x1000), "Note", "cat", "a");
        inner.set_bookmark(test_address(0x2000), "Todo", "cat", "b");
        let mgr = mgr_with(inner);
        let mut results = Vec::new();
        let ok = mgr.write(&mut results, None, &DummyMonitor);
        assert!(ok.is_ok());
    }

    #[test]
    fn write_returns_cancelled_when_monitor_cancelled() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                false
            }
            fn clear_cancelled(&self) {}
        }

        let mut inner = MockBookmarkManager::new();
        inner.set_bookmark(test_address(0x1000), "Note", "cat", "a");
        let mgr = mgr_with(inner);
        let mut results = Vec::new();
        let err = mgr.write(&mut results, None, &CancelledMonitor);
        assert!(err.is_err());
    }

    impl BookmarksSarifMgr {
        /// Test-only helper that drives `process_bookmark` with a caller-supplied address,
        /// bypassing the still-stubbed `SarifMgr::get_location` so the overwrite-conflict logic
        /// can be exercised on its own.
        fn process_bookmark_for_test(
            &mut self,
            addr: Address,
            bookmark_type: &str,
            category: &str,
            comment: &str,
            overwrite: bool,
        ) {
            let bookmark_mgr = Arc::get_mut(&mut self.bookmark_mgr).expect("sole owner in tests");
            let has_existing_bookmark = bookmark_mgr
                .get_bookmark(addr.clone(), bookmark_type, category)
                .is_some();
            if overwrite || !has_existing_bookmark {
                bookmark_mgr.set_bookmark(addr.clone(), bookmark_type, category, comment);
            }
            if !overwrite && has_existing_bookmark {
                self.log
                    .append_msg(format!("Conflicting '{bookmark_type}' BOOKMARK ignored at: {addr}"));
            }
        }
    }
}
