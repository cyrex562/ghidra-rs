//! Decoupling seam standing in for the pieces of `ghidra.program.database.bookmark.BookmarkDBManager`
//! (a 798-line class, `PORT_MANIFEST.tsv` still `TODO` -- not ported this session) that
//! `BookmarkDB` needs from its owning manager: address decoding, bookmark-type lookup by ID,
//! record lookup by key, change notification, and the manager's write lock.
//!
//! Mirrors this port's established convention for exactly this situation --
//! [`FunctionTagManagerDb`](crate::program::database::function::FunctionTagManagerDb) plays the
//! identical role for `FunctionTagDB`/`FunctionTagManagerDB`. A future `BookmarkDBManager` port
//! implements this trait directly (or via a thin wrapper), and every method here has a one-to-one
//! Java counterpart already named in its own doc comment, so that port should be a mechanical
//! fill-in rather than a redesign.

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::model::address::Address;
use crate::program::model::listing::bookmark_type::BookmarkType;
use crate::util::lock::ReentrantLock;

/// Seam trait exposing exactly what [`BookmarkDb`](crate::program::database::bookmark::bookmark_db::BookmarkDb)
/// needs from its owning `BookmarkDBManager`.
pub trait BookmarkManagerDb: Send + Sync {
    /// The manager's write lock, guarding mutation of a bookmark's category/comment. Stands in
    /// for `BookmarkDBManager.lock`.
    fn lock(&self) -> &ReentrantLock;

    /// Decodes an address-map key (as stored in a bookmark record's `ADDRESS_COL`) into an
    /// [`Address`]. Stands in for `BookmarkDBManager.getAddress(long)`.
    fn get_address(&self, address_key: i64) -> Address;

    /// Looks up the bookmark type with the given ID. Stands in for
    /// `BookmarkDBManager.getBookmarkType(int)`.
    fn get_bookmark_type(&self, type_id: i32) -> Arc<dyn BookmarkType + Send + Sync>;

    /// Fetches the current record for the bookmark with the given key, or `None` if it no longer
    /// exists. Stands in for `BookmarkDBManager.getRecord(long)` (which internally reports I/O
    /// errors via `dbError` rather than propagating them to the caller, so this seam returns a
    /// plain `Option` rather than an `io::Result`, matching that same non-throwing contract).
    fn get_record(&self, key: i64) -> Option<DBRecord>;

    /// Notifies the manager that the given bookmark's record has been mutated in place (category
    /// and/or comment), so it can persist the change and fire a change event. Stands in for
    /// `BookmarkDBManager.bookmarkChanged(BookmarkDB)`.
    ///
    /// `&mut self`: persisting the change is a real database write, mirroring every other
    /// mutating manager method ported this session (e.g.
    /// [`BookmarkDbAdapterV3::update_record`](crate::program::database::bookmark::bookmark_db_adapter_v3::BookmarkDbAdapterV3)).
    /// Because [`BookmarkDb::manager`] can only hand back a shared `Arc<dyn BookmarkManagerDb>`,
    /// this method is unreachable from a `&self` trait default -- see
    /// [`BookmarkDb::bookmark_db_set_comment`]/[`BookmarkDb::bookmark_db_set`], which are left
    /// required for exactly this reason (same friction
    /// [`FunctionTagDb::function_tag_db_set_comment`](crate::program::database::function::FunctionTagDb::function_tag_db_set_comment)
    /// documents for its own manager).
    fn bookmark_changed(&mut self, key: i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockManager {
        lock: ReentrantLock,
        records: Mutex<std::collections::HashMap<i64, DBRecord>>,
        changed: Mutex<Vec<i64>>,
    }

    struct MockType(i32);
    impl BookmarkType for MockType {
        fn get_type_string(&self) -> &str {
            "Note"
        }
        fn get_icon(&self) -> Option<Box<dyn crate::program::model::data::playable::Icon>> {
            None
        }
        fn get_marker_color(
            &self,
        ) -> Option<crate::program::model::listing::bookmark_type::MarkerColor> {
            None
        }
        fn get_marker_priority(&self) -> i32 {
            -1
        }
        fn has_bookmarks(&self) -> bool {
            true
        }
        fn get_type_id(&self) -> i32 {
            self.0
        }
    }

    impl BookmarkManagerDb for MockManager {
        fn lock(&self) -> &ReentrantLock {
            &self.lock
        }
        fn get_address(&self, address_key: i64) -> Address {
            let space = crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                0,
            );
            Address::new(space, address_key)
        }
        fn get_bookmark_type(&self, type_id: i32) -> Arc<dyn BookmarkType + Send + Sync> {
            Arc::new(MockType(type_id))
        }
        fn get_record(&self, key: i64) -> Option<DBRecord> {
            self.records.lock().unwrap().get(&key).cloned()
        }
        fn bookmark_changed(&mut self, key: i64) {
            self.changed.lock().unwrap().push(key);
        }
    }

    #[test]
    fn mock_manager_behaves_as_a_trait_object() {
        let mut mgr: Box<dyn BookmarkManagerDb> = Box::new(MockManager {
            lock: ReentrantLock::new("Bookmarks"),
            records: Mutex::new(std::collections::HashMap::new()),
            changed: Mutex::new(Vec::new()),
        });
        assert!(mgr.get_record(1).is_none());
        assert_eq!(mgr.get_bookmark_type(3).get_type_id(), 3);
        mgr.bookmark_changed(5);
        let addr = mgr.get_address(0x100);
        assert_eq!(addr.offset(), 0x100);
    }
}
