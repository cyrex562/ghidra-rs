//! Port of `ghidra.program.database.bookmark.BookmarkDB`, mirroring
//! [`FunctionTagDb`](crate::program::database::function::FunctionTagDb)'s shape: a `pub trait
//! BookmarkDb: Bookmark + DbObject` with `bookmark_db_*`-prefixed default methods where a real
//! algorithm applies, and required methods where the Java body needs `&mut self` access to the
//! owning manager through what this trait can only offer as a shared
//! `Arc<dyn `[`BookmarkManagerDb`]`>` (see that trait's module docs for the seam this bridges,
//! standing in for the not-yet-ported `BookmarkDBManager`).
//!
//! `BookmarkDB extends DbObject implements Bookmark`, modeled by extending both already-ported
//! traits directly (mirroring `FunctionTagDb`'s identical relationship). The `mgr`/`record`
//! fields are exposed as required accessors ([`BookmarkDb::manager`]/[`BookmarkDb::record`]/
//! [`BookmarkDb::set_record`]).
//!
//! [`get_type`](Bookmark::get_type) returns `&dyn BookmarkType`, but [`BookmarkManagerDb::get_bookmark_type`]
//! can only hand back an owned `Arc`; [`BookmarkDb::bookmark_db_get_type`] therefore returns the
//! owned `Arc` under its own name (same owned-vs-borrowed bridging
//! [`FunctionTagDb::function_tag_db_get_comment`](crate::program::database::function::FunctionTagDb::function_tag_db_get_comment)
//! documents), and a concrete `impl Bookmark for Foo` is expected to cache the last-fetched `Arc`
//! in a field and hand back `&*cached` for the real [`Bookmark::get_type`]/
//! [`Bookmark::get_type_string`] bodies.
//!
//! [`set_comment`](BookmarkDb::bookmark_db_set_comment)/[`set`](BookmarkDb::bookmark_db_set) are
//! left required (see each method's own doc): their Java bodies call
//! `BookmarkDBManager.bookmarkChanged(BookmarkDB)`, which is `&mut self` on [`BookmarkManagerDb`]
//! and therefore unreachable from a `&self` default through the shared `Arc`.
//!
//! Left out, matching `FunctionTagDb`'s identical note: `hashCode`/`toString` (`toString`'s exact
//! `"{type} - {category} - {comment} - {address}"` format is trivially reproducible by a concrete
//! implementor via `std::fmt::Display` using the same default accessors, so it isn't worth a
//! trait method of its own), and the package-private constructor/`setRecord`/`getRecord()`
//! accessor (superseded by [`BookmarkDb::set_record`]/[`BookmarkDb::record`]).

use std::cmp::Ordering;
use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::bookmark::bookmark_db_adapter::{
    ADDRESS_COL, CATEGORY_COL, COMMENT_COL,
};
use crate::program::database::bookmark::bookmark_db_adapter_v3::TYPE_ID_OFFSET;
use crate::program::database::bookmark::bookmark_manager_db::BookmarkManagerDb;
use crate::program::database::db_object::DbObject;
use crate::program::model::address::Address;
use crate::program::model::listing::bookmark::Bookmark;
use crate::program::model::listing::bookmark_type::BookmarkType;

/// Database object for [`BookmarkDbAdapterV3`](crate::program::database::bookmark::bookmark_db_adapter_v3::BookmarkDbAdapterV3)
/// records.
///
/// Port of `ghidra.program.database.bookmark.BookmarkDB`. See the module docs for the
/// default-vs-required method split and everything intentionally left out.
pub trait BookmarkDb: Bookmark + DbObject {
    /// Backing storage for the `mgr` field.
    fn manager(&self) -> Arc<dyn BookmarkManagerDb>;

    /// Backing storage for the `record` field, returned by value (mirrors `FunctionTagDb::record`'s
    /// identical convention -- avoids a lock guard whose lifetime can't outlive the accessor).
    fn record(&self) -> DBRecord;

    /// Updates the backing storage for the `record` field. Port of the package-private
    /// `BookmarkDB.setRecord(DBRecord)`, minus its `IllegalArgumentException` key-mismatch guard
    /// (a concrete implementor that only ever calls this with records it fetched for its own key
    /// cannot trigger that case).
    fn set_record(&self, record: DBRecord);

    /// Default body for [`Bookmark::get_id`]. Port of `BookmarkDB.getId()` (`return key;`).
    fn bookmark_db_id(&self) -> i64 {
        self.get_key()
    }

    /// Default body for `DbObject::refresh`. Port of `BookmarkDB.refresh(DBRecord)`.
    fn bookmark_db_refresh(&self, record: Option<&DBRecord>) -> bool {
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => self.manager().get_record(self.get_key()),
        };
        match rec {
            Some(r) => {
                self.set_record(r);
                true
            }
            None => false,
        }
    }

    /// Default body backing [`Bookmark::get_address`]. Port of `BookmarkDB.getAddress()`.
    fn bookmark_db_get_address(&self) -> Address {
        self.validate(self.manager().lock());
        let key = self.record().get_field(ADDRESS_COL).get_long_value();
        self.manager().get_address(key)
    }

    /// Default body backing [`Bookmark::get_type`], returning an owned `Arc` rather than `&dyn
    /// BookmarkType` (see the module docs). Port of `BookmarkDB.getType()`.
    fn bookmark_db_get_type(&self) -> Arc<dyn BookmarkType + Send + Sync> {
        let type_id = (self.get_key() >> TYPE_ID_OFFSET) as i32;
        self.manager().get_bookmark_type(type_id)
    }

    /// Default body backing [`Bookmark::get_type_string`], returning an owned `String` rather
    /// than `&str` (see the module docs). Port of `BookmarkDB.getTypeString()`.
    fn bookmark_db_get_type_string(&self) -> String {
        self.bookmark_db_get_type().get_type_string().to_string()
    }

    /// Default body backing [`Bookmark::get_category`], returning an owned `String` rather than
    /// `&str` (see the module docs). Port of `BookmarkDB.getCategory()`, including its "NOTE: Old
    /// data may have stored null" fallback to an empty string.
    fn bookmark_db_get_category(&self) -> String {
        self.validate(self.manager().lock());
        self.record().get_string(CATEGORY_COL).unwrap_or("").to_string()
    }

    /// Default body backing [`Bookmark::get_comment`], returning an owned `String` rather than
    /// `&str` (see the module docs). Port of `BookmarkDB.getComment()`, including its "NOTE: Old
    /// data may have stored null" fallback to an empty string.
    fn bookmark_db_get_comment(&self) -> String {
        self.validate(self.manager().lock());
        self.record().get_string(COMMENT_COL).unwrap_or("").to_string()
    }

    /// Required body for setting just the comment. Port of `BookmarkDB.setComment(String)`:
    /// ```java
    /// public void setComment(String comment) {
    ///     try (Closeable c = mgr.lock.write()) {
    ///         checkDeleted();
    ///         if (comment == null) comment = "";
    ///         if (!comment.equals(record.getString(COMMENT_COL))) {
    ///             record.setString(COMMENT_COL, comment);
    ///             mgr.bookmarkChanged(this);
    ///         }
    ///     }
    /// }
    /// ```
    /// Left required (see module docs): `BookmarkManagerDb::bookmark_changed` is `&mut self`,
    /// unreachable from a `&self` default through the shared `Arc<dyn BookmarkManagerDb>`
    /// [`BookmarkDb::manager`] returns. A concrete implementor should take the manager's write
    /// lock, call [`DbObject::check_deleted`], then mutate its stored record's
    /// [`COMMENT_COL`](crate::program::database::bookmark::bookmark_db_adapter::COMMENT_COL) via
    /// [`BookmarkDb::set_record`] and notify the manager if the value actually changed.
    fn bookmark_db_set_comment(&self, comment: &str);

    /// Required body for setting category and comment together. Port of `BookmarkDB.set(String,
    /// String)`, the two-field sibling of [`BookmarkDb::bookmark_db_set_comment`] (same required-
    /// method rationale; also updates
    /// [`CATEGORY_COL`](crate::program::database::bookmark::bookmark_db_adapter::CATEGORY_COL)).
    fn bookmark_db_set(&self, category: &str, comment: &str);

    /// Default body for [`Bookmark::compare_to`]. Port of `BookmarkDB.compareTo(Bookmark)`
    /// (address, then type string, then category, then comment, each compared in turn until one
    /// differs).
    fn bookmark_db_compare_to(&self, other: &dyn Bookmark) -> Ordering {
        let rc = self.get_address().cmp(&other.get_address());
        if rc != Ordering::Equal {
            return rc;
        }
        let rc = self.get_type_string().cmp(other.get_type_string());
        if rc != Ordering::Equal {
            return rc;
        }
        let rc = self.get_category().cmp(other.get_category());
        if rc != Ordering::Equal {
            return rc;
        }
        self.get_comment().cmp(other.get_comment())
    }

    /// Port of `BookmarkDB.isOwnedBy(BookmarkDBManager)`: whether this bookmark belongs to the
    /// given manager (Java's `==` reference-identity check, mirrored here via `Arc::ptr_eq`).
    fn bookmark_db_is_owned_by(&self, other_manager: &Arc<dyn BookmarkManagerDb>) -> bool {
        Arc::ptr_eq(&self.manager(), other_manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::bookmark::bookmark_manager_db::BookmarkManagerDb;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::bookmark_type::MarkerColor;
    use crate::util::lock::ReentrantLock;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockType(i32);
    impl BookmarkType for MockType {
        fn get_type_string(&self) -> &str {
            "Note"
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
            true
        }
        fn get_type_id(&self) -> i32 {
            self.0
        }
    }

    /// Minimal in-memory [`BookmarkManagerDb`]. Every field carries its own interior mutability
    /// (`ReentrantLock` already does; `records`/`change_count` are individually `Mutex`-wrapped),
    /// so this whole struct is shared as a plain `Arc<MockManager>` -- no outer `Mutex` needed,
    /// which keeps [`BookmarkManagerDb::lock`] able to hand back a real, safely-borrowed
    /// `&ReentrantLock` (an outer `Mutex<MockManager>` would make that impossible without unsafe
    /// code, since the borrow would need to outlive the guard that produced it).
    struct MockManager {
        lock: ReentrantLock,
        records: Mutex<HashMap<i64, DBRecord>>,
        change_count: Mutex<u32>,
    }

    impl MockManager {
        /// Records a change, callable through a shared `&MockManager` (interior mutability),
        /// used by [`MockBookmarkDb`]'s required set methods to notify the manager without
        /// needing `&mut` access to it (see [`BookmarkManagerDb::bookmark_changed`]'s own doc for
        /// why the trait method itself is `&mut self`).
        fn record_change(&self, key: i64) {
            *self.change_count.lock().unwrap() += 1;
            let _ = key;
        }
    }

    impl BookmarkManagerDb for MockManager {
        fn lock(&self) -> &ReentrantLock {
            &self.lock
        }
        fn get_address(&self, address_key: i64) -> Address {
            Address::new(ram(), address_key)
        }
        fn get_bookmark_type(&self, type_id: i32) -> Arc<dyn BookmarkType + Send + Sync> {
            Arc::new(MockType(type_id))
        }
        fn get_record(&self, key: i64) -> Option<DBRecord> {
            self.records.lock().unwrap().get(&key).cloned()
        }
        fn bookmark_changed(&mut self, key: i64) {
            self.record_change(key);
        }
    }

    fn schema() -> Arc<crate::framework::db::Schema> {
        crate::program::database::bookmark::bookmark_db_adapter_v3::schema()
    }

    /// Minimal [`BookmarkDb`] implementor, caching its last-fetched `BookmarkType` `Arc` in a
    /// field to bridge the owned-vs-`&dyn` gap the module docs describe.
    struct MockBookmarkDb {
        state: DbObjectState,
        /// Direct handle used only by the required set methods
        /// ([`BookmarkDb::bookmark_db_set_comment`]/[`BookmarkDb::bookmark_db_set`]), bypassing
        /// the trait's `manager()` accessor and calling `MockManager::record_change` directly
        /// (which only needs `&self` -- see that method's own doc).
        manager: Arc<MockManager>,
        /// Stable `Arc<dyn BookmarkManagerDb>` returned by the trait's `manager()` accessor.
        /// Built once and cloned (not reconstructed) on each call, so
        /// [`BookmarkDb::bookmark_db_is_owned_by`]'s `Arc::ptr_eq` identity check is meaningful.
        manager_ref: Arc<dyn BookmarkManagerDb>,
        record: Mutex<DBRecord>,
        cached_type: Mutex<Arc<dyn BookmarkType + Send + Sync>>,
        cached_type_string: Mutex<String>,
        cached_category: Mutex<String>,
        cached_comment: Mutex<String>,
    }

    impl MockBookmarkDb {
        fn new(
            manager: Arc<MockManager>,
            type_id: i32,
            local_id: i64,
            address: i64,
            category: &str,
            comment: &str,
        ) -> Self {
            let key = ((type_id as i64) << TYPE_ID_OFFSET) | local_id;
            let mut record = DBRecord::new(schema(), crate::framework::db::Field::Long(Some(key)));
            record.set_field(ADDRESS_COL, crate::framework::db::Field::Long(Some(address)));
            record.set_field(
                CATEGORY_COL,
                crate::framework::db::Field::String(Some(category.to_string())),
            );
            record.set_field(
                COMMENT_COL,
                crate::framework::db::Field::String(Some(comment.to_string())),
            );
            manager.records.lock().unwrap().insert(key, record.clone());
            let cached_type = Arc::new(MockType(type_id)) as Arc<dyn BookmarkType + Send + Sync>;
            let manager_ref: Arc<dyn BookmarkManagerDb> = Arc::new(ManagerRef(manager.clone()));
            MockBookmarkDb {
                state: DbObjectState::new(key),
                manager,
                manager_ref,
                record: Mutex::new(record),
                cached_type: Mutex::new(cached_type),
                cached_type_string: Mutex::new("Note".to_string()),
                cached_category: Mutex::new(category.to_string()),
                cached_comment: Mutex::new(comment.to_string()),
            }
        }
    }

    impl DbObject for MockBookmarkDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }
        fn refresh(&self, record: Option<&DBRecord>) -> bool {
            self.bookmark_db_refresh(record)
        }
    }

    /// Thin `&dyn BookmarkManagerDb` view over `Arc<MockManager>`. Every method here reaches the
    /// shared mock directly (no lock-and-borrow gymnastics needed, since `MockManager`'s own
    /// fields are already individually interior-mutable -- see its doc comment).
    struct ManagerRef(Arc<MockManager>);
    impl BookmarkManagerDb for ManagerRef {
        fn lock(&self) -> &ReentrantLock {
            &self.0.lock
        }
        fn get_address(&self, address_key: i64) -> Address {
            self.0.get_address(address_key)
        }
        fn get_bookmark_type(&self, type_id: i32) -> Arc<dyn BookmarkType + Send + Sync> {
            self.0.get_bookmark_type(type_id)
        }
        fn get_record(&self, key: i64) -> Option<DBRecord> {
            self.0.get_record(key)
        }
        fn bookmark_changed(&mut self, key: i64) {
            self.0.record_change(key);
        }
    }

    impl BookmarkDb for MockBookmarkDb {
        fn manager(&self) -> Arc<dyn BookmarkManagerDb> {
            self.manager_ref.clone()
        }
        fn record(&self) -> DBRecord {
            self.record.lock().unwrap().clone()
        }
        fn set_record(&self, record: DBRecord) {
            if let Some(cat) = record.get_string(CATEGORY_COL) {
                *self.cached_category.lock().unwrap() = cat.to_string();
            }
            if let Some(com) = record.get_string(COMMENT_COL) {
                *self.cached_comment.lock().unwrap() = com.to_string();
            }
            *self.record.lock().unwrap() = record;
        }
        fn bookmark_db_set_comment(&self, comment: &str) {
            if self.check_deleted().is_err() {
                return;
            }
            let old = self.record().get_string(COMMENT_COL).unwrap_or("").to_string();
            if comment != old {
                let mut rec = self.record();
                rec.set_field(
                    COMMENT_COL,
                    crate::framework::db::Field::String(Some(comment.to_string())),
                );
                self.set_record(rec.clone());
                self.manager.records.lock().unwrap().insert(self.get_key(), rec);
                self.manager.record_change(self.get_key());
            }
        }
        fn bookmark_db_set(&self, category: &str, comment: &str) {
            if self.check_deleted().is_err() {
                return;
            }
            let mut rec = self.record();
            rec.set_field(
                CATEGORY_COL,
                crate::framework::db::Field::String(Some(category.to_string())),
            );
            rec.set_field(
                COMMENT_COL,
                crate::framework::db::Field::String(Some(comment.to_string())),
            );
            self.set_record(rec.clone());
            self.manager.records.lock().unwrap().insert(self.get_key(), rec);
            self.manager.record_change(self.get_key());
        }
    }

    impl Bookmark for MockBookmarkDb {
        fn get_id(&self) -> i64 {
            self.bookmark_db_id()
        }
        fn get_address(&self) -> Address {
            self.bookmark_db_get_address()
        }
        fn get_type(&self) -> &dyn BookmarkType {
            self.refresh_if_needed();
            *self.cached_type.lock().unwrap() = self.bookmark_db_get_type();
            let arc = self.cached_type.lock().unwrap().clone();
            // Leak-free bridge is not possible through a `Mutex` guard's lifetime; this smoke
            // test only needs `get_type_string`, exercised via `bookmark_db_get_type_string`
            // directly instead of through this accessor.
            Box::leak(Box::new(ArcTypeRef(arc)))
        }
        fn get_type_string(&self) -> &str {
            self.refresh_if_needed();
            *self.cached_type_string.lock().unwrap() = self.bookmark_db_get_type_string();
            Box::leak(self.cached_type_string.lock().unwrap().clone().into_boxed_str())
        }
        fn get_category(&self) -> &str {
            self.refresh_if_needed();
            *self.cached_category.lock().unwrap() = self.bookmark_db_get_category();
            Box::leak(self.cached_category.lock().unwrap().clone().into_boxed_str())
        }
        fn get_comment(&self) -> &str {
            self.refresh_if_needed();
            *self.cached_comment.lock().unwrap() = self.bookmark_db_get_comment();
            Box::leak(self.cached_comment.lock().unwrap().clone().into_boxed_str())
        }
        fn set(&mut self, category: &str, comment: &str) {
            self.bookmark_db_set(category, comment);
        }
        fn compare_to(&self, other: &dyn Bookmark) -> Ordering {
            self.bookmark_db_compare_to(other)
        }
    }

    /// Thin `&dyn BookmarkType` wrapper around an owned `Arc`, used only so
    /// [`Bookmark::get_type`]'s test impl above can return a `'static` reference via `Box::leak`.
    struct ArcTypeRef(Arc<dyn BookmarkType + Send + Sync>);
    impl BookmarkType for ArcTypeRef {
        fn get_type_string(&self) -> &str {
            self.0.get_type_string()
        }
        fn get_icon(&self) -> Option<Box<dyn crate::program::model::data::playable::Icon>> {
            self.0.get_icon()
        }
        fn get_marker_color(&self) -> Option<MarkerColor> {
            self.0.get_marker_color()
        }
        fn get_marker_priority(&self) -> i32 {
            self.0.get_marker_priority()
        }
        fn has_bookmarks(&self) -> bool {
            self.0.has_bookmarks()
        }
        fn get_type_id(&self) -> i32 {
            self.0.get_type_id()
        }
    }

    fn manager() -> Arc<MockManager> {
        Arc::new(MockManager {
            lock: ReentrantLock::new("Bookmarks"),
            records: Mutex::new(HashMap::new()),
            change_count: Mutex::new(0),
        })
    }

    #[test]
    fn accessors_read_through_the_record() {
        let mgr = manager();
        let bm = MockBookmarkDb::new(mgr, 3, 1, 0x1000, "general", "hello");
        assert_eq!(bm.bookmark_db_id(), (3i64 << TYPE_ID_OFFSET) | 1);
        assert_eq!(Bookmark::get_address(&bm).offset(), 0x1000);
        assert_eq!(Bookmark::get_type_string(&bm), "Note");
        assert_eq!(Bookmark::get_category(&bm), "general");
        assert_eq!(Bookmark::get_comment(&bm), "hello");
    }

    #[test]
    fn set_comment_notifies_manager_only_on_change() {
        let mgr = manager();
        let bm = MockBookmarkDb::new(mgr.clone(), 0, 1, 0x10, "cat", "old");
        bm.bookmark_db_set_comment("new");
        assert_eq!(Bookmark::get_comment(&bm), "new");
        assert_eq!(*mgr.change_count.lock().unwrap(), 1);

        bm.bookmark_db_set_comment("new");
        assert_eq!(*mgr.change_count.lock().unwrap(), 1);
    }

    #[test]
    fn set_updates_category_and_comment_together() {
        let mgr = manager();
        let mut bm = MockBookmarkDb::new(mgr, 0, 1, 0x10, "cat", "old");
        Bookmark::set(&mut bm, "newcat", "newcomment");
        assert_eq!(Bookmark::get_category(&bm), "newcat");
        assert_eq!(Bookmark::get_comment(&bm), "newcomment");
    }

    #[test]
    fn compare_to_orders_by_address_then_type_then_category_then_comment() {
        let mgr = manager();
        let a = MockBookmarkDb::new(mgr.clone(), 0, 1, 0x1000, "cat", "aaa");
        let b = MockBookmarkDb::new(mgr, 0, 2, 0x2000, "cat", "aaa");
        assert_eq!(Bookmark::compare_to(&a, &b), Ordering::Less);
        assert_eq!(Bookmark::compare_to(&b, &a), Ordering::Greater);
    }

    #[test]
    fn is_owned_by_uses_manager_identity() {
        let mgr_a = manager();
        let mgr_b = manager();
        let bm = MockBookmarkDb::new(mgr_a, 0, 1, 0x10, "cat", "c");

        // Its own (stable) manager Arc, cloned -- same underlying allocation, so `ptr_eq` matches.
        let owner = bm.manager();
        assert!(bm.bookmark_db_is_owned_by(&owner));

        // A different manager entirely -- must not match.
        let other: Arc<dyn BookmarkManagerDb> = Arc::new(ManagerRef(mgr_b));
        assert!(!bm.bookmark_db_is_owned_by(&other));
    }
}
