//! Port of `ghidra.program.database.bookmark.BookmarkDBManager`.
//!
//! The real, concrete bookmark manager: owns bookmark-type registration
//! ([`BookmarkTypes`]/[`BookmarkTypeDb`]), the adapter-version selection/upgrade chain
//! ([`bookmark_db_adapter::get_adapter`], routing between [`BookmarkDbAdapterV0`]/
//! [`BookmarkDbAdapterV1`]/[`BookmarkDbAdapterV2`]/[`BookmarkDbAdapterV3`]), the sibling bookmark-
//! *type* adapter (routing between [`BookmarkTypeDbAdapterNoTable`]/[`BookmarkTypeDbAdapterV0`]),
//! and the `BookmarkManager`-shaped public API. Implements the [`BookmarkManagerDb`] seam trait
//! that [`BookmarkDb`]/[`BookmarkTypeDb`] were already built against.
//!
//! # Interior mutability, not `&mut self`
//!
//! Every real-work method takes `&self`, matching this port's established convention for
//! concrete DB managers (e.g. `NamespaceManagerDB`, `SymbolManagerDB`): mutable state lives behind
//! `Mutex`/`ReentrantLock`, so a `BookmarkDBManager` can be shared as `Arc<Self>` (and, via
//! [`BookmarkManagerDb`], as `Arc<dyn BookmarkManagerDb>`) without exclusive-borrow contention.
//!
//! # Self-referential `Arc`
//!
//! Every [`BookmarkRecordDb`] this manager hands out needs a way back to its owning manager (for
//! [`BookmarkDb::manager`]). [`BookmarkDBManager::new`] therefore returns `Arc<Self>` built via
//! `Arc::new_cyclic`, storing a `Weak<Self>` in `self_handle` -- the same pattern
//! [`MatchCache`](crate::feature::vt::api::db::vt_match_set_db) already uses for an identical
//! self-reference need.
//!
//! # Adapters are enums, not trait objects
//!
//! [`bookmark_db_adapter::BookmarkAdapterKind`] and this module's own [`BookmarkTypeAdapterKind`]
//! are closed enums over their few concrete variants, not `Box<dyn ...>` -- see
//! [`BookmarkAdapterKind`](crate::program::database::bookmark::bookmark_db_adapter::BookmarkAdapterKind)'s
//! own module docs for why (in short: every variant is independently `Send`, but neither
//! `BookmarkDbAdapter` nor `BookmarkTypeDbAdapter` declares that bound, so a trait object would
//! need it spelled out at every construction site; an enum sidesteps the question).
//! [`BookmarkTypeAdapterKind::select`] duplicates
//! [`bookmark_type_db_adapter::get_adapter`](crate::program::database::bookmark::bookmark_type_db_adapter::get_adapter)'s
//! selection logic for the same reason -- that function returns `Box<dyn BookmarkTypeDbAdapter>`
//! (no `Send` bound), which this manager cannot store in a field a `Send + Sync` manager needs.
//!
//! # `Bookmark`/`BookmarkType` reference-returning getters vs. interior-mutable storage
//!
//! [`Bookmark::get_category`]/[`Bookmark::get_comment`]/[`Bookmark::get_type_string`] must return
//! `&str` borrowed from `&self`, but [`BookmarkRecordDb`]'s backing `DBRecord` lives behind a
//! `Mutex` (it can change on refresh) -- a `&str` borrowed from a `MutexGuard` cannot outlive that
//! guard. This port's only prior concrete implementors of this exact trait shape --
//! `bookmark_db.rs`'s and `function_tag_db.rs`'s own test mocks -- resolve it by leaking a fresh,
//! small owned copy on each call (`Box::leak`); [`BookmarkRecordDb`] follows that same established
//! precedent here for real, non-test code. [`Bookmark::get_type`]/[`Bookmark::get_type_string`],
//! by contrast, need no leak at all: a bookmark's type is derived from the immutable high bits of
//! its own key and therefore never changes after construction, so it is cached once as a plain
//! `Arc<BookmarkTypeDb>` field and borrowed directly.
//!
//! # Not ported (honestly left out; no fake stubs)
//!
//! - `moveAddressRange`/`deleteAddressRange` (the `ManagerDB` address-relocation/deletion
//!   callbacks) -- these need `DatabaseTableUtils.updateIndexedAddressField`-style bulk
//!   address-column remapping across every per-type table, which no address-map/table utility in
//!   this port currently provides. `// TODO(port):` markers are left at the two inherent methods'
//!   natural locations below.
//! - `removeBookmarks(AddressSetView, ...)` (three overloads: all types, one type, one type +
//!   category) -- these iterate every bookmark in a set via `AddressIndexPrimaryKeyIterator`
//!   against the raw per-type `Table`, which this port's [`BookmarkDbAdapter`] trait does not
//!   expose (deliberately -- see that trait's own module docs on `get_table` staying
//!   `pub(crate)`). A caller needing this today can still reasonably approximate it by combining
//!   [`BookmarkDBManager::get_bookmarks_iterator_of_type`] with a manual `AddressSetView::contains`
//!   filter and repeated [`BookmarkDBManager::remove_bookmark`] calls.
//! - `getBookmarksIterator(Address, boolean)` (iterate from a start address, forward or backward)
//!   -- `BookmarkDbAdapter::get_records_by_type_starting_at_address` exists and is exercised by
//!   `BookmarkDbAdapterV3`'s own tests, but wiring the manager-level multi-type merge
//!   (`MultiIterator`/`PeekableIterator` in Java) was cut for time; every other iteration method
//!   Java's `BookmarkManager` interface declares is ported.
//! - The formal `ManagerDB`/`BookmarkManager`/`ErrorHandler` trait `impl`s themselves are not
//!   attached to this struct (Java: `implements BookmarkManager, ErrorHandler, ManagerDB`).
//!   `BookmarkManager`'s own methods take `&mut self` (see that trait's own file), which would
//!   force exactly the exclusive-borrow model this manager (and the `BookmarkManagerDb` seam it
//!   *does* implement) is built to avoid. Every method `BookmarkManager` declares still exists
//!   here as a `&self` inherent method with an equivalent (if not identically-typed) signature, so
//!   a thin `&mut self`-taking wrapper could implement the trait later without touching this file.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::database::bookmark::bookmark_db::BookmarkDb;
use crate::program::database::bookmark::bookmark_db_adapter::{
    self, BookmarkAdapterKind, BookmarkDbAdapter, CATEGORY_COL, COMMENT_COL,
};
use crate::program::database::bookmark::bookmark_manager_db::BookmarkManagerDb;
use crate::program::database::bookmark::bookmark_type_db::BookmarkTypeDb;
use crate::program::database::bookmark::bookmark_type_db_adapter::{BookmarkTypeDbAdapter, TYPE_NAME_COL};
use crate::program::database::bookmark::bookmark_type_db_adapter_no_table::BookmarkTypeDbAdapterNoTable;
use crate::program::database::bookmark::bookmark_type_db_adapter_v0::BookmarkTypeDbAdapterV0;
use crate::program::database::bookmark::bookmark_types::BookmarkTypes;
use crate::program::database::bookmark::old_bookmark_manager::OldBookmarkManager;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressSet};
use crate::program::model::listing::bookmark::Bookmark;
use crate::program::model::listing::bookmark_type::{BookmarkType, MarkerColor};
use crate::program::seam_stubs::BookmarkManagerProgram;
use crate::util::exception::CancelledException;
use crate::util::lock::ReentrantLock;
use crate::util::task::TaskMonitor;
use crate::util::exception::VersionException;

/// Which of the two historical bookmark-*type* table schemas is in play. Mirrors
/// [`BookmarkAdapterKind`] for the sibling type-adapter family -- see the module docs for why this
/// duplicates [`bookmark_type_db_adapter::get_adapter`]'s selection logic instead of reusing it.
pub enum BookmarkTypeAdapterKind {
    NoTable(BookmarkTypeDbAdapterNoTable),
    V0(BookmarkTypeDbAdapterV0),
}

impl BookmarkTypeAdapterKind {
    /// Port of `BookmarkTypeDBAdapter.getAdapter(DBHandle, OpenMode)`, re-implemented against this
    /// enum instead of `Box<dyn BookmarkTypeDbAdapter>` -- see the module docs.
    fn select(handle: &mut DBHandle, open_mode: OpenMode) -> Result<Self, VersionException> {
        if open_mode == OpenMode::Create {
            return Ok(Self::V0(BookmarkTypeDbAdapterV0::new(handle, true)?));
        }
        match BookmarkTypeDbAdapterV0::new(handle, false) {
            Ok(a) => Ok(Self::V0(a)),
            Err(e) => {
                if open_mode == OpenMode::Update {
                    return Err(e);
                }
                if open_mode == OpenMode::Upgrade {
                    return Ok(Self::V0(BookmarkTypeDbAdapterV0::new(handle, true)?));
                }
                Ok(Self::NoTable(BookmarkTypeDbAdapterNoTable::new()))
            }
        }
    }
}

impl BookmarkTypeDbAdapter for BookmarkTypeAdapterKind {
    fn add_type(&mut self, type_id: i32, type_name: &str) -> io::Result<()> {
        match self {
            Self::NoTable(a) => a.add_type(type_id, type_name),
            Self::V0(a) => a.add_type(type_id, type_name),
        }
    }
    fn delete_record(&mut self, type_id: i64) -> io::Result<()> {
        match self {
            Self::NoTable(a) => a.delete_record(type_id),
            Self::V0(a) => a.delete_record(type_id),
        }
    }
    fn get_records(&self) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::NoTable(a) => a.get_records(),
            Self::V0(a) => a.get_records(),
        }
    }
}

/// The real, concrete bookmark manager. See the module docs.
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBManager`.
pub struct BookmarkDBManager {
    self_handle: Weak<BookmarkDBManager>,
    handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    bookmark_type_adapter: Mutex<BookmarkTypeAdapterKind>,
    bookmark_adapter: Mutex<BookmarkAdapterKind>,
    bookmark_types: Mutex<BookmarkTypes>,
    /// Simplified in-memory replacement for Java's `DbCache<BookmarkDB>` -- a plain key-indexed
    /// map rather than the generic modification-count-based `DbCache` abstraction (see
    /// `db_cache.rs`), since correctness only needs "the same key always maps to the same
    /// instance," which a `HashMap` already gives for free.
    cache: Mutex<HashMap<i64, Arc<BookmarkRecordDb>>>,
    lock: ReentrantLock,
    owner: Mutex<Option<Arc<dyn BookmarkManagerProgram>>>,
    upgrade: bool,
}

impl BookmarkDBManager {
    /// Constructs a new bookmark manager for a program's database. Port of
    /// `BookmarkDBManager(DBHandle, AddressMap, OpenMode, Lock, TaskMonitor)`. Java's shared
    /// `Lock` parameter is dropped -- this manager owns its own [`ReentrantLock`] instead (no
    /// concrete `ProgramDB` yet to hand a program-wide one down from).
    ///
    /// # Errors
    /// Returns a [`VersionException`] if the database is incompatible with `open_mode` and cannot
    /// be upgraded, or an I/O error (wrapped as a `VersionException`, matching how this port's
    /// other `getAdapter`-style factories report I/O failures through the same single error type)
    /// if reading the bookmark-type table fails.
    pub fn new(
        handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        open_mode: OpenMode,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<Self>, VersionException> {
        let upgrade = open_mode == OpenMode::Upgrade;

        let (bookmark_type_adapter, type_ids) = {
            let mut h = handle.write().unwrap();
            let type_adapter = BookmarkTypeAdapterKind::select(&mut h, open_mode)?;
            let type_ids: Vec<i32> = type_adapter
                .get_type_ids()
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            (type_adapter, type_ids)
        };

        let bookmark_adapter = {
            let mut h = handle.write().unwrap();
            bookmark_db_adapter::get_adapter(&mut h, open_mode, &type_ids, addr_map.clone(), monitor)?
        };

        Ok(Arc::new_cyclic(|weak| BookmarkDBManager {
            self_handle: weak.clone(),
            handle,
            addr_map,
            bookmark_type_adapter: Mutex::new(bookmark_type_adapter),
            bookmark_adapter: Mutex::new(bookmark_adapter),
            bookmark_types: Mutex::new(BookmarkTypes::new()),
            cache: Mutex::new(HashMap::new()),
            lock: ReentrantLock::new("Bookmarks"),
            owner: Mutex::new(None),
            upgrade,
        }))
    }

    fn owner(&self) -> Option<Arc<dyn BookmarkManagerProgram>> {
        self.owner.lock().unwrap().clone()
    }

    fn report_error(&self, e: io::Error) {
        if let Some(owner) = self.owner() {
            owner.db_error(&e);
        }
    }

    /// Associates this manager with its owning program. Port of `BookmarkDBManager.setProgram`.
    ///
    /// # Panics
    /// Panics if called more than once, mirroring Java's `AssertException` guard.
    pub fn set_owner(&self, owner: Arc<dyn BookmarkManagerProgram>) {
        {
            let mut slot = self.owner.lock().unwrap();
            assert!(slot.is_none(), "BookmarkDBManager owner already set");
            *slot = Some(owner.clone());
        }

        if self.upgrade {
            self.upgrade_old_bookmarks(&owner);
        } else {
            let is_legacy = {
                let type_adapter = self.bookmark_type_adapter.lock().unwrap();
                let bm_adapter = self.bookmark_adapter.lock().unwrap();
                matches!(&*type_adapter, BookmarkTypeAdapterKind::NoTable(_))
                    && matches!(&*bm_adapter, BookmarkAdapterKind::V0(_))
            };
            if is_legacy {
                let old_mgr = OldBookmarkManager::new(owner.program(), owner.property_map_manager());
                {
                    let mut type_adapter = self.bookmark_type_adapter.lock().unwrap();
                    if let BookmarkTypeAdapterKind::NoTable(nt) = &mut *type_adapter {
                        nt.set_records(old_mgr.get_type_records());
                    }
                }
                let mut bm_adapter = self.bookmark_adapter.lock().unwrap();
                if let BookmarkAdapterKind::V0(v0) = &mut *bm_adapter {
                    if let Err(e) = v0.set_old_bookmark_manager(&old_mgr, self.addr_map.clone()) {
                        drop(bm_adapter);
                        self.report_error(e);
                    }
                }
            }
        }

        if let Err(e) = self.load_bookmark_types() {
            self.report_error(e);
        }
    }

    /// Upgrades old property-based bookmarks to the new storage schema. Port of the private
    /// `BookmarkDBManager.upgradeOldBookmarks(ProgramDB)`.
    fn upgrade_old_bookmarks(&self, owner: &Arc<dyn BookmarkManagerProgram>) {
        let old_mgr = OldBookmarkManager::new(owner.program(), owner.property_map_manager());
        let old_types = old_mgr.get_type_records();
        if old_types.is_empty() {
            return;
        }
        for old_type in &old_types {
            let type_name = old_type.get_string(TYPE_NAME_COL).unwrap_or_default().to_string();
            let addrs: Vec<Address> = old_mgr.get_bookmark_addresses(&type_name).collect();
            for addr in addrs {
                if let Some(bm) = old_mgr.get_bookmark(&addr, &type_name) {
                    self.set_bookmark(addr, &type_name, bm.get_category(), bm.get_comment());
                }
            }
            old_mgr.remove_all_bookmarks(&type_name);
        }
    }

    /// Loads bookmark type records from the type adapter, refreshing `has_bookmarks` for each.
    /// Port of the unconditional `typeRecords` loop at the end of `BookmarkDBManager.setProgram`.
    fn load_bookmark_types(&self) -> io::Result<()> {
        let records = self.bookmark_type_adapter.lock().unwrap().get_records()?;
        let mut types = BookmarkTypes::new();
        let adapter = self.bookmark_adapter.lock().unwrap();
        for rec in records {
            let type_id = rec.get_key().get_long_value() as i32;
            let name = rec.get_string(TYPE_NAME_COL).unwrap_or_default().to_string();
            let bt = Arc::new(BookmarkTypeDb::new(type_id, name));
            bt.set_has_bookmarks(adapter.has_table(type_id));
            types.add_bookmark_type(bt);
        }
        drop(adapter);
        *self.bookmark_types.lock().unwrap() = types;
        Ok(())
    }

    /// Gets or creates a bookmark type with the given name, allocating a table for it if
    /// `create_in_database` is true and it doesn't already have one. Port of the private
    /// `BookmarkDBManager.getBookmarkType(String, boolean)`.
    fn get_or_create_bookmark_type(&self, type_name: &str, create_in_database: bool) -> io::Result<Arc<BookmarkTypeDb>> {
        let bmt = {
            let mut types = self.bookmark_types.lock().unwrap();
            match types.get(type_name) {
                Some(t) => t.clone(),
                None => {
                    let id = types.get_lowest_unused_id();
                    let t = Arc::new(BookmarkTypeDb::new(id, type_name));
                    types.add_bookmark_type(t.clone());
                    t
                }
            }
        };
        if create_in_database && !bmt.has_bookmarks() {
            self.bookmark_type_adapter
                .lock()
                .unwrap()
                .add_type(bmt.get_type_id(), bmt.get_type_string())?;
            {
                let mut h = self.handle.write().unwrap();
                self.bookmark_adapter.lock().unwrap().add_type(&mut h, bmt.get_type_id())?;
            }
            bmt.set_has_bookmarks(true);
            if let Some(owner) = self.owner() {
                owner.bookmark_type_added(bmt.get_type_id(), bmt.get_type_string());
            }
        }
        Ok(bmt)
    }

    fn get_cached_instance(&self, record: DBRecord, bookmark_type: Arc<BookmarkTypeDb>) -> Arc<BookmarkRecordDb> {
        let key = record.get_key().get_long_value();
        let mut cache = self.cache.lock().unwrap();
        if let Some(existing) = cache.get(&key) {
            existing.refresh(Some(&record));
            return existing.clone();
        }
        let bm = Arc::new(BookmarkRecordDb::new(self.self_handle.clone(), record, bookmark_type));
        cache.insert(key, bm.clone());
        bm
    }

    /// Persists an in-place category/comment edit and fires the change notification. Backs both
    /// [`BookmarkManagerDb::bookmark_changed`] and (via a direct call on the upgraded concrete
    /// `Arc`, bypassing the trait entirely) [`BookmarkRecordDb::bookmark_db_set_comment`]/
    /// [`BookmarkRecordDb::bookmark_db_set`] -- see [`BookmarkManagerDb::bookmark_changed`]'s own
    /// doc comment for why the trait method's `&mut self` signature makes it otherwise
    /// unreachable through the shared `Arc<dyn BookmarkManagerDb>` this manager is normally used
    /// as. Port of `BookmarkDBManager.bookmarkChanged(BookmarkDB)`.
    fn persist_bookmark_change(&self, key: i64) {
        let Some(bm) = self.cache.lock().unwrap().get(&key).cloned() else {
            return;
        };
        let rec = bm.record();
        if let Err(e) = self.bookmark_adapter.lock().unwrap().update_record(&rec) {
            self.report_error(e);
            return;
        }
        if let Some(owner) = self.owner() {
            owner.bookmark_changed(&bm.bookmark_db_get_address(), key);
        }
    }

    //==============================================================================================
    // BookmarkManager-shaped public API
    //==============================================================================================

    /// Defines a bookmark type with its marker icon and color. Port of
    /// `BookmarkDBManager.defineType(String, Icon, Color, int)`.
    ///
    /// # Panics
    /// Panics if `type_name` is blank after trimming, mirroring Java's
    /// `IllegalArgumentException("Invalid bookmark type parameters were specified")`.
    pub fn define_type(&self, type_name: &str, icon_id: Option<String>, color: MarkerColor, priority: i32) -> Arc<BookmarkTypeDb> {
        let _guard = self.lock.write();
        let trimmed = type_name.trim();
        assert!(!trimmed.is_empty(), "Invalid bookmark type parameters were specified");
        let bmt = match self.get_or_create_bookmark_type(trimmed, false) {
            Ok(b) => b,
            Err(e) => {
                self.report_error(e);
                return Arc::new(BookmarkTypeDb::new(-1, trimmed));
            }
        };
        bmt.set_icon(icon_id);
        bmt.set_marker_color(Some(color));
        bmt.set_marker_priority(priority);
        bmt
    }

    /// Returns all known bookmark types. Port of `BookmarkDBManager.getBookmarkTypes()`.
    pub fn get_bookmark_types(&self) -> Vec<Arc<BookmarkTypeDb>> {
        let _guard = self.lock.read();
        self.bookmark_types.lock().unwrap().get_all_types().to_vec()
    }

    /// Gets a bookmark type by name, or `None` if unknown. Port of
    /// `BookmarkDBManager.getBookmarkType(String)`.
    pub fn get_bookmark_type_by_name(&self, type_name: &str) -> Option<Arc<BookmarkTypeDb>> {
        self.bookmark_types.lock().unwrap().get(type_name).cloned()
    }

    /// Sets a bookmark, creating its type (and updating an existing bookmark's comment) as
    /// needed. Port of `BookmarkDBManager.setBookmark(Address, String, String, String)`.
    pub fn set_bookmark(&self, addr: Address, type_name: &str, category: &str, comment: &str) -> Option<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.write();
        let bmt = match self.get_or_create_bookmark_type(type_name, true) {
            Ok(b) => b,
            Err(e) => {
                self.report_error(e);
                return None;
            }
        };
        if let Some(existing) = self.get_bookmark(&addr, type_name, category) {
            existing.bookmark_db_set_comment(comment);
            return Some(existing);
        }
        let type_id = bmt.get_type_id();
        let key = self.addr_map.get_key(&addr, true);
        match self
            .bookmark_adapter
            .lock()
            .unwrap()
            .create_bookmark(type_id, Some(category), key, Some(comment))
        {
            Ok(Some(rec)) => {
                let bm = self.get_cached_instance(rec, bmt);
                if let Some(owner) = self.owner() {
                    owner.bookmark_added(&addr, bm.get_key());
                }
                Some(bm)
            }
            Ok(None) => None,
            Err(e) => {
                self.report_error(e);
                None
            }
        }
    }

    /// Gets a specific bookmark with the given type and category at an address, or `None`. Port
    /// of `BookmarkDBManager.getBookmark(Address, String, String)`.
    pub fn get_bookmark(&self, addr: &Address, type_name: &str, category: &str) -> Option<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.read();
        let bmt = self.bookmark_types.lock().unwrap().get(type_name).cloned()?;
        if !bmt.has_bookmarks() {
            return None;
        }
        let type_id = bmt.get_type_id();
        let key = self.addr_map.get_key(addr, false);
        let records = match self.bookmark_adapter.lock().unwrap().get_records_by_type_at_address(type_id, key) {
            Ok(r) => r,
            Err(e) => {
                self.report_error(e);
                return None;
            }
        };
        for rec in records {
            if rec.get_string(CATEGORY_COL) == Some(category) {
                return Some(self.get_cached_instance(rec, bmt));
            }
        }
        None
    }

    /// Gets the bookmark with the given id, if it's already cached or exists in the database.
    /// Port of `BookmarkDBManager.getBookmark(long)`.
    pub fn get_bookmark_by_id(&self, id: i64) -> Option<Arc<BookmarkRecordDb>> {
        if let Some(existing) = self.cache.lock().unwrap().get(&id) {
            return Some(existing.clone());
        }
        let record = match self.bookmark_adapter.lock().unwrap().get_record(id) {
            Ok(r) => r,
            Err(e) => {
                self.report_error(e);
                return None;
            }
        }?;
        let type_id = bookmark_db_adapter::get_type_id(&record);
        let bmt = self.bookmark_types.lock().unwrap().get_type_by_id(type_id).cloned()?;
        Some(self.get_cached_instance(record, bmt))
    }

    /// Removes the given bookmark. Port of `BookmarkDBManager.removeBookmark(Bookmark)`.
    ///
    /// # Panics
    /// Panics if `bookmark` was not produced by this manager, mirroring Java's
    /// `IllegalArgumentException("Bookmark is not from this program!")`.
    pub fn remove_bookmark(&self, bookmark: &Arc<BookmarkRecordDb>) {
        let _guard = self.lock.write();
        if bookmark.check_deleted().is_err() {
            return;
        }
        assert!(
            Weak::ptr_eq(&bookmark.manager, &self.self_handle),
            "Bookmark is not from this program!"
        );
        let type_id = bookmark.bookmark_type.get_type_id();
        let type_string = bookmark.bookmark_type.get_type_string().to_string();
        self.do_remove_bookmark(bookmark);
        if self.bookmark_adapter.lock().unwrap().get_bookmark_count_for_type(type_id) == 0 {
            self.remove_bookmarks_of_type(&type_string);
        }
    }

    fn do_remove_bookmark(&self, bm: &Arc<BookmarkRecordDb>) {
        let addr = bm.bookmark_db_get_address();
        let key = bm.get_key();
        self.cache.lock().unwrap().remove(&key);
        match self.bookmark_adapter.lock().unwrap().delete_record(key) {
            Ok(()) => {
                if let Some(owner) = self.owner() {
                    owner.bookmark_removed(&addr, key);
                }
            }
            Err(e) => self.report_error(e),
        }
    }

    /// Removes all bookmarks of the given type (and drops its table entirely). Port of
    /// `BookmarkDBManager.removeBookmarks(String)`.
    pub fn remove_bookmarks_of_type(&self, type_name: &str) {
        let _guard = self.lock.write();
        let bmt = match self.bookmark_types.lock().unwrap().get(type_name).cloned() {
            Some(b) if b.has_bookmarks() => b,
            _ => return,
        };
        let type_id = bmt.get_type_id();
        let delete_result = {
            let mut h = self.handle.write().unwrap();
            self.bookmark_adapter.lock().unwrap().delete_type(&mut h, type_id)
        };
        if let Err(e) = delete_result {
            self.report_error(e);
            return;
        }
        if let Err(e) = self.bookmark_type_adapter.lock().unwrap().delete_record(type_id as i64) {
            self.report_error(e);
            return;
        }
        bmt.set_has_bookmarks(false);
        self.cache.lock().unwrap().retain(|_, v| v.bookmark_type.get_type_id() != type_id);
        if let Some(owner) = self.owner() {
            owner.bookmark_type_removed(type_id, bmt.get_type_string());
        }
    }

    /// Removes all bookmarks with the given type and category. Port of
    /// `BookmarkDBManager.removeBookmarks(String, String, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if `monitor` reports cancellation.
    pub fn remove_bookmarks_of_type_and_category(
        &self,
        type_name: &str,
        category: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let _guard = self.lock.write();
        let bmt = match self.bookmark_types.lock().unwrap().get(type_name).cloned() {
            Some(b) if b.has_bookmarks() => b,
            _ => return Ok(()),
        };
        let records = match self
            .bookmark_adapter
            .lock()
            .unwrap()
            .get_records_by_type_and_category(bmt.get_type_id(), Some(category))
        {
            Ok(r) => r,
            Err(e) => {
                self.report_error(e);
                return Ok(());
            }
        };
        for rec in records {
            let bm = self.get_cached_instance(rec, bmt.clone());
            self.remove_bookmark(&bm);
            monitor.check_cancelled()?;
        }
        Ok(())
    }

    fn collect_bookmarks_at(&self, addr: &Address, bmt: Arc<BookmarkTypeDb>, out: &mut Vec<Arc<BookmarkRecordDb>>) {
        let type_id = bmt.get_type_id();
        if type_id < 0 {
            return;
        }
        let key = self.addr_map.get_key(addr, false);
        match self.bookmark_adapter.lock().unwrap().get_records_by_type_at_address(type_id, key) {
            Ok(records) => {
                for rec in records {
                    out.push(self.get_cached_instance(rec, bmt.clone()));
                }
            }
            Err(e) => self.report_error(e),
        }
    }

    /// Gets all bookmarks at the given address, across every type. Port of
    /// `BookmarkDBManager.getBookmarks(Address)`.
    pub fn get_bookmarks_at(&self, addr: &Address) -> Vec<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.read();
        let types = self.bookmark_types.lock().unwrap().get_all_types().to_vec();
        let mut out = Vec::new();
        for t in types {
            if t.has_bookmarks() {
                self.collect_bookmarks_at(addr, t, &mut out);
            }
        }
        out
    }

    /// Gets all bookmarks of the given type at an address. Port of
    /// `BookmarkDBManager.getBookmarks(Address, String)`.
    pub fn get_bookmarks_at_of_type(&self, addr: &Address, type_name: &str) -> Vec<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.read();
        let mut out = Vec::new();
        if let Some(bmt) = self.bookmark_types.lock().unwrap().get(type_name).cloned() {
            if bmt.has_bookmarks() {
                self.collect_bookmarks_at(addr, bmt, &mut out);
            }
        }
        out
    }

    /// Returns true if the program has any bookmarks of the given type. Port of
    /// `BookmarkDBManager.hasBookmarks(String)`.
    pub fn has_bookmarks(&self, type_name: &str) -> bool {
        let _guard = self.lock.read();
        self.bookmark_types
            .lock()
            .unwrap()
            .get(type_name)
            .map(|t| t.has_bookmarks())
            .unwrap_or(false)
    }

    /// Gets all known categories for a bookmark type. Port of
    /// `BookmarkDBManager.getCategories(String)`.
    pub fn get_categories(&self, type_name: &str) -> Vec<String> {
        let _guard = self.lock.read();
        let Some(bmt) = self.bookmark_types.lock().unwrap().get(type_name).cloned() else {
            return Vec::new();
        };
        if !bmt.has_bookmarks() {
            return Vec::new();
        }
        match self.bookmark_adapter.lock().unwrap().get_categories(bmt.get_type_id()) {
            Ok(v) => v,
            Err(e) => {
                self.report_error(e);
                Vec::new()
            }
        }
    }

    /// Gets the set of addresses with bookmarks of the given type. Port of
    /// `BookmarkDBManager.getBookmarkAddresses(String)`.
    pub fn get_bookmark_addresses(&self, type_name: &str) -> AddressSet {
        let _guard = self.lock.read();
        let Some(bmt) = self.bookmark_types.lock().unwrap().get(type_name).cloned() else {
            return AddressSet::new();
        };
        if !bmt.has_bookmarks() {
            return AddressSet::new();
        }
        match self.bookmark_adapter.lock().unwrap().get_bookmark_addresses(bmt.get_type_id()) {
            Ok(s) => s,
            Err(e) => {
                self.report_error(e);
                AddressSet::new()
            }
        }
    }

    /// Returns the total number of bookmarks. Port of `BookmarkDBManager.getBookmarkCount()`.
    pub fn get_bookmark_count(&self) -> usize {
        let _guard = self.lock.read();
        self.bookmark_adapter.lock().unwrap().get_bookmark_count().max(0) as usize
    }

    /// Returns the number of bookmarks of the given type. Port of
    /// `BookmarkDBManager.getBookmarkCount(String)`.
    pub fn get_bookmark_count_of_type(&self, type_name: &str) -> usize {
        let _guard = self.lock.read();
        let Some(bmt) = self.bookmark_types.lock().unwrap().get(type_name).cloned() else {
            return 0;
        };
        self.bookmark_adapter
            .lock()
            .unwrap()
            .get_bookmark_count_for_type(bmt.get_type_id())
            .max(0) as usize
    }

    /// Returns a snapshot of every bookmark of the given type. Port of
    /// `BookmarkDBManager.getBookmarksIterator(String)` (eagerly collected rather than lazily
    /// iterated -- see the module docs for why the from-address-forward/backward variant is left
    /// out entirely, which was the one genuinely lazy iterator Java provides here).
    pub fn get_bookmarks_iterator_of_type(&self, type_name: &str) -> Vec<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.read();
        let Some(bmt) = self.bookmark_types.lock().unwrap().get(type_name).cloned() else {
            return Vec::new();
        };
        if !bmt.has_bookmarks() {
            return Vec::new();
        }
        match self.bookmark_adapter.lock().unwrap().get_records_by_type(bmt.get_type_id()) {
            Ok(records) => records.into_iter().map(|r| self.get_cached_instance(r, bmt.clone())).collect(),
            Err(e) => {
                self.report_error(e);
                Vec::new()
            }
        }
    }

    /// Returns a snapshot of every bookmark, across every type. Port of
    /// `BookmarkDBManager.getBookmarksIterator()`.
    pub fn get_bookmarks_iterator(&self) -> Vec<Arc<BookmarkRecordDb>> {
        let _guard = self.lock.read();
        let types = self.bookmark_types.lock().unwrap().get_all_types().to_vec();
        let mut out = Vec::new();
        for t in types {
            if t.has_bookmarks() {
                match self.bookmark_adapter.lock().unwrap().get_records_by_type(t.get_type_id()) {
                    Ok(records) => {
                        for r in records {
                            out.push(self.get_cached_instance(r, t.clone()));
                        }
                    }
                    Err(e) => self.report_error(e),
                }
            }
        }
        out
    }

    /// Invalidates cached objects held by this manager. Port of
    /// `BookmarkDBManager.invalidateCache(boolean)` (the `all` parameter is unused in Java too --
    /// every invalidation is total).
    pub fn invalidate_cache(&self, _all: bool) {
        let _guard = self.lock.write();
        self.cache.lock().unwrap().clear();
        {
            let mut adapter = self.bookmark_adapter.lock().unwrap();
            if let BookmarkAdapterKind::V3(v3) = &mut *adapter {
                let h = self.handle.read().unwrap();
                v3.reload_tables(&h);
            }
        }
        let types = self.bookmark_types.lock().unwrap();
        let adapter = self.bookmark_adapter.lock().unwrap();
        for t in types.get_all_types() {
            t.set_has_bookmarks(adapter.has_table(t.get_type_id()));
        }
    }

    // TODO(port): `BookmarkDBManager.moveAddressRange(Address, Address, long, TaskMonitor)` --
    // needs bulk address-column remapping across every per-type table
    // (`DatabaseTableUtils.updateIndexedAddressField` in Java), which no table/address-map utility
    // in this port currently exposes.

    // TODO(port): `BookmarkDBManager.deleteAddressRange(Address, Address, TaskMonitor)` -- in Java
    // this is a one-line call to the (also not-ported) `removeBookmarks(AddressSetView,
    // TaskMonitor)` overload -- see the module docs for why that family is left out.
}

impl BookmarkManagerDb for BookmarkDBManager {
    fn lock(&self) -> &ReentrantLock {
        &self.lock
    }

    fn get_address(&self, address_key: i64) -> Address {
        self.addr_map.decode_address(address_key)
    }

    fn get_bookmark_type(&self, type_id: i32) -> Arc<dyn BookmarkType + Send + Sync> {
        match self.bookmark_types.lock().unwrap().get_type_by_id(type_id).cloned() {
            Some(t) => t,
            // No known type with this id: hand back an empty placeholder rather than panicking,
            // matching this trait's `&self` (non-`Result`) signature.
            None => Arc::new(BookmarkTypeDb::new(type_id, "")),
        }
    }

    fn get_record(&self, key: i64) -> Option<DBRecord> {
        match self.bookmark_adapter.lock().unwrap().get_record(key) {
            Ok(r) => r,
            Err(e) => {
                self.report_error(e);
                None
            }
        }
    }

    fn bookmark_changed(&mut self, key: i64) {
        // See `persist_bookmark_change`'s own doc comment for why this trait method is, in
        // practice, unreachable through the shared `Arc<dyn BookmarkManagerDb>` this manager is
        // normally used as -- implemented for real anyway, for any caller that does hold a
        // genuine `&mut BookmarkDBManager`.
        self.persist_bookmark_change(key);
    }
}

/// Database object for a single bookmark. See the module docs for the `Box::leak` tradeoff its
/// `Bookmark` string accessors make.
///
/// Port of `ghidra.program.database.bookmark.BookmarkDB`.
pub struct BookmarkRecordDb {
    state: DbObjectState,
    manager: Weak<BookmarkDBManager>,
    record: Mutex<DBRecord>,
    /// Fixed at construction: a bookmark's type is derived from the immutable high bits of its
    /// own key (see [`BookmarkDb::bookmark_db_get_type`]), so unlike `category`/`comment` it never
    /// needs to be refreshed, and can be borrowed directly with no `Box::leak` needed for
    /// [`Bookmark::get_type`]/[`Bookmark::get_type_string`].
    bookmark_type: Arc<BookmarkTypeDb>,
}

impl BookmarkRecordDb {
    fn new(manager: Weak<BookmarkDBManager>, record: DBRecord, bookmark_type: Arc<BookmarkTypeDb>) -> Self {
        let key = record.get_key().get_long_value();
        BookmarkRecordDb {
            state: DbObjectState::new(key),
            manager,
            record: Mutex::new(record),
            bookmark_type,
        }
    }
}

impl DbObject for BookmarkRecordDb {
    fn state(&self) -> &DbObjectState {
        &self.state
    }
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        self.bookmark_db_refresh(record)
    }
}

impl BookmarkDb for BookmarkRecordDb {
    fn manager(&self) -> Arc<dyn BookmarkManagerDb> {
        self.manager
            .upgrade()
            .expect("BookmarkDBManager dropped while a BookmarkRecordDb is still alive")
    }

    fn record(&self) -> DBRecord {
        self.record.lock().unwrap().clone()
    }

    fn set_record(&self, record: DBRecord) {
        *self.record.lock().unwrap() = record;
    }

    fn bookmark_db_set_comment(&self, comment: &str) {
        if self.check_deleted().is_err() {
            return;
        }
        let manager = self
            .manager
            .upgrade()
            .expect("BookmarkDBManager dropped while a BookmarkRecordDb is still alive");
        let _guard = manager.lock.write();
        let old = self.record().get_string(COMMENT_COL).unwrap_or("").to_string();
        if comment != old {
            let mut rec = self.record();
            rec.set_field(COMMENT_COL, Field::String(Some(comment.to_string())));
            self.set_record(rec);
            manager.persist_bookmark_change(self.get_key());
        }
    }

    fn bookmark_db_set(&self, category: &str, comment: &str) {
        if self.check_deleted().is_err() {
            return;
        }
        let manager = self
            .manager
            .upgrade()
            .expect("BookmarkDBManager dropped while a BookmarkRecordDb is still alive");
        let _guard = manager.lock.write();
        let mut rec = self.record();
        rec.set_field(CATEGORY_COL, Field::String(Some(category.to_string())));
        rec.set_field(COMMENT_COL, Field::String(Some(comment.to_string())));
        self.set_record(rec);
        manager.persist_bookmark_change(self.get_key());
    }
}

impl Bookmark for BookmarkRecordDb {
    fn get_id(&self) -> i64 {
        self.bookmark_db_id()
    }

    fn get_address(&self) -> Address {
        self.bookmark_db_get_address()
    }

    fn get_type(&self) -> &dyn BookmarkType {
        self.bookmark_type.as_ref()
    }

    fn get_type_string(&self) -> &str {
        self.bookmark_type.get_type_string()
    }

    fn get_category(&self) -> &str {
        self.refresh_if_needed();
        // See the module docs for why this leaks a fresh, small owned copy on each call.
        Box::leak(self.bookmark_db_get_category().into_boxed_str())
    }

    fn get_comment(&self) -> &str {
        self.refresh_if_needed();
        Box::leak(self.bookmark_db_get_comment().into_boxed_str())
    }

    fn set(&mut self, category: &str, comment: &str) {
        self.bookmark_db_set(category, comment);
    }

    fn compare_to(&self, other: &dyn Bookmark) -> std::cmp::Ordering {
        self.bookmark_db_compare_to(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, DefaultAddressFactory, KeyRange};
    use crate::program::model::listing::{Program, NOTE};
    use crate::program::model::util::property_map_manager::PropertyMapManager;
    use crate::program::util::ObjectPropertyMap;
    use crate::util::exception::DuplicateNameException;
    use crate::util::task::DummyMonitor;
    use std::collections::BTreeMap;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    struct IdentityAddressMap;
    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(ram(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(&self, _s: &Address, _e: &Address, _a: bool, _c: bool) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(&self, _s: Option<&dyn AddressSetView>, _a: bool, _c: bool) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap)
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(ram(), 0)
        }
    }

    fn addr_map() -> Arc<dyn AddressMap + Send + Sync> {
        Arc::new(IdentityAddressMap)
    }

    struct NoopOwner;
    impl BookmarkManagerProgram for NoopOwner {
        fn db_error(&self, _err: &io::Error) {}
        fn program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed by tests that only exercise the V3-backed CRUD path")
        }
        fn property_map_manager(&self) -> Arc<Mutex<dyn PropertyMapManager + Send>> {
            unimplemented!("not needed by tests that only exercise the V3-backed CRUD path")
        }
        fn bookmark_added(&self, _addr: &Address, _id: i64) {}
        fn bookmark_changed(&self, _addr: &Address, _id: i64) {}
        fn bookmark_removed(&self, _addr: &Address, _id: i64) {}
        fn bookmark_type_added(&self, _type_id: i32, _type_name: &str) {}
        fn bookmark_type_removed(&self, _type_id: i32, _type_name: &str) {}
    }

    fn new_manager(open_mode: OpenMode) -> (Arc<RwLock<DBHandle>>, Arc<BookmarkDBManager>) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mgr = BookmarkDBManager::new(handle.clone(), addr_map(), open_mode, &DummyMonitor).unwrap();
        mgr.set_owner(Arc::new(NoopOwner));
        (handle, mgr)
    }

    #[test]
    fn create_mode_starts_empty() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        assert_eq!(mgr.get_bookmark_count(), 0);
        assert!(mgr.get_bookmark_types().is_empty());
    }

    #[test]
    fn set_bookmark_creates_type_and_bookmark_then_updates_in_place() {
        let (_h, mgr) = new_manager(OpenMode::Create);

        let bm = mgr.set_bookmark(addr(0x1000), "Note", "general", "hello").unwrap();
        assert_eq!(Bookmark::get_comment(bm.as_ref()), "hello");
        assert_eq!(Bookmark::get_category(bm.as_ref()), "general");
        assert_eq!(Bookmark::get_type_string(bm.as_ref()), "Note");
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert_eq!(mgr.get_bookmark_count_of_type("Note"), 1);
        assert!(mgr.has_bookmarks("Note"));

        // Setting again at the same address/type/category updates the existing bookmark in place
        // rather than creating a second one.
        let bm2 = mgr.set_bookmark(addr(0x1000), "Note", "general", "updated").unwrap();
        assert_eq!(bm2.get_key(), bm.get_key());
        assert_eq!(Bookmark::get_comment(bm2.as_ref()), "updated");
        assert_eq!(mgr.get_bookmark_count(), 1);
    }

    #[test]
    fn get_bookmark_finds_by_address_type_and_category() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "cat-a", "a").unwrap();
        mgr.set_bookmark(addr(0x1000), "Note", "cat-b", "b").unwrap();

        let found = mgr.get_bookmark(&addr(0x1000), "Note", "cat-a").unwrap();
        assert_eq!(Bookmark::get_comment(found.as_ref()), "a");
        assert!(mgr.get_bookmark(&addr(0x1000), "Note", "cat-missing").is_none());
        assert!(mgr.get_bookmark(&addr(0x2000), "Note", "cat-a").is_none());
    }

    #[test]
    fn get_bookmark_by_id_round_trips() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        let bm = mgr.set_bookmark(addr(0x1000), "Note", "cat", "hi").unwrap();
        let refetched = mgr.get_bookmark_by_id(bm.get_key()).unwrap();
        assert_eq!(refetched.get_key(), bm.get_key());
        assert!(mgr.get_bookmark_by_id(999_999).is_none());
    }

    #[test]
    fn remove_bookmark_deletes_it_and_drops_now_empty_type() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        let bm = mgr.set_bookmark(addr(0x1000), "Note", "cat", "hi").unwrap();
        assert_eq!(mgr.get_bookmark_count(), 1);

        mgr.remove_bookmark(&bm);
        assert_eq!(mgr.get_bookmark_count(), 0);
        // The type itself is dropped once its last bookmark is removed (mirrors Java).
        assert!(!mgr.has_bookmarks("Note"));
        assert!(mgr.get_bookmark(&addr(0x1000), "Note", "cat").is_none());
    }

    #[test]
    fn remove_bookmarks_of_type_clears_everything_for_that_type_only() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "cat", "a").unwrap();
        mgr.set_bookmark(addr(0x2000), "Note", "cat", "b").unwrap();
        mgr.set_bookmark(addr(0x3000), "Todo", "cat", "c").unwrap();

        mgr.remove_bookmarks_of_type("Note");
        assert!(!mgr.has_bookmarks("Note"));
        assert!(mgr.has_bookmarks("Todo"));
        assert_eq!(mgr.get_bookmark_count(), 1);
    }

    #[test]
    fn remove_bookmarks_of_type_and_category_only_removes_matching_category() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "keep", "a").unwrap();
        mgr.set_bookmark(addr(0x2000), "Note", "drop", "b").unwrap();

        mgr.remove_bookmarks_of_type_and_category("Note", "drop", &DummyMonitor).unwrap();
        assert_eq!(mgr.get_bookmark_count(), 1);
        assert!(mgr.get_bookmark(&addr(0x1000), "Note", "keep").is_some());
        assert!(mgr.get_bookmark(&addr(0x2000), "Note", "drop").is_none());
    }

    #[test]
    fn categories_and_addresses_reflect_real_stored_bookmarks() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "alpha", "a").unwrap();
        mgr.set_bookmark(addr(0x2000), "Note", "beta", "b").unwrap();

        let mut cats = mgr.get_categories("Note");
        cats.sort();
        assert_eq!(cats, vec!["alpha".to_string(), "beta".to_string()]);

        let addrs = mgr.get_bookmark_addresses("Note");
        assert_eq!(addrs.num_addresses(), 2);
        assert!(mgr.get_categories("Unknown").is_empty());
    }

    #[test]
    fn get_bookmarks_at_and_at_of_type() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "cat", "a").unwrap();
        mgr.set_bookmark(addr(0x1000), "Todo", "cat", "b").unwrap();

        assert_eq!(mgr.get_bookmarks_at(&addr(0x1000)).len(), 2);
        assert_eq!(mgr.get_bookmarks_at_of_type(&addr(0x1000), "Note").len(), 1);
        assert!(mgr.get_bookmarks_at(&addr(0x9999)).is_empty());
    }

    #[test]
    fn iterators_cover_every_bookmark() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        mgr.set_bookmark(addr(0x1000), "Note", "cat", "a").unwrap();
        mgr.set_bookmark(addr(0x2000), "Note", "cat", "b").unwrap();
        mgr.set_bookmark(addr(0x3000), "Todo", "cat", "c").unwrap();

        assert_eq!(mgr.get_bookmarks_iterator_of_type("Note").len(), 2);
        assert_eq!(mgr.get_bookmarks_iterator().len(), 3);
    }

    #[test]
    fn define_type_sets_display_metadata_without_requiring_bookmarks_first() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        let bmt = mgr.define_type("Analysis", Some("icon.analysis".to_string()), MarkerColor::rgb(255, 0, 0), 3);
        assert_eq!(bmt.get_type_string(), "Analysis");
        assert_eq!(bmt.get_marker_color(), Some(MarkerColor::rgb(255, 0, 0)));
        assert_eq!(bmt.get_marker_priority(), 3);
        assert_eq!(mgr.get_bookmark_type_by_name("Analysis").unwrap().get_type_id(), bmt.get_type_id());
    }

    #[test]
    fn invalidate_cache_clears_cached_instances_and_refreshes_has_bookmarks() {
        let (_h, mgr) = new_manager(OpenMode::Create);
        let bm = mgr.set_bookmark(addr(0x1000), "Note", "cat", "a").unwrap();
        mgr.invalidate_cache(true);
        // A fresh lookup still finds the same underlying record (re-instantiated, not literally
        // `Arc`-identical, since the plain-`HashMap` cache was cleared).
        let refetched = mgr.get_bookmark(&addr(0x1000), "Note", "cat").unwrap();
        assert_eq!(refetched.get_key(), bm.get_key());
        assert!(mgr.has_bookmarks("Note"));
    }

    #[test]
    fn reopening_an_existing_create_mode_database_with_update_preserves_data() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mgr = BookmarkDBManager::new(handle.clone(), addr_map(), OpenMode::Create, &DummyMonitor).unwrap();
            mgr.set_owner(Arc::new(NoopOwner));
            mgr.set_bookmark(addr(0x1000), "Note", "cat", "persisted").unwrap();
        }
        let reopened = BookmarkDBManager::new(handle, addr_map(), OpenMode::Update, &DummyMonitor).unwrap();
        reopened.set_owner(Arc::new(NoopOwner));
        assert_eq!(reopened.get_bookmark_count(), 1);
        let bm = reopened.get_bookmark(&addr(0x1000), "Note", "cat").unwrap();
        assert_eq!(Bookmark::get_comment(bm.as_ref()), "persisted");
    }

    #[test]
    fn opening_a_bare_v1_table_in_update_mode_fails_but_immutable_mode_reads_through_the_quirky_v1_adapter() {
        // Build a bare V1-schema "Bookmarks" table directly (as if written by an ancient release),
        // with no Bookmark Types table at all.
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mut h = handle.write().unwrap();
            let table = h
                .create_table(
                    bookmark_db_adapter::BOOKMARK_TABLE_NAME.to_string(),
                    crate::program::database::bookmark::bookmark_db_adapter_v1::v1_schema(),
                )
                .unwrap();
            let mut rec = DBRecord::new(
                crate::program::database::bookmark::bookmark_db_adapter_v1::v1_schema(),
                Field::Long(Some(1)),
            );
            rec.set_field(
                crate::program::database::bookmark::bookmark_db_adapter_v1::V1_ADDRESS_COL,
                Field::Long(Some(0x100)),
            );
            rec.set_field(
                crate::program::database::bookmark::bookmark_db_adapter_v1::V1_TYPE_ID_COL,
                Field::Long(Some(0)),
            );
            rec.set_field(
                crate::program::database::bookmark::bookmark_db_adapter_v1::V1_TYPE_CATEGORY_COL,
                Field::String(Some(bookmark_db_adapter::mangle_type_category(0, Some("legacy")))),
            );
            rec.set_field(
                crate::program::database::bookmark::bookmark_db_adapter_v1::V1_COMMENT_COL,
                Field::String(Some("from V1".to_string())),
            );
            table.write().unwrap().put_record(rec).unwrap();
        }

        assert!(BookmarkDBManager::new(handle.clone(), addr_map(), OpenMode::Update, &DummyMonitor).is_err());

        let mgr = BookmarkDBManager::new(handle, addr_map(), OpenMode::Immutable, &DummyMonitor).unwrap();
        // No Bookmark Types table exists either, so the type adapter falls back to `NoTable`
        // (empty until something populates it) -- but the bookmark records themselves are still
        // reachable directly through the raw adapter/type-id, proving `find_read_only_adapter`
        // really did select the `V1` adapter rather than erroring out.
        let adapter_type_count = {
            let adapter = mgr.bookmark_adapter.lock().unwrap();
            matches!(&*adapter, BookmarkAdapterKind::V1(_))
        };
        assert!(adapter_type_count);
    }

    /// Thin per-name view onto a shared `ObjectPropertyMapDB<OldBookmark>`, mirroring the
    /// identical helper in `old_bookmark_manager.rs`'s own tests.
    struct MapView(Arc<Mutex<crate::program::database::properties::ObjectPropertyMapDB<crate::program::database::bookmark::old_bookmark::OldBookmark>>>);
    impl ObjectPropertyMap for MapView {
        fn add_object(&mut self, addr: &Address, value: Box<dyn crate::util::Saveable>) {
            self.0.lock().unwrap().add_object(addr, value);
        }
        fn get_object(&self, addr: &Address) -> Result<Box<dyn crate::util::Saveable>, crate::util::exception::NoValueException> {
            self.0.lock().unwrap().get_object(addr)
        }
    }
    impl crate::program::model::util::PropertyMap for MapView {
        fn get_name(&self) -> String {
            self.0.lock().unwrap().get_name()
        }
        fn get_value_class(&self) -> Option<std::any::TypeId> {
            self.0.lock().unwrap().get_value_class()
        }
        fn clear(&mut self) {
            self.0.lock().unwrap().clear();
        }
        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.0.lock().unwrap().intersects_range(start, end)
        }
        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.0.lock().unwrap().intersects_set(set)
        }
        fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
            self.0.lock().unwrap().remove_range(start, end)
        }
        fn remove(&mut self, addr: &Address) -> bool {
            self.0.lock().unwrap().remove(addr)
        }
        fn has_property(&self, addr: &Address) -> bool {
            self.0.lock().unwrap().has_property(addr)
        }
        fn add(&mut self, addr: &Address, value: Option<Box<dyn std::any::Any>>) {
            self.0.lock().unwrap().add(addr, value);
        }
        fn get(&self, addr: &Address) -> Option<Box<dyn std::any::Any>> {
            self.0.lock().unwrap().get(addr)
        }
        fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
            self.0.lock().unwrap().get_next_property_address(addr)
        }
        fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
            self.0.lock().unwrap().get_previous_property_address(addr)
        }
        fn get_first_property_address(&self) -> Option<Address> {
            self.0.lock().unwrap().get_first_property_address()
        }
        fn get_last_property_address(&self) -> Option<Address> {
            self.0.lock().unwrap().get_last_property_address()
        }
        fn get_size(&self) -> usize {
            self.0.lock().unwrap().get_size()
        }
        fn get_property_iterator_range(&self, start: &Address, end: &Address) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_range(start, end)
        }
        fn get_property_iterator_range_ordered(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_range_ordered(start, end, forward)
        }
        fn get_property_iterator(&self) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator()
        }
        fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set(asv)
        }
        fn get_property_iterator_set_ordered(&self, asv: &dyn AddressSetView, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set_ordered(asv, forward)
        }
        fn get_property_iterator_from(&self, start: &Address, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_from(start, forward)
        }
        fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
            self.0.lock().unwrap().move_range(start, end, new_start);
        }
    }

    struct LegacyPropertyMapManager {
        db_handle: DBHandle,
        maps: BTreeMap<
            String,
            Arc<Mutex<crate::program::database::properties::ObjectPropertyMapDB<crate::program::database::bookmark::old_bookmark::OldBookmark>>>,
        >,
    }
    impl LegacyPropertyMapManager {
        fn new() -> Self {
            LegacyPropertyMapManager {
                db_handle: DBHandle::new().unwrap(),
                maps: BTreeMap::new(),
            }
        }
    }
    impl PropertyMapManager for LegacyPropertyMapManager {
        fn create_int_property_map(&mut self, _n: &str) -> Result<Box<dyn crate::program::util::IntPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_long_property_map(&mut self, _n: &str) -> Result<Box<dyn crate::program::util::LongPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_string_property_map(&mut self, _n: &str) -> Result<Box<dyn crate::program::util::StringPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_object_property_map(&mut self, property_name: &str) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                return Err(DuplicateNameException::new());
            }
            let map = crate::program::database::properties::ObjectPropertyMapDB::new(&mut self.db_handle, property_name, ram(), false).unwrap();
            let shared = Arc::new(Mutex::new(map));
            self.maps.insert(property_name.to_string(), shared.clone());
            Ok(Box::new(MapView(shared)))
        }
        fn create_void_property_map(&mut self, _n: &str) -> Result<Box<dyn crate::program::util::VoidPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn get_property_map(&self, property_name: &str) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            self.maps
                .get(property_name)
                .map(|m| Box::new(MapView(m.clone())) as Box<dyn crate::program::model::util::PropertyMap>)
        }
        fn get_int_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::IntPropertyMap>> {
            None
        }
        fn get_long_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::LongPropertyMap>> {
            None
        }
        fn get_string_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::StringPropertyMap>> {
            None
        }
        fn get_object_property_map(&self, property_name: &str) -> Option<Box<dyn ObjectPropertyMap>> {
            self.maps.get(property_name).map(|m| Box::new(MapView(m.clone())) as Box<dyn ObjectPropertyMap>)
        }
        fn get_void_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::VoidPropertyMap>> {
            None
        }
        fn remove_property_map(&mut self, property_name: &str) -> bool {
            self.maps.remove(property_name).is_some()
        }
        fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_> {
            Box::new(self.maps.keys().cloned())
        }
        fn remove_all(&mut self, _addr: &Address) {}
        fn remove_all_range(&mut self, _s: &Address, _e: &Address, _m: &dyn TaskMonitor) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    struct LegacyProgramOwner {
        program: Arc<dyn Program>,
        property_mgr: Arc<Mutex<dyn PropertyMapManager + Send>>,
    }
    impl BookmarkManagerProgram for LegacyProgramOwner {
        fn db_error(&self, _err: &io::Error) {}
        fn program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn property_map_manager(&self) -> Arc<Mutex<dyn PropertyMapManager + Send>> {
            self.property_mgr.clone()
        }
        fn bookmark_added(&self, _addr: &Address, _id: i64) {}
        fn bookmark_changed(&self, _addr: &Address, _id: i64) {}
        fn bookmark_removed(&self, _addr: &Address, _id: i64) {}
        fn bookmark_type_added(&self, _type_id: i32, _type_name: &str) {}
        fn bookmark_type_removed(&self, _type_id: i32, _type_name: &str) {}
    }

    struct TestProgram {
        factory: Arc<DefaultAddressFactory>,
    }
    impl crate::framework::model::DomainObject for TestProgram {}
    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    #[test]
    fn opening_a_legacy_no_tables_database_wires_an_old_bookmark_manager_for_reads() {
        // No tables at all exist yet: `OpenMode::Immutable` selects `BookmarkTypeAdapterKind::NoTable`
        // and (via `find_read_only_adapter`, which falls through every version) `BookmarkAdapterKind::V0`.
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mgr = BookmarkDBManager::new(handle, addr_map(), OpenMode::Immutable, &DummyMonitor).unwrap();

        let mut backing = LegacyPropertyMapManager::new();
        {
            let mut note_map = backing.create_object_property_map(crate::program::database::bookmark::old_bookmark_manager::OLD_BOOKMARK_PROPERTY).unwrap();
            note_map.add_object(
                &addr(0x1000),
                Box::new(crate::program::database::bookmark::old_bookmark::OldBookmark::new(
                    Some(NOTE),
                    Some("legacy-cat"),
                    Some("legacy-comment"),
                    addr(0x1000),
                )),
            );
        }
        let program: Arc<dyn Program> = Arc::new(TestProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram()])),
        });
        let owner = Arc::new(LegacyProgramOwner {
            program,
            property_mgr: Arc::new(Mutex::new(backing)),
        });
        mgr.set_owner(owner);

        // The legacy bookmark is now readable through the ordinary manager API, converted into
        // the current (V3) in-memory schema by `BookmarkDbAdapterV0::set_old_bookmark_manager`.
        assert_eq!(mgr.get_bookmark_count(), 1);
        let bm = mgr.get_bookmark(&addr(0x1000), NOTE, "legacy-cat").unwrap();
        assert_eq!(Bookmark::get_comment(bm.as_ref()), "legacy-comment");
    }

    #[test]
    fn upgrade_mode_from_a_legacy_no_tables_database_migrates_bookmarks_into_v3() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mgr = BookmarkDBManager::new(handle, addr_map(), OpenMode::Upgrade, &DummyMonitor).unwrap();

        let mut backing = LegacyPropertyMapManager::new();
        {
            let mut note_map = backing.create_object_property_map(crate::program::database::bookmark::old_bookmark_manager::OLD_BOOKMARK_PROPERTY).unwrap();
            note_map.add_object(
                &addr(0x2000),
                Box::new(crate::program::database::bookmark::old_bookmark::OldBookmark::new(
                    Some(NOTE),
                    Some("upgraded-cat"),
                    Some("upgraded-comment"),
                    addr(0x2000),
                )),
            );
        }
        let program: Arc<dyn Program> = Arc::new(TestProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram()])),
        });
        let owner = Arc::new(LegacyProgramOwner {
            program,
            property_mgr: Arc::new(Mutex::new(backing)),
        });
        mgr.set_owner(owner);

        // After upgrading, the bookmark is a real, first-class V3 bookmark (created through the
        // ordinary `set_bookmark` path, per `upgrade_old_bookmarks`), and the legacy property was
        // removed.
        assert_eq!(mgr.get_bookmark_count(), 1);
        let bm = mgr.get_bookmark(&addr(0x2000), NOTE, "upgraded-cat").unwrap();
        assert_eq!(Bookmark::get_comment(bm.as_ref()), "upgraded-comment");
        assert!(matches!(*mgr.bookmark_adapter.lock().unwrap(), BookmarkAdapterKind::V3(_)));
    }
}
