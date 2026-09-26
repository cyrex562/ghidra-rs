//! Port of `ghidra.program.database.function.FunctionTagDB`, mirroring
//! [`VariableDb`](crate::program::database::function::VariableDb)'s shape: a `pub trait
//! FunctionTagDb: FunctionTag + DbObject` with `function_tag_db_*`-prefixed default methods where
//! a real algorithm applies, and required methods where the Java body needs `&mut self` access to
//! the owning manager through what this trait can only offer as a shared `Arc`.
//!
//! `FunctionTagDB extends DbObject implements FunctionTag`, modeled by extending both already-
//! ported traits directly (mirroring [`FunctionDb`](crate::program::database::function::FunctionDb)'s
//! identical `Function + DbObject` relationship). The `mgr`/`record` fields are exposed as required
//! accessors ([`FunctionTagDb::manager`]/[`FunctionTagDb::record`]/[`FunctionTagDb::set_record`]).
//!
//! [`id`](FunctionTagDb::function_tag_db_id) and
//! [`refresh`](FunctionTagDb::function_tag_db_refresh) (`DbObject::refresh`'s real body) get full
//! defaults: `refresh` only calls `FunctionTagManagerDb::get_tag_record`/`ErrorHandler::db_error`,
//! both `&self` on [`FunctionTagManagerDb`](crate::program::database::function::FunctionTagManagerDb),
//! so no `&mut` friction applies there.
//!
//! [`get_comment`](FunctionTagDb::function_tag_db_get_comment)/[`get_name`](FunctionTagDb::function_tag_db_get_name)
//! also get full defaults, but return an owned `String` rather than the `&str`
//! [`FunctionTag::name`]/[`FunctionTag::comment`] require: a `&str` tied to `&self` cannot be
//! extracted from a record fetched by value (as [`FunctionTagDb::record`] does, to avoid a lock
//! guard whose lifetime does not outlive the accessor), so a concrete `impl FunctionTag for Foo`
//! is expected to bridge the owned `String` these return into whatever `&str`-yielding storage it
//! prefers (e.g. a cached plain `String` field kept in sync with the record, refreshed together).
//!
//! [`set_comment`](FunctionTagDb::function_tag_db_set_comment)/
//! [`set_name`](FunctionTagDb::function_tag_db_set_name)/[`delete`](FunctionTagDb::function_tag_db_delete)
//! are left required (see each method's own doc): their Java bodies call
//! `FunctionTagManagerDB.updateFunctionTag`/`doDeleteTag`, both `&mut self` on
//! [`FunctionTagManagerDb`], unreachable from a `&self` default through a shared `Arc` -- the same
//! friction [`VariableDb::variable_db_set_comment`](crate::program::database::function::VariableDb::variable_db_set_comment)
//! documents.
//!
//! [`compare_to`](FunctionTagDb::function_tag_db_compare_to) gets a full default, reaching
//! `self.name()`/`self.comment()` through the `FunctionTag` supertrait bound (ordinary virtual
//! dispatch to the concrete implementor, exactly like
//! [`VariableDb::variable_db_compare_to`](crate::program::database::function::VariableDb::variable_db_compare_to)
//! reaches `self.get_data_type()` etc.).
//!
//! Left out, matching [`FunctionDb`]'s identical note: `equals`/`hashCode`/`toString` (no `Object`
//! identity contract in Rust; [`FunctionTag`] has no `is_equivalent`-style method to fill that role
//! since Java's `equals` here is a plain name/comment value comparison callers can already do via
//! `name()`/`comment()` directly), and the package-private constructor/`getRecord()` accessor
//! (superseded by [`FunctionTagDb::record`]).

use std::cmp::Ordering;
use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::db_object::DbObject;
use crate::program::database::function::function_tag_adapter::{COMMENT_COL, NAME_COL};
use crate::program::database::function::FunctionTagManagerDb;
use crate::program::model::listing::FunctionTag;

/// Database object for [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter)
/// records.
///
/// Port of `ghidra.program.database.function.FunctionTagDB`. See the module docs for the
/// default-vs-required method split and everything intentionally left out.
pub trait FunctionTagDb: FunctionTag + DbObject {
    /// Backing storage for the `mgr` field.
    fn manager(&self) -> Arc<dyn FunctionTagManagerDb>;

    /// Backing storage for the `record` field, returned by value (see the module docs for why).
    fn record(&self) -> DBRecord;

    /// Update the backing storage for the `record` field.
    fn set_record(&self, record: DBRecord);

    /// Default body for [`FunctionTag::id`]. Port of `FunctionTagDB.getId()` (`return key;`).
    fn function_tag_db_id(&self) -> i64 {
        self.get_key()
    }

    /// Default body for `DbObject::refresh`. Port of `FunctionTagDB.refresh(DBRecord)`.
    fn function_tag_db_refresh(&self, record: Option<&DBRecord>) -> bool {
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => match self.manager().get_tag_record(self.get_key()) {
                Ok(r) => r,
                Err(e) => {
                    self.manager().db_error(e);
                    None
                }
            },
        };
        match rec {
            Some(r) => {
                self.set_record(r);
                true
            }
            None => false,
        }
    }

    /// Default body backing [`FunctionTag::comment`]. Port of `FunctionTagDB.getComment()`,
    /// returning an owned `String` rather than `&str` (see the module docs).
    fn function_tag_db_get_comment(&self) -> String {
        self.refresh_if_needed();
        self.record().get_string(COMMENT_COL).unwrap_or("").to_string()
    }

    /// Default body backing [`FunctionTag::name`]. Port of `FunctionTagDB.getName()`, returning
    /// an owned `String` rather than `&str` (see the module docs).
    fn function_tag_db_get_name(&self) -> String {
        self.refresh_if_needed();
        self.record().get_string(NAME_COL).unwrap_or("").to_string()
    }

    /// Required body for [`FunctionTag::set_comment`]. Port of
    /// `FunctionTagDB.setComment(String)`:
    /// ```java
    /// public void setComment(String comment) {
    ///     try (Closeable c = mgr.lock.write()) {
    ///         checkDeleted();
    ///         if (comment == null) comment = "";
    ///         String oldValue = record.getString(FunctionTagAdapter.COMMENT_COL);
    ///         if (!comment.equals(oldValue)) {
    ///             record.setString(FunctionTagAdapter.COMMENT_COL, comment);
    ///             mgr.updateFunctionTag(this, oldValue, comment);
    ///         }
    ///     }
    ///     catch (IOException e) {
    ///         mgr.dbError(e);
    ///     }
    /// }
    /// ```
    /// Left required (see module docs): `FunctionTagManagerDb::update_function_tag` is `&mut
    /// self`, unreachable from a `&self` default through the shared `Arc<dyn FunctionTagManagerDb>`
    /// [`FunctionTagDb::manager`] returns. A concrete implementor should call
    /// [`DbObject::check_deleted`] first, then mutate its stored record's
    /// [`COMMENT_COL`](crate::program::database::function::function_tag_adapter::COMMENT_COL) via
    /// [`FunctionTagDb::set_record`] and call `FunctionTagManagerDb::update_function_tag` if the
    /// value actually changed.
    fn function_tag_db_set_comment(&self, comment: &str);

    /// Required body for [`FunctionTag::set_name`]. Port of `FunctionTagDB.setName(String)`, the
    /// mirror image of [`FunctionTagDb::function_tag_db_set_comment`] (same required-method
    /// rationale; operates on
    /// [`NAME_COL`](crate::program::database::function::function_tag_adapter::NAME_COL) instead).
    fn function_tag_db_set_name(&self, name: &str);

    /// Required body for [`FunctionTag::delete`]. Port of `FunctionTagDB.delete()`:
    /// ```java
    /// public void delete() {
    ///     try (Closeable c = mgr.lock.write()) {
    ///         if (refreshIfNeeded()) {
    ///             mgr.doDeleteTag(this);
    ///         }
    ///     }
    ///     catch (IOException e) {
    ///         mgr.dbError(e);
    ///     }
    /// }
    /// ```
    /// Left required for the same reason as
    /// [`FunctionTagDb::function_tag_db_set_comment`]: `FunctionTagManagerDb::do_delete_tag` is
    /// `&mut self`. A concrete implementor should call `DbObject::refresh_if_needed` and, if it
    /// returns `true`, call `FunctionTagManagerDb::do_delete_tag(self.id())`.
    fn function_tag_db_delete(&self);

    /// Default body for [`FunctionTag::compare_to`]. Port of `FunctionTagDB.compareTo(FunctionTag)`
    /// (`String.compareToIgnoreCase`, approximated here via ASCII/Unicode lowercasing).
    fn function_tag_db_compare_to(&self, other: &dyn FunctionTag) -> Ordering {
        let rc = self.name().to_lowercase().cmp(&other.name().to_lowercase());
        if rc != Ordering::Equal {
            return rc;
        }
        self.comment().to_lowercase().cmp(&other.comment().to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io;

    use crate::framework::db::{Field, FieldType, Schema};
    use crate::framework::db::util::ErrorHandler;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::listing::FunctionTagManager;
    use crate::program::seam_stubs::FunctionTagManagerProgram;

    fn tag_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String, FieldType::String],
            vec!["Tag".to_string(), "Comment".to_string()],
            vec![],
        ))
    }

    /// Minimal in-memory [`FunctionTagManagerDb`], sufficient to exercise [`FunctionTagDb`]'s
    /// default and required methods.
    struct MockManager {
        records: RefCell<std::collections::HashMap<i64, DBRecord>>,
        update_calls: Cell<u32>,
        delete_calls: Cell<u32>,
    }

    impl FunctionTagManager for MockManager {
        fn get_function_tag_by_name(&self, _name: &str) -> Option<&dyn FunctionTag> {
            None
        }
        fn get_function_tag_by_id(&self, _id: i64) -> Option<&dyn FunctionTag> {
            None
        }
        fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag> {
            Vec::new()
        }
        fn is_tag_assigned(&self, _name: &str) -> bool {
            false
        }
        fn create_function_tag(&mut self, _name: &str, _comment: &str) -> &dyn FunctionTag {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_use_count(&self, _tag: &dyn FunctionTag) -> usize {
            0
        }
    }

    impl ErrorHandler for MockManager {
        fn db_error(&self, _e: io::Error) {}
    }

    impl FunctionTagManagerDb for MockManager {
        fn set_program(&mut self, _program: Arc<dyn FunctionTagManagerProgram>) {}
        fn is_tag_applied(&self, _function_id: i64, _tag_id: i64) -> bool {
            false
        }
        fn apply_function_tag(&mut self, _function_id: i64, _tag_id: i64) {}
        fn remove_function_tag(&mut self, _function_id: i64, _tag_id: i64) -> bool {
            false
        }
        fn update_function_tag(&mut self, record: &DBRecord, _old_value: &str, _new_value: &str) -> io::Result<()> {
            self.update_calls.set(self.update_calls.get() + 1);
            let Field::Long(Some(id)) = record.get_key() else {
                return Ok(());
            };
            self.records.borrow_mut().insert(*id, record.clone());
            Ok(())
        }
        fn get_tag_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.borrow().get(&id).cloned())
        }
        fn do_delete_tag(&mut self, id: i64) -> io::Result<()> {
            self.delete_calls.set(self.delete_calls.get() + 1);
            self.records.borrow_mut().remove(&id);
            Ok(())
        }
        fn get_function_tags_by_function_id(&self, _function_id: i64) -> io::Result<Vec<&dyn FunctionTag>> {
            Ok(Vec::new())
        }
        fn invalidate_cache(&mut self) {}
    }

    /// Minimal [`FunctionTagDb`] implementor. `name`/`comment` cache the current record's columns
    /// in plain owned fields refreshed alongside `record`, bridging the owned-`String`-vs-`&str`
    /// gap the module docs describe.
    struct MockFunctionTagDb {
        state: DbObjectState,
        manager: Arc<Mutex<MockManager>>,
        record: Mutex<DBRecord>,
        name: Mutex<String>,
        comment: Mutex<String>,
    }

    use std::sync::Mutex;

    impl MockFunctionTagDb {
        fn new(manager: Arc<Mutex<MockManager>>, id: i64, name: &str, comment: &str) -> Self {
            let mut record = DBRecord::new(tag_schema(), Field::Long(Some(id)));
            record.set_string(NAME_COL, Some(name.to_string()));
            record.set_string(COMMENT_COL, Some(comment.to_string()));
            manager.lock().unwrap().records.borrow_mut().insert(id, record.clone());
            MockFunctionTagDb {
                state: DbObjectState::new(id),
                manager,
                record: Mutex::new(record),
                name: Mutex::new(name.to_string()),
                comment: Mutex::new(comment.to_string()),
            }
        }
    }

    impl DbObject for MockFunctionTagDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }
        fn refresh(&self, record: Option<&DBRecord>) -> bool {
            self.function_tag_db_refresh(record)
        }
    }

    impl FunctionTagDb for MockFunctionTagDb {
        fn manager(&self) -> Arc<dyn FunctionTagManagerDb> {
            // `Arc<Mutex<MockManager>>` can't itself be handed out as `Arc<dyn
            // FunctionTagManagerDb>` (the trait's methods take `&self`/`&mut self`, not through a
            // `Mutex`), so route every manager call needed by this test through
            // `self.manager.lock()` directly instead of through this accessor. Exercised only by
            // `function_tag_db_refresh`'s `&self`-only calls, bridged via a thin wrapper below.
            Arc::new(ManagerRef(self.manager.clone()))
        }
        fn record(&self) -> DBRecord {
            self.record.lock().unwrap().clone()
        }
        fn set_record(&self, record: DBRecord) {
            if let Some(name) = record.get_string(NAME_COL) {
                *self.name.lock().unwrap() = name.to_string();
            }
            if let Some(comment) = record.get_string(COMMENT_COL) {
                *self.comment.lock().unwrap() = comment.to_string();
            }
            *self.record.lock().unwrap() = record;
        }
        fn function_tag_db_set_comment(&self, comment: &str) {
            if self.check_deleted().is_err() {
                return;
            }
            let old_value = self.record().get_string(COMMENT_COL).unwrap_or("").to_string();
            if comment != old_value {
                let mut rec = self.record();
                rec.set_string(COMMENT_COL, Some(comment.to_string()));
                self.manager
                    .lock()
                    .unwrap()
                    .update_function_tag(&rec, &old_value, comment)
                    .unwrap();
                self.set_record(rec);
            }
        }
        fn function_tag_db_set_name(&self, name: &str) {
            if self.check_deleted().is_err() {
                return;
            }
            let old_value = self.record().get_string(NAME_COL).unwrap_or("").to_string();
            if name != old_value {
                let mut rec = self.record();
                rec.set_string(NAME_COL, Some(name.to_string()));
                self.manager
                    .lock()
                    .unwrap()
                    .update_function_tag(&rec, &old_value, name)
                    .unwrap();
                self.set_record(rec);
            }
        }
        fn function_tag_db_delete(&self) {
            if self.refresh_if_needed() {
                self.manager.lock().unwrap().do_delete_tag(self.get_key()).unwrap();
            }
        }
    }

    /// Thin `&dyn FunctionTagManagerDb` view over `Arc<Mutex<MockManager>>`, used only so
    /// [`FunctionTagDb::function_tag_db_refresh`]'s `&self`-only calls
    /// (`get_tag_record`/`db_error`) can reach the mutex-guarded mock manager. This test mock's
    /// own `&mut self` calls (`update_function_tag`/`do_delete_tag`) go through `self.manager.lock()`
    /// directly instead (see `manager()`'s doc comment above).
    struct ManagerRef(Arc<Mutex<MockManager>>);

    impl FunctionTagManager for ManagerRef {
        fn get_function_tag_by_name(&self, _name: &str) -> Option<&dyn FunctionTag> {
            None
        }
        fn get_function_tag_by_id(&self, _id: i64) -> Option<&dyn FunctionTag> {
            None
        }
        fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag> {
            Vec::new()
        }
        fn is_tag_assigned(&self, _name: &str) -> bool {
            false
        }
        fn create_function_tag(&mut self, _name: &str, _comment: &str) -> &dyn FunctionTag {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_use_count(&self, _tag: &dyn FunctionTag) -> usize {
            0
        }
    }
    impl ErrorHandler for ManagerRef {
        fn db_error(&self, e: io::Error) {
            self.0.lock().unwrap().db_error(e);
        }
    }
    impl FunctionTagManagerDb for ManagerRef {
        fn set_program(&mut self, _program: Arc<dyn FunctionTagManagerProgram>) {}
        fn is_tag_applied(&self, _function_id: i64, _tag_id: i64) -> bool {
            false
        }
        fn apply_function_tag(&mut self, _function_id: i64, _tag_id: i64) {}
        fn remove_function_tag(&mut self, _function_id: i64, _tag_id: i64) -> bool {
            false
        }
        fn update_function_tag(&mut self, _record: &DBRecord, _old_value: &str, _new_value: &str) -> io::Result<()> {
            unimplemented!("routed through Mutex directly in this test")
        }
        fn get_tag_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
            self.0.lock().unwrap().get_tag_record(id)
        }
        fn do_delete_tag(&mut self, _id: i64) -> io::Result<()> {
            unimplemented!("routed through Mutex directly in this test")
        }
        fn get_function_tags_by_function_id(&self, _function_id: i64) -> io::Result<Vec<&dyn FunctionTag>> {
            Ok(Vec::new())
        }
        fn invalidate_cache(&mut self) {}
    }

    impl FunctionTag for MockFunctionTagDb {
        fn id(&self) -> i64 {
            self.function_tag_db_id()
        }
        fn name(&self) -> &str {
            self.refresh_if_needed();
            // SAFETY-free bridge: `name` is refreshed in lockstep with `record` (see
            // `set_record`), so this borrow reflects the same data `function_tag_db_get_name`
            // would recompute; it's just already cached as an owned `String` we can hand a `&str`
            // into.
            Box::leak(self.name.lock().unwrap().clone().into_boxed_str())
        }
        fn comment(&self) -> &str {
            self.refresh_if_needed();
            Box::leak(self.comment.lock().unwrap().clone().into_boxed_str())
        }
        fn set_name(&mut self, name: &str) {
            self.function_tag_db_set_name(name);
        }
        fn set_comment(&mut self, comment: &str) {
            self.function_tag_db_set_comment(comment);
        }
        fn delete(&mut self) {
            self.function_tag_db_delete();
        }
        fn compare_to(&self, other: &dyn FunctionTag) -> Ordering {
            self.function_tag_db_compare_to(other)
        }
    }

    #[test]
    fn get_name_and_comment_read_through_to_record() {
        let manager = Arc::new(Mutex::new(MockManager {
            records: RefCell::new(std::collections::HashMap::new()),
            update_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        }));
        let tag = MockFunctionTagDb::new(manager, 1, "BADCODE", "known bad code");
        assert_eq!(FunctionTag::name(&tag), "BADCODE");
        assert_eq!(FunctionTag::comment(&tag), "known bad code");
        assert_eq!(tag.function_tag_db_id(), 1);
    }

    #[test]
    fn set_comment_updates_record_and_notifies_manager_only_on_change() {
        let manager = Arc::new(Mutex::new(MockManager {
            records: RefCell::new(std::collections::HashMap::new()),
            update_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        }));
        let mut tag = MockFunctionTagDb::new(manager.clone(), 1, "BADCODE", "old comment");

        FunctionTag::set_comment(&mut tag, "new comment");
        assert_eq!(FunctionTag::comment(&tag), "new comment");
        assert_eq!(manager.lock().unwrap().update_calls.get(), 1);

        // Setting the same value again should not fire another notification.
        FunctionTag::set_comment(&mut tag, "new comment");
        assert_eq!(manager.lock().unwrap().update_calls.get(), 1);
    }

    #[test]
    fn set_name_updates_record_and_notifies_manager() {
        let manager = Arc::new(Mutex::new(MockManager {
            records: RefCell::new(std::collections::HashMap::new()),
            update_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        }));
        let mut tag = MockFunctionTagDb::new(manager.clone(), 1, "BADCODE", "comment");
        FunctionTag::set_name(&mut tag, "HAS_UNIMPLEMENTED");
        assert_eq!(FunctionTag::name(&tag), "HAS_UNIMPLEMENTED");
        assert_eq!(manager.lock().unwrap().update_calls.get(), 1);
    }

    #[test]
    fn delete_calls_manager_do_delete_tag() {
        let manager = Arc::new(Mutex::new(MockManager {
            records: RefCell::new(std::collections::HashMap::new()),
            update_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        }));
        let mut tag = MockFunctionTagDb::new(manager.clone(), 1, "BADCODE", "comment");
        FunctionTag::delete(&mut tag);
        assert_eq!(manager.lock().unwrap().delete_calls.get(), 1);
    }

    #[test]
    fn compare_to_orders_by_name_then_comment_case_insensitively() {
        let manager = Arc::new(Mutex::new(MockManager {
            records: RefCell::new(std::collections::HashMap::new()),
            update_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        }));
        let a = MockFunctionTagDb::new(manager.clone(), 1, "alpha", "zzz");
        let b = MockFunctionTagDb::new(manager, 2, "ALPHA", "aaa");
        // Same name case-insensitively -> falls back to comparing comments.
        assert_eq!(FunctionTag::compare_to(&a, &b), Ordering::Greater);
    }
}
