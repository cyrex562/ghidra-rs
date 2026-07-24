//! Port of `ghidra.program.database.function.FunctionTagManagerDB`.
//!
//! The Java type is a package-private, concrete class that maintains the DB-backed set of
//! function tags (backed by [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter)
//! and [`FunctionTagMappingAdapter`](crate::program::database::function::FunctionTagMappingAdapter))
//! and the functions they've been applied to. Its constructor (adapter selection and `DbCache`/
//! `TagFactory` wiring) and private helpers (`incrementCountCache`, `decrementCountCache`,
//! `buildTagCountCache`, and the `fireTag*Notification` helpers) are construction/caching details
//! that belong with whichever type ends up owning the concrete DB-backed implementation -- this
//! port only models the public/package-visible instance API, as an object-safe trait. This
//! follows the same convention already used for
//! [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter),
//! [`FunctionTagMappingAdapter`](crate::program::database::function::FunctionTagMappingAdapter),
//! and [`TreeManager`](crate::program::database::module::TreeManager). This trait was itself
//! selected as a dependency-cycle cut-point.
//!
//! `FunctionTagManagerDB implements FunctionTagManager, ErrorHandler`; this trait models that
//! same relationship by extending the already-ported
//! [`FunctionTagManager`](crate::program::model::listing::FunctionTagManager) interface and the
//! already-ported [`ErrorHandler`](crate::framework::db::util::ErrorHandler), rather than
//! re-declaring their methods. Java's overloaded `getFunctionTag` (a `String`-keyed overload and
//! a `long`-keyed overload) is therefore inherited pre-split as
//! `FunctionTagManager::get_function_tag_by_name`/`get_function_tag_by_id`.
//!
//! `FunctionTagManagerDB`'s `program` field (declared `Program` but always assigned a `ProgramDB`
//! via a cast in `setProgram`) is modeled as a
//! [`FunctionTagManagerProgram`](crate::program::seam_stubs::FunctionTagManagerProgram)
//! placeholder in `seam_stubs`, covering just the error-reporting/change-notification/cache-
//! invalidation calls this type makes on it, since the real `ProgramDB` port does not expose
//! these members yet.
//!
//! `doDeleteTag(FunctionTag)` is ported as [`FunctionTagManagerDb::do_delete_tag`] taking a
//! `tag_id: i64` rather than a `&dyn FunctionTag`, so that a caller can look a tag up (e.g. via
//! `get_function_tag_by_id`) and then delete it without the borrow-checker forcing the lookup's
//! immutable borrow of `self` to outlive the `&mut self` delete call.

use std::io;
use std::sync::Arc;

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::DBRecord;
use crate::program::database::function::function_tag_adapter::{COMMENT_COL, NAME_COL};
use crate::program::model::listing::{FunctionTag, FunctionTagManager};
use crate::program::seam_stubs::FunctionTagManagerProgram;

/// Manages the set of function tags available in a program, and their application to individual
/// functions.
///
/// Port of `ghidra.program.database.function.FunctionTagManagerDB`. See the module docs for what
/// was intentionally left out (construction/caching details) and how the `Program`/`ErrorHandler`
/// dependencies were mapped.
pub trait FunctionTagManagerDb: FunctionTagManager + ErrorHandler {
    /// Associates this manager with its owning program, used to report database errors and fire
    /// tag-related change notifications.
    ///
    /// Stands in for `FunctionTagManagerDB.setProgram(Program)`.
    fn set_program(&mut self, program: Arc<dyn FunctionTagManagerProgram>);

    /// Determines if the given tag has been applied to the given function.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.isTagApplied(long, long)`.
    fn is_tag_applied(&self, function_id: i64, tag_id: i64) -> bool;

    /// Applies the tag with the given id to the function with the given id. Has no effect if no
    /// tag with `tag_id` exists.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.applyFunctionTag(long, long)`.
    fn apply_function_tag(&mut self, function_id: i64, tag_id: i64);

    /// Removes the tag with the given id from the function with the given id. Returns `true` if a
    /// mapping was actually removed.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.removeFunctionTag(long, long)`.
    fn remove_function_tag(&mut self, function_id: i64, tag_id: i64) -> bool;

    /// Persists a tag record whose name and/or comment have already been updated in-place by the
    /// caller, and fires a change notification describing the transition from `old_value` to
    /// `new_value`.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.updateFunctionTag(FunctionTagDB,
    /// String, String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_function_tag(&mut self, record: &DBRecord, old_value: &str, new_value: &str) -> io::Result<()>;

    /// Returns the raw database record for the tag with the given id, or `None` if not found.
    ///
    /// Stands in for `FunctionTagManagerDB.getTagRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_tag_record(&self, id: i64) -> io::Result<Option<DBRecord>>;

    /// Deletes the tag with the given id, removing all of its function mappings.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.doDeleteTag(FunctionTag)`. See the
    /// module docs for why this takes a `tag_id` rather than a `&dyn FunctionTag`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn do_delete_tag(&mut self, tag_id: i64) -> io::Result<()>;

    /// Returns all function tags associated with the given function id.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.getFunctionTagsByFunctionID(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_function_tags_by_function_id(&self, function_id: i64) -> io::Result<Vec<&dyn FunctionTag>>;

    /// Invalidates the tag-use-count cache, forcing it to be rebuilt from the database next time
    /// it is needed.
    ///
    /// Stands in for the package-private `FunctionTagManagerDB.invalidateCache()`.
    fn invalidate_cache(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::cell::Cell;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockTag {
        id: i64,
        name: String,
        comment: String,
    }

    impl MockTag {
        fn new(id: i64, name: &str, comment: &str) -> Self {
            MockTag {
                id,
                name: name.to_string(),
                comment: comment.to_string(),
            }
        }
    }

    impl FunctionTag for MockTag {
        fn id(&self) -> i64 {
            self.id
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn comment(&self) -> &str {
            &self.comment
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn set_comment(&mut self, comment: &str) {
            self.comment = comment.to_string();
        }

        fn delete(&mut self) {}

        fn compare_to(&self, other: &dyn FunctionTag) -> Ordering {
            self.name.as_str().cmp(other.name())
        }
    }

    #[derive(Default)]
    struct RecordingProgram {
        errors: Cell<u32>,
        created: Cell<u32>,
        changed: Cell<u32>,
        deleted: Cell<u32>,
        invalidations: Cell<u32>,
    }

    impl FunctionTagManagerProgram for RecordingProgram {
        fn db_error(&self, _err: &io::Error) {
            self.errors.set(self.errors.get() + 1);
        }

        fn tag_created(&self, _tag: &dyn FunctionTag) {
            self.created.set(self.created.get() + 1);
        }

        fn tag_changed(&self, _tag: &dyn FunctionTag, _old_value: &str, _new_value: &str) {
            self.changed.set(self.changed.get() + 1);
        }

        fn tag_deleted(&self, _tag: &dyn FunctionTag) {
            self.deleted.set(self.deleted.get() + 1);
        }

        fn function_tags_changed(&self) {
            self.invalidations.set(self.invalidations.get() + 1);
        }
    }

    fn tag_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String, FieldType::String],
            vec!["Tag Name".to_string(), "Comment".to_string()],
            vec![],
        ))
    }

    /// A minimal in-memory `FunctionTagManagerDB`, exercising object-safety and the create/apply/
    /// query/update/delete/invalidate contract described by the Java class.
    struct MockFunctionTagManagerDb {
        tags: HashMap<i64, MockTag>,
        next_tag_id: i64,
        mappings: Vec<(i64, i64)>,
        program: Option<Arc<dyn FunctionTagManagerProgram>>,
        cache_invalidations: u32,
    }

    impl MockFunctionTagManagerDb {
        fn new() -> Self {
            MockFunctionTagManagerDb {
                tags: HashMap::new(),
                next_tag_id: 0,
                mappings: Vec::new(),
                program: None,
                cache_invalidations: 0,
            }
        }
    }

    impl FunctionTagManager for MockFunctionTagManagerDb {
        fn get_function_tag_by_name(&self, name: &str) -> Option<&dyn FunctionTag> {
            self.tags
                .values()
                .find(|tag| tag.name == name)
                .map(|tag| tag as &dyn FunctionTag)
        }

        fn get_function_tag_by_id(&self, id: i64) -> Option<&dyn FunctionTag> {
            self.tags.get(&id).map(|tag| tag as &dyn FunctionTag)
        }

        fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag> {
            self.tags.values().map(|tag| tag as &dyn FunctionTag).collect()
        }

        fn is_tag_assigned(&self, name: &str) -> bool {
            let Some(tag) = self.tags.values().find(|tag| tag.name == name) else {
                return false;
            };
            self.mappings.iter().any(|(_, tag_id)| *tag_id == tag.id)
        }

        fn create_function_tag(&mut self, name: &str, comment: &str) -> &dyn FunctionTag {
            if !self.tags.values().any(|tag| tag.name == name) {
                let id = self.next_tag_id;
                self.next_tag_id += 1;
                self.tags.insert(id, MockTag::new(id, name, comment));
                if let Some(program) = &self.program {
                    program.tag_created(&self.tags[&id]);
                }
            }
            let id = self.tags.values().find(|tag| tag.name == name).unwrap().id;
            &self.tags[&id]
        }

        fn get_use_count(&self, tag: &dyn FunctionTag) -> usize {
            self.mappings.iter().filter(|(_, tag_id)| *tag_id == tag.id()).count()
        }
    }

    impl ErrorHandler for MockFunctionTagManagerDb {
        fn db_error(&self, e: io::Error) {
            if let Some(program) = &self.program {
                program.db_error(&e);
            }
        }
    }

    impl FunctionTagManagerDb for MockFunctionTagManagerDb {
        fn set_program(&mut self, program: Arc<dyn FunctionTagManagerProgram>) {
            self.program = Some(program);
        }

        fn is_tag_applied(&self, function_id: i64, tag_id: i64) -> bool {
            self.mappings.contains(&(function_id, tag_id))
        }

        fn apply_function_tag(&mut self, function_id: i64, tag_id: i64) {
            if self.tags.contains_key(&tag_id) {
                self.mappings.push((function_id, tag_id));
            }
        }

        fn remove_function_tag(&mut self, function_id: i64, tag_id: i64) -> bool {
            let before = self.mappings.len();
            self.mappings.retain(|mapping| *mapping != (function_id, tag_id));
            self.mappings.len() != before
        }

        fn update_function_tag(&mut self, record: &DBRecord, old_value: &str, new_value: &str) -> io::Result<()> {
            let Field::Long(Some(id)) = record.get_key() else {
                return Ok(());
            };
            if let Some(tag) = self.tags.get_mut(id) {
                if let Some(name) = record.get_string(NAME_COL) {
                    tag.name = name.to_string();
                }
                if let Some(comment) = record.get_string(COMMENT_COL) {
                    tag.comment = comment.to_string();
                }
                if let Some(program) = &self.program {
                    program.tag_changed(&self.tags[id], old_value, new_value);
                }
            }
            Ok(())
        }

        fn get_tag_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.tags.get(&id).map(|tag| {
                let mut record = DBRecord::new(tag_schema(), Field::Long(Some(tag.id)));
                record.set_string(NAME_COL, Some(tag.name.clone()));
                record.set_string(COMMENT_COL, Some(tag.comment.clone()));
                record
            }))
        }

        fn do_delete_tag(&mut self, tag_id: i64) -> io::Result<()> {
            if let Some(tag) = self.tags.remove(&tag_id) {
                self.mappings.retain(|(_, mapped_tag_id)| *mapped_tag_id != tag_id);
                if let Some(program) = &self.program {
                    program.tag_deleted(&tag);
                }
            }
            Ok(())
        }

        fn get_function_tags_by_function_id(&self, function_id: i64) -> io::Result<Vec<&dyn FunctionTag>> {
            Ok(self
                .mappings
                .iter()
                .filter(|(fid, _)| *fid == function_id)
                .filter_map(|(_, tag_id)| self.tags.get(tag_id))
                .map(|tag| tag as &dyn FunctionTag)
                .collect())
        }

        fn invalidate_cache(&mut self) {
            self.cache_invalidations += 1;
            if let Some(program) = &self.program {
                program.function_tags_changed();
            }
        }
    }

    #[test]
    fn object_safe_and_tracks_tags_and_mappings() {
        let mut manager: Box<dyn FunctionTagManagerDb> = Box::new(MockFunctionTagManagerDb::new());
        let program = Arc::new(RecordingProgram::default());
        manager.set_program(program.clone());

        // Creating tags fires a `tagCreated` notification and dedups by name.
        let tag = manager.create_function_tag("BADCODE", "known bad code");
        assert_eq!(tag.name(), "BADCODE");
        let tag_id = tag.id();
        manager.create_function_tag("BADCODE", "different comment");
        assert_eq!(manager.get_all_function_tags().len(), 1);
        assert_eq!(program.created.get(), 1);

        // Applying a tag to a function is reflected in isTagApplied/isTagAssigned/getUseCount.
        assert!(!manager.is_tag_applied(100, tag_id));
        manager.apply_function_tag(100, tag_id);
        manager.apply_function_tag(200, tag_id);
        assert!(manager.is_tag_applied(100, tag_id));
        assert!(manager.is_tag_assigned("BADCODE"));
        let fetched = manager.get_function_tag_by_id(tag_id).unwrap();
        assert_eq!(manager.get_use_count(fetched), 2);

        // getFunctionTagsByFunctionID returns just the tags applied to that function.
        let tags_for_100 = manager.get_function_tags_by_function_id(100).unwrap();
        assert_eq!(tags_for_100.len(), 1);
        assert_eq!(tags_for_100[0].id(), tag_id);
        assert!(manager.get_function_tags_by_function_id(999).unwrap().is_empty());

        // updateFunctionTag persists the record's already-mutated fields and notifies.
        let mut record = manager.get_tag_record(tag_id).unwrap().unwrap();
        record.set_string(NAME_COL, Some("HAS_UNIMPLEMENTED".to_string()));
        manager.update_function_tag(&record, "BADCODE", "HAS_UNIMPLEMENTED").unwrap();
        assert_eq!(program.changed.get(), 1);
        assert!(manager.get_function_tag_by_name("HAS_UNIMPLEMENTED").is_some());
        assert!(manager.get_function_tag_by_name("BADCODE").is_none());

        // removeFunctionTag removes exactly one mapping and reports whether it did.
        assert!(manager.remove_function_tag(100, tag_id));
        assert!(!manager.remove_function_tag(100, tag_id));
        assert!(!manager.is_tag_applied(100, tag_id));
        assert!(manager.is_tag_applied(200, tag_id));

        // invalidateCache forwards to the program's function-tag cache invalidation.
        manager.invalidate_cache();
        assert_eq!(program.invalidations.get(), 1);

        // doDeleteTag removes all remaining mappings along with the tag itself, and notifies.
        manager.do_delete_tag(tag_id).unwrap();
        assert!(manager.get_function_tag_by_id(tag_id).is_none());
        assert!(!manager.is_tag_applied(200, tag_id));
        assert_eq!(program.deleted.get(), 1);
        assert!(manager.get_all_function_tags().is_empty());

        // dbError (via the `ErrorHandler` supertrait) forwards to the program.
        manager.db_error(io::Error::new(io::ErrorKind::Other, "disk full"));
        assert_eq!(program.errors.get(), 1);
    }
}
