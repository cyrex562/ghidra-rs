//! Port of `ghidra.feature.fid.db.FidQueryService`.

use crate::feature::fid::db::fid_db::FidDB;
use crate::feature::fid::db::fid_query_close_listener::FidQueryCloseListener;
use crate::feature::fid::db::function_record::FunctionRecord;
use crate::feature::fid::db::library_record::LibraryRecord;
use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::feature::seam_stubs::{FidFile, GetFidDbError};
use crate::program::model::lang::language::Language;

use std::sync::Arc;

/// A set of open Fid databases appropriate for querying against a particular language.
///
/// Port of `ghidra.feature.fid.db.FidQueryService`. Java's `FidQueryService implements
/// Closeable`; the Rust equivalent is the inherent [`FidQueryService::close`] below. This object
/// must be closed when it is no longer needed, which in turn closes all of its open FID
/// databases and notifies any registered close listeners.
pub struct FidQueryService {
    fid_db_list: Vec<FidDB>,
    listeners: Vec<Box<dyn FidQueryCloseListener>>,
}

impl FidQueryService {
    /// Builds a query service over every `fid_file` that is active and, when `language` is
    /// supplied, can process that language (Java: `language == null ||
    /// fidFile.canProcessLanguage(language)`).
    ///
    /// Java's constructor is package-private -- it is only ever called by `FidFileManager`
    /// (not yet ported), so this is `pub(crate)` until that caller lands.
    ///
    /// Java assumes `fidFiles` have already been checked for version compatibility; that
    /// precondition is preserved here rather than re-validated.
    pub(crate) fn new(
        fid_files: &[Arc<dyn FidFile>],
        language: Option<&dyn Language>,
        open_for_update: bool,
    ) -> Result<Self, GetFidDbError> {
        let mut fid_db_list = Vec::new();
        for fid_file in fid_files {
            let can_process =
                language.map_or(true, |language| fid_file.can_process_language(language));
            if fid_file.is_active() && can_process {
                fid_db_list.push(fid_file.get_fid_db(open_for_update)?);
            }
        }
        Ok(Self { fid_db_list, listeners: Vec::new() })
    }

    /// Adds a listener to be notified when this `FidQueryService` is closed.
    pub fn add_close_listener(&mut self, listener: Box<dyn FidQueryCloseListener>) {
        self.listeners.push(listener);
    }

    /// Removes the listener to be notified when this `FidQueryService` is closed.
    ///
    /// Java removes by `List.remove(Object)`, which is identity-based here since
    /// `FidQueryCloseListener` implementors don't override `equals`; matched by comparing the
    /// trait object's data pointer against `listener`'s.
    pub fn remove_close_listener(&mut self, listener: &dyn FidQueryCloseListener) {
        let target = std::ptr::addr_of!(*listener).cast::<()>();
        self.listeners
            .retain(|candidate| !std::ptr::eq(std::ptr::addr_of!(**candidate).cast::<()>(), target));
    }

    /// Returns a single function record given its id, or `None` if no such record exists,
    /// searching across all attached databases.
    ///
    /// Function record ids are generated so they are unique across libraries and databases.
    pub fn get_function_by_id(&self, function_id: i64) -> Option<Arc<FunctionRecord>> {
        self.fid_db_list.iter().find_map(|fid_db| fid_db.get_function_by_id(function_id))
    }

    /// Returns true if the relation exists between a superior (caller) function and a full hash
    /// representing the inferior (callee) function, searching across all attached databases.
    pub fn get_superior_full_relation(
        &self,
        superior_function: &FunctionRecord,
        inferior_function: &dyn FidHashQuad,
    ) -> bool {
        self.fid_db_list
            .iter()
            .any(|fid_db| fid_db.get_superior_full_relation(superior_function, inferior_function))
    }

    /// Returns true if the relation exists between an inferior (callee) function and a full hash
    /// representing the superior (caller) function, searching across all attached databases.
    pub fn get_inferior_full_relation(
        &self,
        superior_function: &dyn FidHashQuad,
        inferior_function: &FunctionRecord,
    ) -> bool {
        self.fid_db_list
            .iter()
            .any(|fid_db| fid_db.get_inferior_full_relation(superior_function, inferior_function))
    }

    /// Returns the library record in which the provided function record resides.
    pub fn get_library_for_function(&self, function_record: &FunctionRecord) -> Option<LibraryRecord> {
        self.fid_db_list.iter().find_map(|fid_db| fid_db.get_library_for_function(function_record))
    }

    /// Returns the first full hash value across all the databases that is greater than or equal
    /// to `value`. Mostly for debug or statistical analysis.
    pub fn find_full_hash_value_at_or_after(&self, value: i64) -> Option<i64> {
        self.fid_db_list.iter().filter_map(|fid_db| fid_db.find_full_hash_value_at_or_after(value)).min()
    }

    /// Returns all the function records that have the provided specific hash, searching across
    /// all attached databases.
    pub fn find_functions_by_specific_hash(&self, specific_hash: i64) -> Vec<Arc<FunctionRecord>> {
        let mut result = Vec::new();
        for fid_db in &self.fid_db_list {
            if let Some(list) = fid_db.find_functions_by_specific_hash(specific_hash) {
                result.extend(list);
            }
        }
        result
    }

    /// Returns all the function records that have the provided full hash, searching across all
    /// attached databases.
    pub fn find_functions_by_full_hash(&self, full_hash: i64) -> Vec<Arc<FunctionRecord>> {
        let mut result = Vec::new();
        for fid_db in &self.fid_db_list {
            if let Some(list) = fid_db.find_functions_by_full_hash(full_hash) {
                result.extend(list);
            }
        }
        result
    }

    /// Searches all databases for functions that match a name substring.
    pub fn find_functions_by_name_substring(&self, name: &str) -> Vec<Arc<FunctionRecord>> {
        let mut result = Vec::new();
        for fid_db in &self.fid_db_list {
            if let Some(list) = fid_db.find_functions_by_name_substring(name) {
                result.extend(list);
            }
        }
        result
    }

    /// Searches all databases for functions that match a domain path substring.
    pub fn find_functions_by_domain_path_substring(&self, domain_path: &str) -> Vec<Arc<FunctionRecord>> {
        let mut result = Vec::new();
        for fid_db in &self.fid_db_list {
            if let Some(list) = fid_db.find_functions_by_domain_path_substring(domain_path) {
                result.extend(list);
            }
        }
        result
    }

    /// Closes this `FidQueryService`, which in turn closes all of its open FID databases. Also
    /// notifies any registered listeners that it has been closed.
    ///
    /// Listeners are copied out and the listener list reset before notification, in case a
    /// listener tries to remove itself (or another listener) during the callback.
    pub fn close(&mut self) {
        let mut current_listeners = std::mem::take(&mut self.listeners);
        for listener in current_listeners.iter_mut() {
            listener.fid_query_closed(self);
        }
        self.listeners.clear();
        for fid_db in &mut self.fid_db_list {
            fid_db.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::relations_table::RelationsTable;
    use crate::feature::seam_stubs::{FunctionsTable, LibrariesTable, StringRecord, StringsTable};
    use crate::framework::db::db_handle::DBHandle;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use std::collections::HashMap;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct NoopStringsTable;
    impl StringsTable for NoopStringsTable {
        fn lookup_string(&self, _id: i64) -> Option<StringRecord> {
            None
        }
    }

    struct NoopLibrariesTable;
    impl LibrariesTable for NoopLibrariesTable {
        fn create_library(
            &self,
            _library_family_name: &str,
            _library_version: &str,
            _library_variant: &str,
            _ghidra_version: &str,
            _language_id: &crate::program::model::lang::language_id::LanguageID,
            _language_version: i32,
            _language_minor_version: i32,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> io::Result<DBRecord> {
            unimplemented!("test service never creates libraries")
        }
        fn get_libraries(&self) -> io::Result<Vec<LibraryRecord>> {
            Ok(Vec::new())
        }
        fn get_libraries_by_name(
            &self,
            _family: &str,
            _version: Option<&str>,
            _variant: Option<&str>,
        ) -> io::Result<Vec<LibraryRecord>> {
            Ok(Vec::new())
        }
        fn get_library_by_id(&self, _id: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
    }

    fn function_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Function ID".to_string(),
            vec![
                FieldType::Short,
                FieldType::Long,
                FieldType::Byte,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Byte,
            ],
            vec![
                "Code Unit Size".to_string(),
                "Full Hash".to_string(),
                "Specific Hash Additional Size".to_string(),
                "Specific Hash".to_string(),
                "Library ID".to_string(),
                "Name ID".to_string(),
                "Entry Point".to_string(),
                "Domain Path ID".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    /// Builds an `Arc<FunctionRecord>` with the given id. The record only needs to be
    /// distinguishable by id for these tests, so every other column is left at its default.
    fn build_function_record(id: i64) -> Arc<FunctionRecord> {
        let fid_db = crate::feature::fid::db::fid_db::test_support::minimal_fid_db(Arc::new(NoopStringsTable));
        let record = DBRecord::new(function_schema(), Field::Long(Some(id)));
        Arc::new(FunctionRecord::new(fid_db, record))
    }

    /// A `FunctionsTable` whose per-database results are configured directly by the test, rather
    /// than derived from a real query, so the fixture can isolate `FidQueryService`'s own
    /// aggregation logic (first-match, `addAll`, min-of) from `FidDB`'s query implementation
    /// (covered by `fid_db`'s own tests).
    struct FakeFunctionsTable {
        by_id: HashMap<i64, Arc<FunctionRecord>>,
        name_substring_matches: Vec<Arc<FunctionRecord>>,
        full_hash_value_at_or_after: Option<i64>,
    }

    impl FunctionsTable for FakeFunctionsTable {
        fn get_full_hash_value_at_or_after(&self, _value: i64) -> io::Result<Option<i64>> {
            Ok(self.full_hash_value_at_or_after)
        }
        fn get_function_records_by_specific_hash(&self, _hash: i64) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(Vec::new())
        }
        fn get_function_records_by_full_hash(&self, _hash: i64) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(Vec::new())
        }
        fn create_function_record(
            &self,
            _library_id: i64,
            _hash_quad: &dyn FidHashQuad,
            _name: &str,
            _entry_point: i64,
            _domain_path: &str,
            _has_terminator: bool,
        ) -> io::Result<Arc<FunctionRecord>> {
            unimplemented!("test service never creates functions")
        }
        fn get_function_records_by_name_substring(&self, _name_search: &str) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(self.name_substring_matches.clone())
        }
        fn get_function_records_by_name_regex(&self, _regex: &str) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(Vec::new())
        }
        fn get_function_by_id(&self, function_id: i64) -> io::Result<Option<Arc<FunctionRecord>>> {
            Ok(self.by_id.get(&function_id).cloned())
        }
        fn get_function_records_by_domain_path_substring(&self, _domain_path_search: &str) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(Vec::new())
        }
        fn get_function_records_by_library_and_name(
            &self,
            _library: &LibraryRecord,
            _name: &str,
        ) -> io::Result<Vec<Arc<FunctionRecord>>> {
            Ok(Vec::new())
        }
        fn modify_flags(&self, _function_id: i64, _flag_mask: i32, _value: bool) -> io::Result<()> {
            Ok(())
        }
    }

    struct TestFidFile {
        active: bool,
        get_fid_db_calls: Arc<AtomicUsize>,
        functions_table: Arc<FakeFunctionsTable>,
    }

    impl FidFile for TestFidFile {
        fn get_name(&self) -> String {
            "test.fidb".to_string()
        }
        fn get_path(&self) -> String {
            "/tmp/test.fidb".to_string()
        }
        fn is_installed(&self) -> bool {
            false
        }
        fn closing_fid_db(&self, _fid_db: &FidDB) {}
        fn is_active(&self) -> bool {
            self.active
        }
        fn can_process_language(&self, _language: &dyn Language) -> bool {
            true
        }
        fn get_fid_db(&self, open_for_update: bool) -> Result<FidDB, GetFidDbError> {
            self.get_fid_db_calls.fetch_add(1, Ordering::SeqCst);
            let mut handle = DBHandle::new().map_err(GetFidDbError::Io)?;
            RelationsTable::create_tables(&mut handle).map_err(GetFidDbError::Io)?;
            FidDB::new(
                Arc::new(NoopFidFile),
                handle,
                Arc::new(NoopLibrariesTable),
                Arc::new(NoopStringsTable),
                self.functions_table.clone(),
                open_for_update,
            )
            .map_err(GetFidDbError::Io)
        }
    }

    struct NoopFidFile;
    impl FidFile for NoopFidFile {
        fn get_name(&self) -> String {
            String::new()
        }
        fn get_path(&self) -> String {
            String::new()
        }
        fn is_installed(&self) -> bool {
            false
        }
        fn closing_fid_db(&self, _fid_db: &FidDB) {}
        fn is_active(&self) -> bool {
            true
        }
        fn can_process_language(&self, _language: &dyn Language) -> bool {
            true
        }
        fn get_fid_db(&self, _open_for_update: bool) -> Result<FidDB, GetFidDbError> {
            unimplemented!("NoopFidFile never opens itself")
        }
    }

    fn fid_file(
        active: bool,
        by_id: Vec<(i64, Arc<FunctionRecord>)>,
        name_substring_matches: Vec<Arc<FunctionRecord>>,
        full_hash_value_at_or_after: Option<i64>,
        calls: Arc<AtomicUsize>,
    ) -> Arc<dyn FidFile> {
        Arc::new(TestFidFile {
            active,
            get_fid_db_calls: calls,
            functions_table: Arc::new(FakeFunctionsTable {
                by_id: by_id.into_iter().collect(),
                name_substring_matches,
                full_hash_value_at_or_after,
            }),
        })
    }

    #[test]
    fn new_only_opens_active_files() {
        let calls_a = Arc::new(AtomicUsize::new(0));
        let calls_b = Arc::new(AtomicUsize::new(0));
        let file_a = fid_file(true, Vec::new(), Vec::new(), None, calls_a.clone());
        let file_b = fid_file(false, Vec::new(), Vec::new(), None, calls_b.clone());

        FidQueryService::new(&[file_a, file_b], None, false).expect("build service");

        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn get_function_by_id_searches_across_all_databases() {
        let record_a = build_function_record(1);
        let record_b = build_function_record(2);
        let calls = Arc::new(AtomicUsize::new(0));
        let file_a = fid_file(true, vec![(1, record_a)], Vec::new(), None, calls.clone());
        let file_b = fid_file(true, vec![(2, record_b)], Vec::new(), None, calls.clone());

        let service = FidQueryService::new(&[file_a, file_b], None, false).expect("build service");

        assert_eq!(service.get_function_by_id(1).map(|r| r.get_id()), Some(1));
        assert_eq!(service.get_function_by_id(2).map(|r| r.get_id()), Some(2));
        assert!(service.get_function_by_id(3).is_none());
    }

    #[test]
    fn find_functions_by_name_substring_aggregates_across_databases() {
        let record_a = build_function_record(1);
        let record_b = build_function_record(2);
        let calls = Arc::new(AtomicUsize::new(0));
        let file_a = fid_file(true, Vec::new(), vec![record_a.clone()], None, calls.clone());
        let file_b = fid_file(true, Vec::new(), vec![record_b.clone()], None, calls.clone());

        let service = FidQueryService::new(&[file_a, file_b], None, false).expect("build service");

        let mut ids: Vec<i64> =
            service.find_functions_by_name_substring("x").iter().map(|r| r.get_id()).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn find_full_hash_value_at_or_after_takes_the_minimum_across_databases() {
        let calls = Arc::new(AtomicUsize::new(0));
        let file_a = fid_file(true, Vec::new(), Vec::new(), Some(100), calls.clone());
        let file_b = fid_file(true, Vec::new(), Vec::new(), Some(42), calls.clone());
        let file_c = fid_file(true, Vec::new(), Vec::new(), None, calls.clone());

        let service =
            FidQueryService::new(&[file_a, file_b, file_c], None, false).expect("build service");

        assert_eq!(service.find_full_hash_value_at_or_after(0), Some(42));
    }

    struct RecordingListener {
        close_count: Arc<AtomicUsize>,
    }

    impl FidQueryCloseListener for RecordingListener {
        fn fid_query_closed(&mut self, _service: &FidQueryService) {
            self.close_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn close_notifies_registered_listeners() {
        let mut service = FidQueryService::new(&[], None, false).expect("build service");
        let close_count = Arc::new(AtomicUsize::new(0));
        service.add_close_listener(Box::new(RecordingListener { close_count: close_count.clone() }));

        service.close();

        assert_eq!(close_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn removed_listener_is_not_notified_on_close() {
        let mut service = FidQueryService::new(&[], None, false).expect("build service");
        let removed_count = Arc::new(AtomicUsize::new(0));
        let kept_count = Arc::new(AtomicUsize::new(0));

        service.add_close_listener(Box::new(RecordingListener { close_count: removed_count.clone() }));
        service.add_close_listener(Box::new(RecordingListener { close_count: kept_count.clone() }));

        // Raw pointer (not a live borrow) to the first listener, so it can be handed to
        // `remove_close_listener` without holding an immutable borrow of `service` across the
        // `&mut self` call.
        let removed: *const dyn FidQueryCloseListener = &*service.listeners[0];
        // SAFETY: the pointee is still owned by `service.listeners` at this point, so it's alive.
        service.remove_close_listener(unsafe { &*removed });

        service.close();

        assert_eq!(removed_count.load(Ordering::SeqCst), 0);
        assert_eq!(kept_count.load(Ordering::SeqCst), 1);
    }
}
