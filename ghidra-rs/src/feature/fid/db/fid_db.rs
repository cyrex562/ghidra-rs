//! Port of `ghidra.feature.fid.db.FidDB`.

use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::feature::seam_stubs::{
    FidFile, FunctionRecord, FunctionsTable, LibrariesTable, StringsTable,
};
use crate::framework::db::db_handle::DBHandle;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;
use crate::util::msg::Msg;
use crate::util::read_only_exception::ReadOnlyException;
use crate::util::task::TaskMonitor;

use super::library_record::LibraryRecord;
use super::relation_type::RelationType;
use super::relations_table::RelationsTable;

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

/// Mirrors `FunctionRecord.AUTO_PASS_FLAG` (Java: `db/FunctionRecord.java:30`). `FunctionRecord`
/// is not ported yet, so the flag masks it declares are mirrored here, the same way
/// [`super::relations_table`] mirrors `LibrariesTable`'s schema version.
pub const AUTO_PASS_FLAG: i32 = 2;
/// Mirrors `FunctionRecord.AUTO_FAIL_FLAG`.
pub const AUTO_FAIL_FLAG: i32 = 4;
/// Mirrors `FunctionRecord.FORCE_SPECIFIC_FLAG`.
pub const FORCE_SPECIFIC_FLAG: i32 = 8;
/// Mirrors `FunctionRecord.FORCE_RELATION_FLAG`.
pub const FORCE_RELATION_FLAG: i32 = 16;

/// Java: `FidDB.FID_CONTENT_TYPE`, the content type stamped on packed FID databases.
pub const FID_CONTENT_TYPE: &str = "Function ID Database";

fn read_only_to_io(e: ReadOnlyException) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "FID database is closed")
}

/// An open Function ID database.
///
/// Port of `ghidra.feature.fid.db.FidDB`. Java's `FidDB implements Closeable`; the Rust
/// equivalent is the inherent [`FidDB::close`] below, which keeps the reference-counted
/// "open count" semantics that make `close` idempotent until the last user lets go.
///
/// Two pieces of the Java class have no Rust counterpart yet and are called out where they bite:
///
/// * Java's constructor opens the database handle itself, via `new DBHandle(File)` for an
///   installed raw file or `PackedDatabase.getPackedDatabase(...)` for a packed one. Neither the
///   file-backed `DBHandle` constructor nor `PackedDatabase`'s static factory is ported, so
///   [`FidDB::new`] takes an already-open handle plus the three unported tables. The
///   `isInstalled()`-driven downgrade to read-only is preserved.
/// * Java tracks `openTransaction`, the id of the long-running transaction it holds open while
///   the database is open for update. `DBHandle` has no `startTransaction`/`endTransaction`/
///   `save`/`saveAs` yet, so that field is elided and the two persistence entry points
///   ([`FidDB::save_database`], [`FidDB::save_raw_database_file`]) report that rather than
///   silently doing nothing.
///
/// Java's package-private `createNewFidDatabase(File)` is likewise omitted: every line of it goes
/// through `PackedDBHandle`, which is not ported.
pub struct FidDB {
    fid_file: Arc<dyn FidFile>,
    handle: DBHandle,
    /// The tables are cleared on close, matching Java's `librariesTable = null` and friends.
    libraries_table: Option<Arc<dyn LibrariesTable>>,
    strings_table: Option<Arc<dyn StringsTable>>,
    functions_table: Option<Arc<dyn FunctionsTable>>,
    relations_table: Option<RelationsTable>,
    open_for_update: bool,
    /// How many users have this open (Java: `AtomicInteger openCount`).
    open_count: AtomicI32,
}

impl FidDB {
    /// Opens a FID database over an already-open handle.
    ///
    /// `open_for_update` is forced to false when the backing file is an installed raw database,
    /// mirroring Java's `openRawDatabaseFile`, which does the same before handing back a handle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fid_file: Arc<dyn FidFile>,
        handle: DBHandle,
        libraries_table: Arc<dyn LibrariesTable>,
        strings_table: Arc<dyn StringsTable>,
        functions_table: Arc<dyn FunctionsTable>,
        open_for_update: bool,
    ) -> io::Result<Self> {
        // Java: raw database files in the installation can never be opened for update.
        let open_for_update = open_for_update && !fid_file.is_installed();
        let relations_table = RelationsTable::new(&handle)?;
        Ok(Self {
            fid_file,
            handle,
            libraries_table: Some(libraries_table),
            strings_table: Some(strings_table),
            functions_table: Some(functions_table),
            relations_table: Some(relations_table),
            open_for_update,
            open_count: AtomicI32::new(1),
        })
    }

    fn log_error(&self, message: &str, error: &dyn std::error::Error) {
        Msg::error_with_error(&self.to_string(), &message, error);
    }

    fn functions_table(&self) -> io::Result<&Arc<dyn FunctionsTable>> {
        self.functions_table.as_ref().ok_or_else(closed)
    }

    /// Saves this FidDB to a raw database file.
    ///
    /// Java: `handle.saveAs(file, false, monitor)`; `DBHandle` has no `saveAs` yet.
    pub fn save_raw_database_file(
        &self,
        _file: &std::path::Path,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DBHandle.saveAs is not ported yet; cannot write a raw FID database file",
        ))
    }

    /// Returns the name of the underlying `FidFile`.
    pub fn get_name(&self) -> String {
        self.fid_file.get_name()
    }

    /// Returns the full file path of the underlying `FidFile`.
    pub fn get_path(&self) -> String {
        self.fid_file.get_path()
    }

    /// Indicates that an additional user wants to keep the database open. The database is closed
    /// only once every user has called [`FidDB::close`]. After the original open the count is one.
    pub fn increment_open_count(&self) {
        self.open_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns the current open count (Java: the value behind `openCount`).
    pub fn open_count(&self) -> i32 {
        self.open_count.load(Ordering::SeqCst)
    }

    /// Indicates that this user of the FidDB no longer needs it open. Decrements the open count
    /// and, when it reaches zero, actually closes the database.
    ///
    /// Java also ends the open transaction and closes the handle here; `DBHandle` exposes neither
    /// yet, so only the table teardown and the `FidFile` callback happen.
    pub fn close(&mut self) {
        if self.open_count.fetch_sub(1, Ordering::SeqCst) - 1 != 0 {
            return;
        }
        // Cloned first so the callback can borrow `self` immutably.
        let fid_file = Arc::clone(&self.fid_file);
        fid_file.closing_fid_db(self);

        self.libraries_table = None;
        self.strings_table = None;
        self.functions_table = None;
        self.relations_table = None;
    }

    /// Returns the string table of the database, or `None` once the database has been closed.
    pub fn get_strings_table(&self) -> Option<&Arc<dyn StringsTable>> {
        self.strings_table.as_ref()
    }

    /// Returns all libraries that exist in this FID database, or an empty list on error.
    pub fn get_all_libraries(&self) -> Vec<LibraryRecord> {
        let Some(table) = self.libraries_table.as_ref() else {
            return Vec::new();
        };
        match table.get_libraries() {
            Ok(libraries) => libraries,
            Err(e) => {
                self.log_error("Error in FID database", &e);
                Vec::new()
            }
        }
    }

    /// Searches this database for functions given a specific library and exact name.
    ///
    /// Java returns `null` after logging an I/O error, which is modelled here as `None`; an
    /// successful-but-empty search still yields `Some(vec![])`.
    pub fn find_functions_by_library_and_name(
        &self,
        library: &LibraryRecord,
        name: &str,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_library_and_name(library, name) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error(
                    "Serious problem searching for FID Functions by name and namespace",
                    &e,
                );
                None
            }
        }
    }

    /// Searches this database for functions that match a name substring.
    pub fn find_functions_by_name_substring(
        &self,
        name: &str,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_name_substring(name) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error("Serious problem searching for FID Functions by name substring", &e);
                None
            }
        }
    }

    /// Searches this database for functions whose name matches the given regular expression.
    pub fn find_functions_by_name_regex(
        &self,
        regex: &str,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_name_regex(regex) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error(
                    "Serious problem search for FID Functions by regular expression",
                    &e,
                );
                None
            }
        }
    }

    /// Searches this database for functions that match a domain path substring.
    pub fn find_functions_by_domain_path_substring(
        &self,
        domain_path: &str,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_domain_path_substring(domain_path) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error("Serious problem searching for FID Functions by domain path", &e);
                None
            }
        }
    }

    /// Returns the first full hash value in the database greater than or equal to `value`, or
    /// `None` if there is no such hash. Useful for iterating over all function records in
    /// (arbitrarily, but deterministically) sorted full hash order.
    pub fn find_full_hash_value_at_or_after(&self, value: i64) -> Option<i64> {
        let table = self.functions_table.as_ref()?;
        match table.get_full_hash_value_at_or_after(value) {
            Ok(search) => search,
            Err(e) => {
                self.log_error("Serious problem searching for full hash values", &e);
                None
            }
        }
    }

    /// Returns all the function records that have the provided specific hash.
    pub fn find_functions_by_specific_hash(
        &self,
        specific_hash: i64,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_specific_hash(specific_hash) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error("Serious problem searching for FID Functions by specific hash", &e);
                None
            }
        }
    }

    /// Returns all the function records that have the provided full hash.
    pub fn find_functions_by_full_hash(
        &self,
        full_hash: i64,
    ) -> Option<Vec<Arc<dyn FunctionRecord>>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_records_by_full_hash(full_hash) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error("Serious problem searching for FID Functions by full hash", &e);
                None
            }
        }
    }

    /// Returns libraries by name, restricted by `version` and `variant` when those are supplied
    /// (Java passes `null` for "any").
    pub fn find_libraries_by_name(
        &self,
        family: &str,
        version: Option<&str>,
        variant: Option<&str>,
    ) -> Option<Vec<LibraryRecord>> {
        let table = self.libraries_table.as_ref()?;
        match table.get_libraries_by_name(family, version, variant) {
            Ok(list) => Some(list),
            Err(e) => {
                self.log_error("Serious problem search for FID Libraries by name", &e);
                None
            }
        }
    }

    /// Returns true if a relation exists between a superior (caller) function and a full hash
    /// representing the inferior (callee) function.
    pub fn get_superior_full_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FidHashQuad,
    ) -> bool {
        let (Some(libraries), Some(relations)) =
            (self.libraries_table.as_ref(), self.relations_table.as_ref())
        else {
            return false;
        };
        match libraries
            .get_library_by_id(superior_function.get_library_id())
            .and_then(|library| match library {
                Some(_) => relations.get_superior_full_relation(superior_function, inferior_function),
                None => Ok(false),
            }) {
            Ok(found) => found,
            Err(e) => {
                self.log_error("Serious problem in getSuperiorFullRelation", &e);
                false
            }
        }
    }

    /// Returns true if a relation exists between an inferior (callee) function and a full hash
    /// representing the superior (caller) function.
    pub fn get_inferior_full_relation(
        &self,
        superior_function: &dyn FidHashQuad,
        inferior_function: &dyn FunctionRecord,
    ) -> bool {
        let (Some(libraries), Some(relations)) =
            (self.libraries_table.as_ref(), self.relations_table.as_ref())
        else {
            return false;
        };
        match libraries
            .get_library_by_id(inferior_function.get_library_id())
            .and_then(|library| match library {
                Some(_) => relations.get_inferior_full_relation(superior_function, inferior_function),
                None => Ok(false),
            }) {
            Ok(found) => found,
            Err(e) => {
                self.log_error("Serious problem in getInferiorFullRelation", &e);
                false
            }
        }
    }

    /// Returns a single function record given its id, or `None` if no such record exists.
    pub fn get_function_by_id(&self, function_id: i64) -> Option<Arc<dyn FunctionRecord>> {
        let table = self.functions_table.as_ref()?;
        match table.get_function_by_id(function_id) {
            Ok(record) => record,
            Err(e) => {
                self.log_error("Serious problem finding Function record by ID", &e);
                None
            }
        }
    }

    /// Returns the library record in which the provided function record resides.
    pub fn get_library_for_function(
        &self,
        function_record: &dyn FunctionRecord,
    ) -> Option<LibraryRecord> {
        let table = self.libraries_table.as_ref()?;
        match table.get_library_by_id(function_record.get_library_id()) {
            Ok(record) => record.map(LibraryRecord::new),
            Err(e) => {
                self.log_error("Serious problem finding Library for function", &e);
                None
            }
        }
    }

    pub fn get_db_handle(&self) -> &DBHandle {
        &self.handle
    }

    /// Creates a new library using the parameters supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn create_new_library(
        &self,
        library_family_name: &str,
        library_version: &str,
        library_variant: &str,
        ghidra_version: &str,
        language_id: &LanguageID,
        language_version: i32,
        language_minor_version: i32,
        compiler_spec_id: &CompilerSpecID,
    ) -> Option<LibraryRecord> {
        if let Err(e) = self.check_update_allowed() {
            Msg::error(&self.to_string(), &e);
            return None;
        }
        let table = self.libraries_table.as_ref()?;
        match table.create_library(
            library_family_name,
            library_version,
            library_variant,
            ghidra_version,
            language_id,
            language_version,
            language_minor_version,
            compiler_spec_id,
        ) {
            Ok(record) => Some(LibraryRecord::new(record)),
            Err(e) => {
                self.log_error("Serious problem creating FID Library record", &e);
                None
            }
        }
    }

    fn check_update_allowed(&self) -> Result<(), ReadOnlyException> {
        if !self.open_for_update {
            return Err(ReadOnlyException::new(&format!(
                "Attempted to modify Fid Database that is not open for update: {self}"
            )));
        }
        Ok(())
    }

    /// Creates a new function record in a specific library in this FID database.
    pub fn create_new_function(
        &self,
        library: &LibraryRecord,
        hash_quad: &dyn FidHashQuad,
        name: &str,
        entry_point: i64,
        domain_path: &str,
        has_terminator: bool,
    ) -> Option<Arc<dyn FunctionRecord>> {
        if let Err(e) = self.check_update_allowed() {
            Msg::error(&self.to_string(), &e);
            return None;
        }
        let table = self.functions_table.as_ref()?;
        match table.create_function_record(
            library.get_library_id(),
            hash_quad,
            name,
            entry_point,
            domain_path,
            has_terminator,
        ) {
            Ok(record) => Some(record),
            Err(e) => {
                self.log_error("Serious problem creating FID Function record", &e);
                None
            }
        }
    }

    /// Creates a new relation record between a superior (caller) and inferior (callee) function.
    pub fn create_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FunctionRecord,
        relation_type: RelationType,
    ) {
        if let Err(e) = self.check_update_allowed() {
            Msg::error(&self.to_string(), &e);
            return;
        }
        let Some(relations) = self.relations_table.as_ref() else {
            return;
        };
        if let Err(e) =
            relations.create_relation(superior_function, inferior_function, relation_type)
        {
            self.log_error("Serious problem creating FID Relation record", &e);
        }
    }

    /// Creates only an inferior relation, used for special distinguishing parent relationships
    /// with common functions.
    pub fn create_inferior_relation(
        &self,
        superior_function: &dyn FunctionRecord,
        inferior_function: &dyn FunctionRecord,
    ) {
        if let Err(e) = self.check_update_allowed() {
            Msg::error(&self.to_string(), &e);
            return;
        }
        let Some(relations) = self.relations_table.as_ref() else {
            return;
        };
        if let Err(e) = relations.create_inferior_relation(superior_function, inferior_function) {
            self.log_error("Serious problem creating FID Inferior Relation record", &e);
        }
    }

    /// Modifies a single flag to a specific value across a list of functions.
    fn modify_flags(
        &self,
        func_list: &[Arc<dyn FunctionRecord>],
        flag_mask: i32,
        value: bool,
    ) -> io::Result<()> {
        let table = self.functions_table()?;
        for func_rec in func_list {
            table.modify_flags(func_rec.get_key(), flag_mask, value)?;
        }
        Ok(())
    }

    /// Modifies a flag of a `FunctionRecord` in the database and returns the reloaded record.
    ///
    /// Java first rejects records that belong to a different `FidDB` (`funcRec.getFidDb() != this`).
    /// That check is an object-identity comparison against the owning database, which a
    /// `FunctionRecord` stub cannot express without handing back a borrow of its owner, so it is
    /// dropped until `FunctionRecord` is ported.
    fn modify_function_flag(
        &self,
        func_rec: &dyn FunctionRecord,
        flag_mask: i32,
        value: bool,
    ) -> io::Result<Arc<dyn FunctionRecord>> {
        let table = self.functions_table()?;
        let key = func_rec.get_key();
        table.modify_flags(key, flag_mask, value)?;
        table.get_function_by_id(key)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Could not recover modified FunctionRecord")
        })
    }

    fn set_flag_by_full_hash(&self, hash: i64, flag_mask: i32, value: bool) -> io::Result<()> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        let func_list = self.find_functions_by_full_hash(hash).unwrap_or_default();
        self.modify_flags(&func_list, flag_mask, value)
    }

    fn set_flag_by_name(
        &self,
        library: &str,
        version: Option<&str>,
        variant: Option<&str>,
        function_name: &str,
        flag_mask: i32,
        value: bool,
    ) -> io::Result<()> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        let library_list = self.find_libraries_by_name(library, version, variant).unwrap_or_default();
        for lib_rec in &library_list {
            let func_list =
                self.find_functions_by_library_and_name(lib_rec, function_name).unwrap_or_default();
            self.modify_flags(&func_list, flag_mask, value)?;
        }
        Ok(())
    }

    /// Changes the auto-pass property for all functions with the given full hash.
    pub fn set_auto_pass_by_full_hash(&self, hash: i64, value: bool) -> io::Result<()> {
        self.set_flag_by_full_hash(hash, AUTO_PASS_FLAG, value)
    }

    /// Changes the auto-fail property for all functions with the given full hash.
    pub fn set_auto_fail_by_full_hash(&self, hash: i64, value: bool) -> io::Result<()> {
        self.set_flag_by_full_hash(hash, AUTO_FAIL_FLAG, value)
    }

    /// Changes the force-specific property for all functions with the given full hash.
    pub fn set_force_specific_by_full_hash(&self, hash: i64, value: bool) -> io::Result<()> {
        self.set_flag_by_full_hash(hash, FORCE_SPECIFIC_FLAG, value)
    }

    /// Changes the force-relation property for all functions with the given full hash.
    pub fn set_force_relation_by_full_hash(&self, hash: i64, value: bool) -> io::Result<()> {
        self.set_flag_by_full_hash(hash, FORCE_RELATION_FLAG, value)
    }

    /// Changes the auto-pass property on the given record, returning the reloaded record.
    pub fn set_auto_pass_on_function(
        &self,
        func_rec: &dyn FunctionRecord,
        value: bool,
    ) -> io::Result<Arc<dyn FunctionRecord>> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        self.modify_function_flag(func_rec, AUTO_PASS_FLAG, value)
    }

    /// Changes the auto-fail property on the given record, returning the reloaded record.
    pub fn set_auto_fail_on_function(
        &self,
        func_rec: &dyn FunctionRecord,
        value: bool,
    ) -> io::Result<Arc<dyn FunctionRecord>> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        self.modify_function_flag(func_rec, AUTO_FAIL_FLAG, value)
    }

    /// Changes the force-specific property on the given record, returning the reloaded record.
    pub fn set_force_specific_on_function(
        &self,
        func_rec: &dyn FunctionRecord,
        value: bool,
    ) -> io::Result<Arc<dyn FunctionRecord>> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        self.modify_function_flag(func_rec, FORCE_SPECIFIC_FLAG, value)
    }

    /// Changes the force-relation property on the given record, returning the reloaded record.
    pub fn set_force_relation_on_function(
        &self,
        func_rec: &dyn FunctionRecord,
        value: bool,
    ) -> io::Result<Arc<dyn FunctionRecord>> {
        self.check_update_allowed().map_err(read_only_to_io)?;
        self.modify_function_flag(func_rec, FORCE_RELATION_FLAG, value)
    }

    /// Changes the auto-pass property for all functions with the given name.
    pub fn set_auto_pass_by_name(
        &self,
        library: &str,
        version: Option<&str>,
        variant: Option<&str>,
        function_name: &str,
        value: bool,
    ) -> io::Result<()> {
        self.set_flag_by_name(library, version, variant, function_name, AUTO_PASS_FLAG, value)
    }

    /// Changes the auto-fail property for all functions with the given name.
    pub fn set_auto_fail_by_name(
        &self,
        library: &str,
        version: Option<&str>,
        variant: Option<&str>,
        function_name: &str,
        value: bool,
    ) -> io::Result<()> {
        self.set_flag_by_name(library, version, variant, function_name, AUTO_FAIL_FLAG, value)
    }

    /// Changes the force-specific property for all functions with the given name.
    pub fn set_force_specific_by_name(
        &self,
        library: &str,
        version: Option<&str>,
        variant: Option<&str>,
        function_name: &str,
        value: bool,
    ) -> io::Result<()> {
        self.set_flag_by_name(library, version, variant, function_name, FORCE_SPECIFIC_FLAG, value)
    }

    /// Changes the force-relation property for all functions with the given name.
    pub fn set_force_relation_by_name(
        &self,
        library: &str,
        version: Option<&str>,
        variant: Option<&str>,
        function_name: &str,
        value: bool,
    ) -> io::Result<()> {
        self.set_flag_by_name(library, version, variant, function_name, FORCE_RELATION_FLAG, value)
    }

    /// Saves the database. Java requires this after one or more transactions and before Ghidra
    /// exits, otherwise all changes are lost.
    ///
    /// A database that is not open for update has nothing to save and returns `Ok`, as in Java.
    /// Otherwise this reports that `DBHandle`'s transaction and save API is not ported yet rather
    /// than silently dropping the changes.
    pub fn save_database(&mut self, _comment: &str, _monitor: &dyn TaskMonitor) -> io::Result<()> {
        if !self.open_for_update {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DBHandle.save and its transaction API are not ported yet; cannot save the FID database",
        ))
    }
}

impl fmt::Display for FidDB {
    /// Java: `toString()` returns `"FidDB: " + fidFile.getFile().getAbsolutePath()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FidDB: {}", self.fid_file.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use crate::util::task::DummyMonitor;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    struct FakeFidFile {
        path: String,
        installed: bool,
        closed: AtomicBool,
    }

    impl FakeFidFile {
        fn new(path: &str, installed: bool) -> Arc<Self> {
            Arc::new(Self {
                path: path.to_string(),
                installed,
                closed: AtomicBool::new(false),
            })
        }
    }

    impl FidFile for FakeFidFile {
        fn get_name(&self) -> String {
            self.path.rsplit('/').next().unwrap_or(&self.path).to_string()
        }
        fn get_path(&self) -> String {
            self.path.clone()
        }
        fn is_installed(&self) -> bool {
            self.installed
        }
        fn closing_fid_db(&self, _fid_db: &FidDB) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    fn library_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            6,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::String,
                FieldType::String,
                FieldType::String,
                FieldType::Int,
                FieldType::Int,
                FieldType::String,
            ],
            vec![
                "LibraryFamilyName".to_string(),
                "LibraryVersion".to_string(),
                "LibraryVariant".to_string(),
                "GhidraVersion".to_string(),
                "GhidraLanguageID".to_string(),
                "GhidraLanguageVersion".to_string(),
                "GhidraLanguageMinorVersion".to_string(),
                "GhidraCompilerSpecID".to_string(),
            ],
            vec![],
        ))
    }

    fn library_record(key: i64, family: &str, version: &str, variant: &str) -> DBRecord {
        let mut record = DBRecord::new(library_schema(), Field::Long(Some(key)));
        record.set_string(0, Some(family.to_string()));
        record.set_string(1, Some(version.to_string()));
        record.set_string(2, Some(variant.to_string()));
        record.set_string(3, Some("11.0".to_string()));
        record.set_string(4, Some("x86:LE:64:default".to_string()));
        record.set_int(5, 1);
        record.set_int(6, 0);
        record.set_string(7, Some("gcc".to_string()));
        record
    }

    #[derive(Default)]
    struct FakeLibrariesTable {
        /// library id -> (family, version, variant)
        libraries: Mutex<Vec<(i64, String, String, String)>>,
        next_key: AtomicI32,
    }

    impl LibrariesTable for FakeLibrariesTable {
        fn create_library(
            &self,
            library_family_name: &str,
            library_version: &str,
            library_variant: &str,
            _ghidra_version: &str,
            _language_id: &LanguageID,
            _language_version: i32,
            _language_minor_version: i32,
            _compiler_spec_id: &CompilerSpecID,
        ) -> io::Result<DBRecord> {
            let key = self.next_key.fetch_add(1, Ordering::SeqCst) as i64 + 1;
            self.libraries.lock().unwrap().push((
                key,
                library_family_name.to_string(),
                library_version.to_string(),
                library_variant.to_string(),
            ));
            Ok(library_record(key, library_family_name, library_version, library_variant))
        }

        fn get_libraries(&self) -> io::Result<Vec<LibraryRecord>> {
            Ok(self
                .libraries
                .lock()
                .unwrap()
                .iter()
                .map(|(k, f, ver, var)| LibraryRecord::new(library_record(*k, f, ver, var)))
                .collect())
        }

        fn get_libraries_by_name(
            &self,
            family: &str,
            version: Option<&str>,
            variant: Option<&str>,
        ) -> io::Result<Vec<LibraryRecord>> {
            Ok(self
                .libraries
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, f, ver, var)| {
                    f == family
                        && version.is_none_or(|v| v == ver)
                        && variant.is_none_or(|v| v == var)
                })
                .map(|(k, f, ver, var)| LibraryRecord::new(library_record(*k, f, ver, var)))
                .collect())
        }

        fn get_library_by_id(&self, id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .libraries
                .lock()
                .unwrap()
                .iter()
                .find(|(k, ..)| *k == id)
                .map(|(k, f, ver, var)| library_record(*k, f, ver, var)))
        }
    }

    struct FakeStringsTable;
    impl StringsTable for FakeStringsTable {}

    #[derive(Clone)]
    struct FakeFunctionRecord {
        key: i64,
        library_id: i64,
        name: String,
        full_hash: i64,
        flags: i32,
    }

    impl FidHashQuad for FakeFunctionRecord {
        fn code_unit_size(&self) -> i16 {
            4
        }
        fn full_hash(&self) -> i64 {
            self.full_hash
        }
        fn specific_hash_additional_size(&self) -> i8 {
            0
        }
        fn specific_hash(&self) -> i64 {
            self.full_hash ^ 1
        }
    }

    impl FunctionRecord for FakeFunctionRecord {
        fn get_key(&self) -> i64 {
            self.key
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_library_id(&self) -> i64 {
            self.library_id
        }
    }

    #[derive(Default)]
    struct FakeFunctionsTable {
        functions: Mutex<HashMap<i64, FakeFunctionRecord>>,
        next_key: AtomicI32,
    }

    impl FakeFunctionsTable {
        fn seed(&self, key: i64, library_id: i64, name: &str, full_hash: i64) {
            self.functions.lock().unwrap().insert(
                key,
                FakeFunctionRecord {
                    key,
                    library_id,
                    name: name.to_string(),
                    full_hash,
                    flags: 0,
                },
            );
        }

        fn flags_of(&self, key: i64) -> i32 {
            self.functions.lock().unwrap()[&key].flags
        }

        fn collect(
            &self,
            pred: impl Fn(&FakeFunctionRecord) -> bool,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            let mut found: Vec<FakeFunctionRecord> =
                self.functions.lock().unwrap().values().filter(|f| pred(f)).cloned().collect();
            found.sort_by_key(|f| f.key);
            Ok(found.into_iter().map(|f| Arc::new(f) as Arc<dyn FunctionRecord>).collect())
        }
    }

    impl FunctionsTable for FakeFunctionsTable {
        fn get_full_hash_value_at_or_after(&self, value: i64) -> io::Result<Option<i64>> {
            Ok(self
                .functions
                .lock()
                .unwrap()
                .values()
                .map(|f| f.full_hash)
                .filter(|h| *h >= value)
                .min())
        }

        fn get_function_records_by_specific_hash(
            &self,
            hash: i64,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            self.collect(|f| f.specific_hash() == hash)
        }

        fn get_function_records_by_full_hash(
            &self,
            hash: i64,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            self.collect(|f| f.full_hash == hash)
        }

        fn create_function_record(
            &self,
            library_id: i64,
            hash_quad: &dyn FidHashQuad,
            name: &str,
            _entry_point: i64,
            _domain_path: &str,
            _has_terminator: bool,
        ) -> io::Result<Arc<dyn FunctionRecord>> {
            let key = self.next_key.fetch_add(1, Ordering::SeqCst) as i64 + 100;
            let record = FakeFunctionRecord {
                key,
                library_id,
                name: name.to_string(),
                full_hash: hash_quad.full_hash(),
                flags: 0,
            };
            self.functions.lock().unwrap().insert(key, record.clone());
            Ok(Arc::new(record))
        }

        fn get_function_records_by_name_substring(
            &self,
            name_search: &str,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            self.collect(|f| f.name.contains(name_search))
        }

        fn get_function_records_by_name_regex(
            &self,
            regex: &str,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            // Enough of a regex for the smoke tests: a trailing `.*` wildcard.
            let prefix = regex.trim_end_matches(".*");
            self.collect(|f| f.name.starts_with(prefix))
        }

        fn get_function_by_id(
            &self,
            function_id: i64,
        ) -> io::Result<Option<Arc<dyn FunctionRecord>>> {
            Ok(self
                .functions
                .lock()
                .unwrap()
                .get(&function_id)
                .cloned()
                .map(|f| Arc::new(f) as Arc<dyn FunctionRecord>))
        }

        fn get_function_records_by_domain_path_substring(
            &self,
            _domain_path_search: &str,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            self.collect(|_| true)
        }

        fn get_function_records_by_library_and_name(
            &self,
            library: &LibraryRecord,
            name: &str,
        ) -> io::Result<Vec<Arc<dyn FunctionRecord>>> {
            let library_id = library.get_library_id();
            self.collect(|f| f.library_id == library_id && f.name == name)
        }

        fn modify_flags(&self, function_id: i64, flag_mask: i32, value: bool) -> io::Result<()> {
            let mut functions = self.functions.lock().unwrap();
            let record = functions.get_mut(&function_id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Function record does not exist")
            })?;
            if value {
                record.flags |= flag_mask;
            } else {
                record.flags &= !flag_mask;
            }
            Ok(())
        }
    }

    struct Fixture {
        db: FidDB,
        fid_file: Arc<FakeFidFile>,
        functions: Arc<FakeFunctionsTable>,
        libraries: Arc<FakeLibrariesTable>,
    }

    fn fixture(installed: bool, open_for_update: bool) -> Fixture {
        let mut handle = DBHandle::new().expect("new db handle");
        RelationsTable::create_tables(&mut handle).expect("create relation tables");

        let fid_file = FakeFidFile::new("/opt/ghidra/fid/vs2015.fidb", installed);
        let libraries = Arc::new(FakeLibrariesTable::default());
        let functions = Arc::new(FakeFunctionsTable::default());

        libraries
            .create_library(
                "vs2015",
                "14.0",
                "x86",
                "11.0",
                &LanguageID::new("x86:LE:32:default").unwrap(),
                1,
                0,
                &CompilerSpecID::new(Some("windows")),
            )
            .expect("seed library");
        functions.seed(10, 1, "memcpy", 0x1111);
        functions.seed(11, 1, "memmove", 0x1111);
        functions.seed(12, 1, "strlen", 0x2222);
        // A function pointing at a library that does not exist in the libraries table.
        functions.seed(13, 99, "orphan", 0x3333);

        let db = FidDB::new(
            fid_file.clone(),
            handle,
            libraries.clone(),
            Arc::new(FakeStringsTable),
            functions.clone(),
            open_for_update,
        )
        .expect("open fid db");

        Fixture { db, fid_file, functions, libraries }
    }

    #[test]
    fn display_and_names_match_java_to_string() {
        let f = fixture(false, false);
        // Java: "FidDB: " + fidFile.getFile().getAbsolutePath()
        assert_eq!(f.db.to_string(), "FidDB: /opt/ghidra/fid/vs2015.fidb");
        assert_eq!(f.db.get_path(), "/opt/ghidra/fid/vs2015.fidb");
        assert_eq!(f.db.get_name(), "vs2015.fidb");
    }

    #[test]
    fn installed_file_is_forced_read_only() {
        // Java: openRawDatabaseFile() sets openForUpdate = false for installation files, so every
        // mutator goes through checkUpdateAllowed and fails.
        let f = fixture(true, true);
        assert!(f
            .db
            .create_new_library(
                "libc",
                "2.31",
                "glibc",
                "11.0",
                &LanguageID::new("x86:LE:64:default").unwrap(),
                1,
                0,
                &CompilerSpecID::new(Some("gcc")),
            )
            .is_none());
        let err = f.db.set_auto_pass_by_full_hash(0x1111, true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("not open for update"));
        // ...and the flag really was not applied.
        assert_eq!(f.functions.flags_of(10), 0);
    }

    #[test]
    fn set_auto_pass_by_full_hash_applies_java_flag_mask_to_every_match() {
        let f = fixture(false, true);
        f.db.set_auto_pass_by_full_hash(0x1111, true).expect("set auto pass");
        // Java: FunctionRecord.AUTO_PASS_FLAG == 2, applied to both 0x1111 functions only.
        assert_eq!(f.functions.flags_of(10), 2);
        assert_eq!(f.functions.flags_of(11), 2);
        assert_eq!(f.functions.flags_of(12), 0);

        f.db.set_force_relation_by_full_hash(0x1111, true).expect("set force relation");
        assert_eq!(f.functions.flags_of(10), 2 | 16);

        f.db.set_auto_pass_by_full_hash(0x1111, false).expect("clear auto pass");
        assert_eq!(f.functions.flags_of(10), 16);
    }

    #[test]
    fn set_flag_on_function_returns_reloaded_record() {
        let f = fixture(false, true);
        let original = f.db.get_function_by_id(12).expect("function 12");
        let updated = f
            .db
            .set_force_specific_on_function(original.as_ref(), true)
            .expect("set force specific");
        assert_eq!(updated.get_key(), 12);
        assert_eq!(updated.get_name(), "strlen");
        assert_eq!(f.functions.flags_of(12), FORCE_SPECIFIC_FLAG);
    }

    #[test]
    fn set_flag_by_name_walks_matching_libraries() {
        let f = fixture(false, true);
        f.db.set_auto_fail_by_name("vs2015", Some("14.0"), None, "memcpy", true)
            .expect("set auto fail by name");
        assert_eq!(f.functions.flags_of(10), AUTO_FAIL_FLAG);
        assert_eq!(f.functions.flags_of(11), 0);

        // A version that matches no library leaves everything untouched.
        f.db.set_auto_fail_by_name("vs2015", Some("13.0"), None, "memmove", true)
            .expect("no matching library");
        assert_eq!(f.functions.flags_of(11), 0);
    }

    #[test]
    fn searches_delegate_to_the_functions_table() {
        let f = fixture(false, false);
        let by_hash = f.db.find_functions_by_full_hash(0x1111).expect("search succeeded");
        assert_eq!(
            by_hash.iter().map(|r| r.get_name()).collect::<Vec<_>>(),
            vec!["memcpy", "memmove"]
        );
        let by_substring = f.db.find_functions_by_name_substring("mem").expect("search succeeded");
        assert_eq!(by_substring.len(), 2);
        assert_eq!(f.db.find_functions_by_name_regex("str.*").expect("regex").len(), 1);
        assert_eq!(f.db.find_full_hash_value_at_or_after(0x1112), Some(0x2222));
        assert_eq!(f.db.find_full_hash_value_at_or_after(0x9999), None);
        assert_eq!(f.db.get_all_libraries().len(), 1);
    }

    #[test]
    fn get_library_for_function_resolves_through_the_libraries_table() {
        let f = fixture(false, false);
        let func = f.db.get_function_by_id(10).expect("function 10");
        let library = f.db.get_library_for_function(func.as_ref()).expect("library for function");
        assert_eq!(library.get_library_family_name(), "vs2015");
        assert_eq!(library.get_library_version(), "14.0");

        // Java returns null when getLibraryByID finds no record.
        let orphan = f.db.get_function_by_id(13).expect("function 13");
        assert!(f.db.get_library_for_function(orphan.as_ref()).is_none());
    }

    #[test]
    fn relations_are_gated_on_the_owning_library_existing() {
        let f = fixture(false, true);
        let caller = f.db.get_function_by_id(10).expect("function 10");
        let callee = f.db.get_function_by_id(12).expect("function 12");
        f.db.create_relation(caller.as_ref(), callee.as_ref(), RelationType::DirectCall);

        assert!(f.db.get_superior_full_relation(caller.as_ref(), callee.as_ref()));
        assert!(f.db.get_inferior_full_relation(caller.as_ref(), callee.as_ref()));

        // Java: getSuperiorFullRelation short-circuits to false when the superior function's
        // library id resolves to no record, even though the relation itself was written.
        let orphan = f.db.get_function_by_id(13).expect("function 13");
        f.db.create_relation(orphan.as_ref(), callee.as_ref(), RelationType::DirectCall);
        assert!(!f.db.get_superior_full_relation(orphan.as_ref(), callee.as_ref()));
    }

    #[test]
    fn create_new_function_and_library_round_trip() {
        let f = fixture(false, true);
        let library = f
            .db
            .create_new_library(
                "libc",
                "2.31",
                "glibc",
                "11.0",
                &LanguageID::new("x86:LE:64:default").unwrap(),
                1,
                0,
                &CompilerSpecID::new(Some("gcc")),
            )
            .expect("create library");
        assert_eq!(library.get_library_family_name(), "libc");
        assert_eq!(f.libraries.get_libraries().unwrap().len(), 2);

        let quad = FakeFunctionRecord {
            key: 0,
            library_id: 0,
            name: String::new(),
            full_hash: 0x4444,
            flags: 0,
        };
        let created = f
            .db
            .create_new_function(&library, &quad, "printf", 0x401000, "/lib/libc", true)
            .expect("create function");
        assert_eq!(created.get_name(), "printf");
        assert_eq!(created.get_library_id(), library.get_library_id());
        assert_eq!(f.db.find_full_hash_value_at_or_after(0x4444), Some(0x4444));
    }

    #[test]
    fn close_honours_the_open_count() {
        let mut f = fixture(false, false);
        assert_eq!(f.db.open_count(), 1);
        f.db.increment_open_count();
        assert_eq!(f.db.open_count(), 2);

        f.db.close();
        // Still open for the remaining user: tables intact, FidFile not notified.
        assert!(!f.fid_file.closed.load(Ordering::SeqCst));
        assert!(f.db.get_strings_table().is_some());
        assert_eq!(f.db.get_all_libraries().len(), 1);

        f.db.close();
        assert!(f.fid_file.closed.load(Ordering::SeqCst));
        assert!(f.db.get_strings_table().is_none());
        // Java nulls the tables out; getAllLibraries then yields an empty list.
        assert!(f.db.get_all_libraries().is_empty());
        assert!(f.db.find_functions_by_full_hash(0x1111).is_none());
    }

    #[test]
    fn save_database_is_a_no_op_when_not_open_for_update() {
        let mut f = fixture(false, false);
        assert!(f.db.save_database("comment", &DummyMonitor).is_ok());

        let mut updateable = fixture(false, true);
        assert_eq!(
            updateable.db.save_database("comment", &DummyMonitor).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
