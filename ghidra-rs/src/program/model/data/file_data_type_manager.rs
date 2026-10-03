use thiserror::Error;

use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::data::file_archive_based_data_type_manager::FileArchiveBasedDataTypeManager;
use crate::program::model::data::stand_alone_data_type_manager::StandAloneDataTypeManager;
use crate::util::exception::DuplicateFileException;
use crate::util::universal_id::UniversalID;

/// Filename extension for a Ghidra data type archive file, without the leading `.`.
///
/// Port of `ghidra.program.model.data.FileDataTypeManager.EXTENSION`.
pub const EXTENSION: &str = "gdt";

/// Filename suffix (including the leading `.`) for a Ghidra data type archive file.
///
/// Port of `ghidra.program.model.data.FileDataTypeManager.SUFFIX`.
pub const SUFFIX: &str = ".gdt";

/// Error produced by [`FileDataTypeManager::save_as`]/[`FileDataTypeManager::save_as_with_id`],
/// standing in for the checked `DuplicateFileException`/`IOException` declared on the Java
/// methods `FileDataTypeManager.saveAs(File)`/`FileDataTypeManager.saveAs(File, UniversalID)`.
#[derive(Error, Debug)]
pub enum SaveAsError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateFileException),
    #[error("IOException: {0}")]
    Io(String),
}

/// Error produced by [`FileDataTypeManager::save`], standing in for the checked `IOException`
/// (and the unchecked `IllegalStateException` thrown when no output file has been set yet, see
/// [`SaveError::NoOutputFile`]) declared on the Java method `FileDataTypeManager.save()`.
#[derive(Error, Debug)]
pub enum SaveError {
    #[error("Output File was not specified: call saveAs(String)")]
    NoOutputFile,
    #[error("IOException: {0}")]
    Io(String),
}

/// Error produced by [`FileDataTypeManager::delete_archive`], standing in for the checked
/// `IOException` declared on the Java instance method `FileDataTypeManager.delete()`.
#[derive(Error, Debug)]
pub enum DeleteArchiveError {
    #[error("IOException: {0}")]
    Io(String),
}

/// DataTypeManager for a file. Can import categories from a file, or export categories to a
/// packed database.
///
/// Port of `ghidra.program.model.data.FileDataTypeManager`.
///
/// This trait was selected as a dependency-cycle cut-point. The Java class is `extends
/// StandAloneDataTypeManager implements FileArchiveBasedDataTypeManager`, so this trait carries
/// both as supertraits, mirroring that hierarchy exactly.
///
/// **Diamond landmine:** [`StandAloneDataTypeManager`] (via `DataTypeManagerDb::get_path`) and
/// [`FileArchiveBasedDataTypeManager`] (via `FileBasedDataTypeManager::get_path`) both declare a
/// same-shaped `fn get_path(&self) -> String`. Rust allows a type to implement both traits (one
/// method definition satisfies both obligations), but calling `.get_path()` through a merged `&dyn
/// FileDataTypeManager` reference is ambiguous and must be disambiguated with UFCS (e.g.
/// `FileBasedDataTypeManager::get_path(dyn_mgr)`), same as Java callers who'd see one overridden
/// method. This trait therefore does *not* redeclare `get_path` itself (redeclaring would only add
/// a third ambiguous candidate); concrete implementations override the supertrait method directly,
/// same as every other signature-matching `@Override` method
/// (`getName`/`setName`/`getPath`/`getType`/`close`, and the `StandAloneDataTypeManager` surface).
///
/// What *is* declared here is the genuinely new surface this concrete class introduces:
/// [`save_as`](Self::save_as)/[`save_as_with_id`](Self::save_as_with_id) (the two `saveAs`
/// overloads), [`save`](Self::save), [`get_filename`](Self::get_filename),
/// [`delete_archive`](Self::delete_archive) (the instance `delete()`), and
/// [`is_closed`](Self::is_closed).
///
/// Left unported (internal wiring, not part of the cycle): the private constructor and the four
/// static factory methods (`createFileArchive` x3, `openFileArchive` x2) -- a trait has no
/// constructors, concrete implementations own their own construction against a backing
/// `PackedDatabase`/`PackedDBHandle` (not yet ported); the static `convertFilename(File)` and
/// static `delete(File)` utilities, which operate on a bare file path with no live instance; the
/// private helpers `validateFilename`/`updateRootCategoryName`/`getRootName`; `finalize()` (Java's
/// GC-triggered finalizer has no Rust equivalent -- callers should rely on `Drop` on their own
/// concrete type instead); and the `OLD_EXTENSION`/`OLD_SUFFIX`/`GDT_FILEFILTER` constants, which
/// only matter to the unported static helpers above (`GDT_FILEFILTER` would additionally require
/// stubbing the not-yet-ported `ExtensionFileFilter`).
pub trait FileDataTypeManager: StandAloneDataTypeManager + FileArchiveBasedDataTypeManager {
    /// Saves the data type manager to the given file with a specific `UniversalID`.
    ///
    /// NOTE: intended for use in transforming one archive database to match another existing
    /// archive database.
    ///
    /// # Errors
    /// Returns `Err` if `save_file` already exists or an IO error occurs.
    fn save_as_with_id(
        &mut self,
        save_file: &ResourceFile,
        new_universal_id: UniversalID,
    ) -> Result<(), SaveAsError>;

    /// Saves the data type manager to the given file.
    ///
    /// # Errors
    /// Returns `Err` if `save_file` already exists or an IO error occurs.
    fn save_as(&mut self, save_file: &ResourceFile) -> Result<(), SaveAsError>;

    /// Save the category to the source file established by a prior
    /// [`save_as`](Self::save_as)/[`save_as_with_id`](Self::save_as_with_id) call.
    ///
    /// # Errors
    /// Returns [`SaveError::NoOutputFile`] if no output file has been established yet, or
    /// [`SaveError::Io`] if an IO error occurs.
    fn save(&mut self) -> Result<(), SaveError>;

    /// Get the filename for the current file, or `None` if there is no current file.
    fn get_filename(&self) -> Option<String>;

    /// Deletes the backing packed database archive, closing this data type manager first.
    ///
    /// Stands in for the instance method `FileDataTypeManager.delete()` (distinct from the
    /// unported static `FileDataTypeManager.delete(File)`).
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs.
    fn delete_archive(&mut self) -> Result<(), DeleteArchiveError>;

    /// Returns `true` if this archive has been closed (its backing packed database released).
    fn is_closed(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
    use crate::program::model::data::stand_alone_data_type_manager::{
        ArchiveWarning, ClearProgramArchitectureError, LanguageUpdateOption,
        SetProgramArchitectureError,
    };
    use crate::program::model::lang::{CompilerSpecID, Language};
    use crate::util::task::TaskMonitor;
    use std::io;

    struct MockFileArchive {
        name: String,
        file: Option<String>,
        closed: bool,
    }

    impl DataTypeManager for MockFileArchive {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl crate::program::database::data::data_type_manager_db::DataTypeManagerDb for MockFileArchive {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    impl StandAloneDataTypeManager for MockFileArchive {
        fn get_warning(&self) -> ArchiveWarning {
            ArchiveWarning::None
        }

        fn clear_program_architecture(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), ClearProgramArchitectureError> {
            Ok(())
        }

        fn set_program_architecture(
            &mut self,
            _language: Box<dyn Language>,
            _compiler_spec_id: CompilerSpecID,
            _update_option: LanguageUpdateOption,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), SetProgramArchitectureError> {
            Ok(())
        }

        fn undo(&mut self) {}
        fn redo(&mut self) {}
        fn can_redo(&self) -> bool {
            false
        }
        fn can_undo(&self) -> bool {
            false
        }
    }

    impl FileBasedDataTypeManager for MockFileArchive {
        fn get_path(&self) -> String {
            self.file.clone().unwrap_or_default()
        }
    }

    impl FileArchiveBasedDataTypeManager for MockFileArchive {}

    impl FileDataTypeManager for MockFileArchive {
        fn save_as_with_id(
            &mut self,
            save_file: &ResourceFile,
            _new_universal_id: UniversalID,
        ) -> Result<(), SaveAsError> {
            if self.file.as_deref() == Some(save_file.absolute_path().as_str()) {
                return Err(SaveAsError::Duplicate(DuplicateFileException::new(
                    save_file.absolute_path(),
                )));
            }
            self.file = Some(save_file.absolute_path());
            Ok(())
        }

        fn save_as(&mut self, save_file: &ResourceFile) -> Result<(), SaveAsError> {
            self.save_as_with_id(save_file, UniversalID::new(0))
        }

        fn save(&mut self) -> Result<(), SaveError> {
            if self.file.is_none() {
                return Err(SaveError::NoOutputFile);
            }
            Ok(())
        }

        fn get_filename(&self) -> Option<String> {
            self.file.clone()
        }

        fn delete_archive(&mut self) -> Result<(), DeleteArchiveError> {
            self.closed = true;
            self.file = None;
            Ok(())
        }

        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    #[test]
    fn usable_as_trait_object_and_drives_save_lifecycle() {
        let mut mgr = MockFileArchive {
            name: "MyArchive".to_string(),
            file: None,
            closed: false,
        };

        {
            let dyn_mgr: &mut dyn FileDataTypeManager = &mut mgr;
            assert_eq!(dyn_mgr.get_filename(), None);
            assert!(matches!(dyn_mgr.save(), Err(SaveError::NoOutputFile)));

            let target = ResourceFile::new(std::path::PathBuf::from("/tmp/archive.gdt"));
            dyn_mgr.save_as(&target).unwrap();
            assert_eq!(dyn_mgr.get_filename(), Some("/tmp/archive.gdt".to_string()));
            dyn_mgr.save().unwrap();

            assert!(matches!(
                dyn_mgr.save_as(&target),
                Err(SaveAsError::Duplicate(_))
            ));

            assert!(!dyn_mgr.is_closed());
            dyn_mgr.delete_archive().unwrap();
            assert!(dyn_mgr.is_closed());
            assert_eq!(dyn_mgr.get_filename(), None);
        }
    }

    #[test]
    fn get_path_diamond_requires_ufcs_disambiguation() {
        let mgr = MockFileArchive {
            name: "MyArchive".to_string(),
            file: Some("/tmp/other.gdt".to_string()),
            closed: false,
        };

        let dyn_mgr: &dyn FileDataTypeManager = &mgr;
        assert_eq!(
            FileBasedDataTypeManager::get_path(dyn_mgr),
            "/tmp/other.gdt".to_string()
        );
    }
}
