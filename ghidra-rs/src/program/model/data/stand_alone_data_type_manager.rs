use thiserror::Error;

use crate::framework::store::LockException;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::lang::{
    CompilerSpecID, CompilerSpecNotFoundException, Language,
};
use crate::program::model::listing::IncompatibleLanguageException;
use crate::program::seam_stubs::LanguageNotFoundException;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Severity of an [`ArchiveWarning`].
///
/// Port of `ghidra.program.model.data.StandAloneDataTypeManager.ArchiveWarningLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveWarningLevel {
    Info,
    Warn,
    Error,
}

/// A warning condition that may have occurred immediately following instantiation of a
/// [`StandAloneDataTypeManager`].
///
/// Port of `ghidra.program.model.data.StandAloneDataTypeManager.ArchiveWarning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArchiveWarning {
    /// Indicates a normal archive condition.
    #[default]
    None,
    /// Indicates an archive open for update was upgraded to a newer language version.
    UpgradedLanguageVersion,
    /// Indicates the [`Language`] required by the associated program architecture was not
    /// found or encountered a problem being loaded.
    LanguageNotFound,
    /// Indicates the compiler spec required by the associated program architecture was not
    /// found or encountered a problem being loaded. Only occurs if the required language was
    /// found.
    CompilerSpecNotFound,
    /// Indicates an archive open read-only requires an upgrade to a newer language version.
    LanguageUpgradeRequired,
    /// Indicates an archive open read-only requires an upgrade to adjust for changes in the
    /// associated data organization.
    DataOrgChanged,
}

impl ArchiveWarning {
    /// Get the warning level.
    pub fn level(self) -> ArchiveWarningLevel {
        match self {
            ArchiveWarning::None | ArchiveWarning::UpgradedLanguageVersion => {
                ArchiveWarningLevel::Info
            }
            ArchiveWarning::LanguageUpgradeRequired | ArchiveWarning::DataOrgChanged => {
                ArchiveWarningLevel::Warn
            }
            ArchiveWarning::LanguageNotFound | ArchiveWarning::CompilerSpecNotFound => {
                ArchiveWarningLevel::Error
            }
        }
    }
}

/// Indicates how variable storage data should be transitioned when
/// [`StandAloneDataTypeManager::set_program_architecture`] changes the current language.
///
/// Port of `ghidra.program.model.data.StandAloneDataTypeManager.LanguageUpdateOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageUpdateOption {
    /// All existing storage data should be cleared.
    Clear,
    /// An attempt should be made to translate from old-to-new language. This has limitations
    /// (i.e. similar architecture) and may result in poor register mappings.
    Translate,
    /// Variable storage data will be retained as-is but may not de-serialize properly when
    /// used.
    Unchanged,
}

/// Error produced by [`StandAloneDataTypeManager::clear_program_architecture`], standing in for
/// the checked `CancelledException`/`IOException`/`LockException` and unchecked
/// `UnsupportedOperationException` declared on the Java method
/// `StandAloneDataTypeManager.clearProgramArchitecture(TaskMonitor)`.
#[derive(Error, Debug)]
pub enum ClearProgramArchitectureError {
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error("IOException: {0}")]
    Io(String),
    #[error(transparent)]
    Lock(#[from] LockException),
    #[error("UnsupportedOperationException: {0}")]
    UnsupportedOperation(String),
}

/// Error produced by [`StandAloneDataTypeManager::set_program_architecture`], standing in for
/// the checked `CompilerSpecNotFoundException`/`LanguageNotFoundException`/`IOException`/
/// `CancelledException`/`LockException`/`IncompatibleLanguageException` and unchecked
/// `UnsupportedOperationException` declared on the Java method
/// `StandAloneDataTypeManager.setProgramArchitecture(Language, CompilerSpecID,
/// LanguageUpdateOption, TaskMonitor)`.
#[derive(Error, Debug)]
pub enum SetProgramArchitectureError {
    #[error(transparent)]
    CompilerSpecNotFound(#[from] CompilerSpecNotFoundException),
    #[error(transparent)]
    LanguageNotFound(#[from] LanguageNotFoundException),
    #[error("IOException: {0}")]
    Io(String),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Lock(#[from] LockException),
    #[error("UnsupportedOperationException: {0}")]
    UnsupportedOperation(String),
    #[error(transparent)]
    IncompatibleLanguage(#[from] IncompatibleLanguageException),
}

/// Basic implementation of the `DataTypeManager` interface, usable as a standalone,
/// non-domain-file-backed archive.
///
/// Port of `ghidra.program.model.data.StandAloneDataTypeManager`.
///
/// This trait was selected as a dependency-cycle cut-point (referenced by
/// [`DataTypeArchive::get_data_type_manager`](crate::program::model::listing::data_type_archive::DataTypeArchive::get_data_type_manager)
/// and, via [`ProjectDataTypeManager`](crate::program::seam_stubs::ProjectDataTypeManager)'s
/// `extends` relationship, by
/// [`DataTypeArchiveDB::get_data_type_manager`](crate::program::database::data_type_archive_db::DataTypeArchiveDB::get_data_type_manager)).
/// It was previously modeled as an empty placeholder (`StandAloneDataTypeManager` in
/// `seam_stubs.rs`, see `STUBS.tsv`); this promotes that placeholder in place (same trait name,
/// same empty original surface -- a superset since nothing needs to be retained) so the
/// dependent files (`data_type_archive.rs`, `data_type_archive_db.rs`,
/// `data_type_archive_service.rs`) keep compiling against the same trait, just from its real
/// home.
///
/// `StandAloneDataTypeManager extends DataTypeManagerDB`, so this trait is bounded by the
/// already-ported [`DataTypeManagerDb`] rather than re-declaring its methods. Every `@Override`
/// method whose signature exactly matches a [`DataTypeManagerDb`]/`DataTypeManager` method
/// (`getName`, `setName`, `getPath`, `getDomainFileID`, `getType`, `flushEvents`, `close`,
/// `openTransaction`, `startTransaction`, `endTransaction`,
/// `replaceDataTypesUsed`/`deleteDataTypesUsed`) is *not* redeclared here; concrete
/// implementations override those supertrait methods directly.
///
/// What *is* declared here is the genuinely new surface this concrete class introduces: the
/// `ArchiveWarning`/`ArchiveWarningLevel`/`LanguageUpdateOption` nested types, warning
/// inspection (`get_warning`, `get_warning_detail`, `get_warning_message`, `log_warning`),
/// program-architecture change plumbing (`is_program_architecture_upgrade_required`,
/// `is_program_architecture_missing`, `clear_program_architecture`, `set_program_architecture`,
/// `is_architecture_change_allowed`), and undo/redo/transaction-history bookkeeping (`undo`,
/// `redo`, `can_undo`, `can_redo`, `get_undo_name`, `get_redo_name`, `get_all_undo_names`,
/// `get_all_redo_names`).
///
/// Left unported (internal wiring, not part of the cycle): the four constructors (a trait has no
/// constructors -- concrete implementations own their own construction), `initializeOtherAdapters`
/// and `handleDataOrganizationChange` (protected extension points overriding abstract
/// `DataTypeManagerDB` hooks against `DBHandle`/adapters not yet exposed on
/// [`DataTypeManagerDb`]), the protected `setProgramArchitecture(ProgramArchitecture,
/// VariableStorageManager, boolean, TaskMonitor)` override (same reason -- its abstract
/// declaration lives on `DataTypeManagerDB` and was not part of that trait's ported surface),
/// `setImmutable`/`initTransactionState`/`getTransactionCount`/`clearUndo` (protected
/// lifecycle hooks only meaningful to a concrete implementation's own constructor/field
/// bookkeeping), and the private helpers `deleteAllProgramArchitectureData`,
/// `createProgramArchitectureData`, `clearCustomStorageUse`.
///
/// `get_warning_detail` models the Java `Exception` return as `Option<String>` (the exception's
/// message) since there is no general-purpose exception type in this crate to return instead.
pub trait StandAloneDataTypeManager: DataTypeManagerDb {
    /// Get the [`ArchiveWarning`] which may have occurred immediately following instantiation of
    /// this data type manager. [`ArchiveWarning::None`] is returned if there is no warning
    /// condition.
    fn get_warning(&self) -> ArchiveWarning {
        ArchiveWarning::None
    }

    /// Get the detail message of the exception associated with
    /// [`ArchiveWarning::LanguageNotFound`] or [`ArchiveWarning::CompilerSpecNotFound`] (see
    /// [`get_warning`](Self::get_warning)) immediately following instantiation of this data type
    /// manager.
    fn get_warning_detail(&self) -> Option<String> {
        None
    }

    /// Get a suitable warning message. See [`get_warning`](Self::get_warning) for the type and
    /// its severity level ([`ArchiveWarning::level`]).
    ///
    /// Returns `None` if [`get_warning`](Self::get_warning) is [`ArchiveWarning::None`].
    fn get_warning_message(&self, include_details: bool) -> Option<String> {
        let detail_suffix = || {
            if include_details {
                format!(
                    " '{}': {}",
                    self.get_name(),
                    self.get_warning_detail().unwrap_or_default()
                )
            } else {
                String::new()
            }
        };
        let summary_suffix = || {
            if include_details {
                format!(
                    " '{}': {}",
                    self.get_name(),
                    self.get_program_architecture_summary().unwrap_or_default()
                )
            } else {
                String::new()
            }
        };
        match self.get_warning() {
            ArchiveWarning::LanguageNotFound => {
                Some(format!("Language not found for Archive{}", detail_suffix()))
            }
            ArchiveWarning::CompilerSpecNotFound => Some(format!(
                "Compiler specification not found for Archive{}",
                detail_suffix()
            )),
            ArchiveWarning::LanguageUpgradeRequired => Some(format!(
                "Language upgrade required for Archive{}",
                summary_suffix()
            )),
            ArchiveWarning::UpgradedLanguageVersion => {
                let msg = "Upgraded program-architecture for Archive".to_string();
                if include_details {
                    Some(format!("{} '{}'", msg, self.get_name()))
                } else {
                    Some(msg)
                }
            }
            ArchiveWarning::DataOrgChanged => Some(format!(
                "Data organization upgrade required for Archive{}",
                summary_suffix()
            )),
            ArchiveWarning::None => None,
        }
    }

    /// Due to the suppression of error and warning conditions during instantiation this method
    /// should be invoked at the end of instantiation, once `get_name`/`get_path` are ready to be
    /// invoked safely. Logging is performed via [`Msg`](crate::util::Msg).
    fn log_warning(&self) {
        let Some(msg) = self.get_warning_message(true) else {
            return;
        };
        match self.get_warning().level() {
            ArchiveWarningLevel::Error => crate::util::Msg::error("StandAloneDataTypeManager", &msg),
            ArchiveWarningLevel::Warn => crate::util::Msg::warn("StandAloneDataTypeManager", &msg),
            ArchiveWarningLevel::Info => crate::util::Msg::info("StandAloneDataTypeManager", &msg),
        }
    }

    /// Indicates that a program architecture upgrade is required in order to constitute
    /// associated data. If true, the associated archive must be open for update to allow the
    /// upgrade to complete, or a new program architecture may be set/cleared if such an
    /// operation is supported.
    fn is_program_architecture_upgrade_required(&self) -> bool {
        self.get_warning() == ArchiveWarning::LanguageUpgradeRequired
    }

    /// Indicates that a failure occurred establishing the program architecture for the
    /// associated archive.
    fn is_program_architecture_missing(&self) -> bool {
        matches!(
            self.get_warning(),
            ArchiveWarning::LanguageNotFound | ArchiveWarning::CompilerSpecNotFound
        )
    }

    /// Determine if a program architecture change is permitted.
    fn is_architecture_change_allowed(&self) -> bool {
        true
    }

    /// Clear the program architecture setting and all architecture-specific data from this
    /// archive. Archive will revert to using the default data organization. Archive must be
    /// open for update for this method to be used.
    ///
    /// # Errors
    /// Returns `Err` if a change is not permitted, the archive is read-only, an IO error occurs,
    /// exclusive access could not be obtained, or the task is cancelled (in which case this data
    /// type manager is no longer stable and should be closed without saving).
    fn clear_program_architecture(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ClearProgramArchitectureError>;

    /// Establish the program architecture for this datatype manager. The current setting can be
    /// determined from [`DataTypeManager::get_program_architecture`](crate::program::model::data::data_type_manager::DataTypeManager::get_program_architecture).
    /// Archive must be open for update for this method to be used.
    ///
    /// `monitor`'s cancellation is not permitted to avoid corrupting state.
    ///
    /// # Errors
    /// Returns `Err` if the compiler spec ID is invalid for `language`, the current language is
    /// not found (if required for data transition), an IO error occurs, the task is cancelled
    /// (in which case this data type manager is no longer stable and should be closed without
    /// saving), exclusive access could not be obtained, the change is not permitted, or
    /// translation was requested but is not possible due to incompatible language
    /// architectures.
    fn set_program_architecture(
        &mut self,
        language: Box<dyn Language>,
        compiler_spec_id: CompilerSpecID,
        update_option: LanguageUpdateOption,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SetProgramArchitectureError>;

    /// Undo the most recent transaction (see [`can_undo`](Self::can_undo)).
    fn undo(&mut self);

    /// Redo the most recently undone transaction (see [`can_redo`](Self::can_redo)).
    fn redo(&mut self);

    /// Determine if there is a transaction previously undone (see [`undo`](Self::undo)) that can
    /// be redone (see [`redo`](Self::redo)).
    fn can_redo(&self) -> bool;

    /// Determine if there is a previous transaction that can be reverted/undone (see
    /// [`undo`](Self::undo)).
    fn can_undo(&self) -> bool;

    /// Get the transaction name that is available for [`redo`](Self::redo) (see
    /// [`can_redo`](Self::can_redo)).
    fn get_redo_name(&self) -> String {
        String::new()
    }

    /// Get the transaction name that is available for [`undo`](Self::undo) (see
    /// [`can_undo`](Self::can_undo)).
    fn get_undo_name(&self) -> String {
        String::new()
    }

    /// Get all transaction names that are available within the [`undo`](Self::undo) stack.
    fn get_all_undo_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get all transaction names that are available within the [`redo`](Self::redo) stack.
    fn get_all_redo_names(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use std::io;

    struct MockManager {
        name: String,
        warning: ArchiveWarning,
        warning_detail: Option<String>,
        undo_stack: Vec<String>,
        redo_stack: Vec<String>,
    }

    impl DataTypeManager for MockManager {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl DataTypeManagerDb for MockManager {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    impl StandAloneDataTypeManager for MockManager {
        fn get_warning(&self) -> ArchiveWarning {
            self.warning
        }

        fn get_warning_detail(&self) -> Option<String> {
            self.warning_detail.clone()
        }

        fn clear_program_architecture(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), ClearProgramArchitectureError> {
            self.warning = ArchiveWarning::None;
            Ok(())
        }

        fn set_program_architecture(
            &mut self,
            _language: Box<dyn Language>,
            _compiler_spec_id: CompilerSpecID,
            _update_option: LanguageUpdateOption,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), SetProgramArchitectureError> {
            self.undo_stack.push("Set Program Architecture".to_string());
            Ok(())
        }

        fn undo(&mut self) {
            if let Some(name) = self.undo_stack.pop() {
                self.redo_stack.push(name);
            }
        }

        fn redo(&mut self) {
            if let Some(name) = self.redo_stack.pop() {
                self.undo_stack.push(name);
            }
        }

        fn can_redo(&self) -> bool {
            !self.redo_stack.is_empty()
        }

        fn can_undo(&self) -> bool {
            !self.undo_stack.is_empty()
        }

        fn get_undo_name(&self) -> String {
            self.undo_stack.last().cloned().unwrap_or_default()
        }

        fn get_all_undo_names(&self) -> Vec<String> {
            self.undo_stack.clone()
        }
    }

    #[test]
    fn archive_warning_level_matches_java_severity() {
        assert_eq!(ArchiveWarning::None.level(), ArchiveWarningLevel::Info);
        assert_eq!(
            ArchiveWarning::UpgradedLanguageVersion.level(),
            ArchiveWarningLevel::Info
        );
        assert_eq!(
            ArchiveWarning::LanguageUpgradeRequired.level(),
            ArchiveWarningLevel::Warn
        );
        assert_eq!(ArchiveWarning::DataOrgChanged.level(), ArchiveWarningLevel::Warn);
        assert_eq!(
            ArchiveWarning::LanguageNotFound.level(),
            ArchiveWarningLevel::Error
        );
        assert_eq!(
            ArchiveWarning::CompilerSpecNotFound.level(),
            ArchiveWarningLevel::Error
        );
    }

    #[test]
    fn usable_as_trait_object_and_drives_undo_redo() {
        let mut mgr = MockManager {
            name: "MyArchive".to_string(),
            warning: ArchiveWarning::LanguageNotFound,
            warning_detail: Some("boom".to_string()),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        };

        mgr.undo_stack.push("Set Program Architecture".to_string());

        {
            let dyn_mgr: &mut dyn StandAloneDataTypeManager = &mut mgr;
            assert!(dyn_mgr.is_program_architecture_missing());
            assert!(!dyn_mgr.is_program_architecture_upgrade_required());
            assert_eq!(
                dyn_mgr.get_warning_message(true),
                Some("Language not found for Archive 'MyArchive': boom".to_string())
            );

            dyn_mgr
                .clear_program_architecture(&crate::util::task::DummyMonitor)
                .unwrap();
            assert_eq!(dyn_mgr.get_warning(), ArchiveWarning::None);
            assert_eq!(dyn_mgr.get_warning_message(true), None);

            assert!(dyn_mgr.can_undo());
            assert_eq!(dyn_mgr.get_undo_name(), "Set Program Architecture");

            dyn_mgr.undo();
            assert!(!dyn_mgr.can_undo());
            assert!(dyn_mgr.can_redo());

            dyn_mgr.redo();
            assert!(dyn_mgr.can_undo());
            assert!(!dyn_mgr.can_redo());
        }

        assert_eq!(mgr.get_all_undo_names(), vec!["Set Program Architecture".to_string()]);
    }

    #[test]
    fn set_program_architecture_is_object_safe_and_records_transaction() {
        struct StubLanguage;
        impl Language for StubLanguage {
            fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
                crate::program::model::lang::LanguageID::new("stub:LE:32:default:1.0").unwrap()
            }
            fn get_language_description(&self) -> Box<dyn crate::program::model::lang::LanguageDescription> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_parallel_instruction_helper(
                &self,
            ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>> {
                None
            }
            fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_version(&self) -> i32 {
                1
            }
            fn get_minor_version(&self) -> i32 {
                0
            }
            fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_default_data_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn is_big_endian(&self) -> bool {
                false
            }
            fn get_instruction_alignment(&self) -> i32 {
                1
            }
            fn supports_pcode(&self) -> bool {
                true
            }
            fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
                false
            }
            fn parse(
                &self,
                _buf: &dyn crate::program::model::mem::MemBuffer,
                _context: &mut dyn crate::program::model::lang::ProcessorContext,
                _in_delay_slot: bool,
            ) -> Result<Box<dyn crate::program::model::lang::InstructionPrototype>, crate::program::model::lang::ParseError>
            {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_number_of_user_defined_op_names(&self) -> i32 {
                0
            }
            fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
                None
            }
            fn get_registers_at(
                &self,
                _address: &crate::program::model::address::Address,
            ) -> Vec<crate::program::model::lang::RegisterRef> {
                Vec::new()
            }
            fn get_register_in_space(
                &self,
                _addrspc: &std::sync::Arc<crate::program::model::address::AddressSpace>,
                _offset: i64,
                _size: i32,
            ) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
                Vec::new()
            }
            fn get_register_names(&self) -> Vec<String> {
                Vec::new()
            }
            fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_register_at(
                &self,
                _addr: &crate::program::model::address::Address,
                _size: i32,
            ) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_program_counter(&self) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_context_base_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_context_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
                Vec::new()
            }
            fn get_default_memory_blocks(
                &self,
            ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
                Vec::new()
            }
            fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
                Vec::new()
            }
            fn get_segmented_space(&self) -> String {
                String::new()
            }
            fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {}
            fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
                Ok(())
            }
            fn get_compatible_compiler_spec_descriptions(
                &self,
            ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
                Vec::new()
            }
            fn get_compiler_spec_by_id(
                &self,
                compiler_spec_id: &CompilerSpecID,
            ) -> Result<Box<dyn crate::program::model::lang::CompilerSpec>, CompilerSpecNotFoundException> {
                Err(CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ))
            }
            fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
                unimplemented!("not exercised by this smoke test")
            }
            fn has_property(&self, _key: &str) -> bool {
                false
            }
            fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
                default_int
            }
            fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
                default_boolean
            }
            fn get_property_or(&self, _key: &str, default_string: &str) -> String {
                default_string.to_string()
            }
            fn get_property(&self, _key: &str) -> Option<String> {
                None
            }
            fn get_property_keys(&self) -> std::collections::HashSet<String> {
                std::collections::HashSet::new()
            }
            fn has_manual(&self) -> bool {
                false
            }
            fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
                None
            }
            fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
                std::collections::HashSet::new()
            }
            fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
                None
            }
            fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
                Vec::new()
            }
            fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_maximum_instruction_length(&self) -> Option<i32> {
                None
            }
        }

        let mut mgr = MockManager {
            name: "MyArchive".to_string(),
            warning: ArchiveWarning::None,
            warning_detail: None,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        };

        mgr.set_program_architecture(
            Box::new(StubLanguage),
            CompilerSpecID::new(None),
            LanguageUpdateOption::Clear,
            &crate::util::task::DummyMonitor,
        )
        .unwrap();

        assert_eq!(mgr.get_undo_name(), "Set Program Architecture");
    }
}
