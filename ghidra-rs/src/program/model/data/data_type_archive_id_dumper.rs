use std::io::{self, Write};
use std::path::Path;

use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::file_data_type_manager::FileDataTypeManager;
use crate::program::seam_stubs::GhidraLaunchable;

/// Command-line utility that dumps the `UniversalID` of a data type archive file, followed by one
/// `<hex id> <path name>` line per contained datatype that has an id.
///
/// Port of `ghidra.program.model.data.DataTypeArchiveIdDumper`. The Java class `implements
/// GhidraLaunchable`, so this trait carries that as a supertrait, mirroring that relationship
/// exactly (see [`FileDataTypeManager`] for the established convention of mirroring
/// `extends`/`implements` relationships as Rust supertraits).
///
/// This trait was selected as a dependency-cycle cut-point.
///
/// [`dump`](Self::dump) reproduces the body of Java's `launch()` method: it opens the archive
/// (via [`open_archive`](Self::open_archive), a hook standing in for the static
/// `FileDataTypeManager.openFileArchive(File, boolean)` call -- a trait has no constructors, so
/// obtaining a concrete archive handle is left to implementors), logs any warning, and writes
/// `FILE_ID: <hex>` followed by one `<hex id> <path name>` line per datatype. A datatype whose
/// [`DataType::get_universal_id`](crate::program::model::data::data_type::DataType::get_universal_id)
/// is the `UniversalID::new(0)` sentinel is skipped -- this crate's `DataType`/`DataTypeManager`
/// ports already collapsed Java's nullable `getUniversalID()` into a non-null `UniversalID` with
/// that zero-value default standing in for "no id", so testing against it here reproduces Java's
/// `if (universalID != null)` check.
///
/// Left unported (internal wiring, not part of the cycle): the `launch(GhidraApplicationLayout,
/// String[])` entry point itself (argument-count validation, `System.exit`, opening the output
/// `FileWriter`, and `Application.initializeApplication(layout, new ApplicationConfiguration())`)
/// -- these are process-level CLI bootstrap concerns for a concrete binary, not part of the
/// archive-dumping logic that makes this type a cycle cut-point. Implementors of
/// [`GhidraLaunchable::launch`] are expected to parse `args`, open the output file, and delegate
/// to [`dump`](Self::dump).
pub trait DataTypeArchiveIdDumper: GhidraLaunchable {
    /// Opens the archive file at `archive_file`, standing in for the static
    /// `FileDataTypeManager.openFileArchive(File, boolean)` call in Java's `launch()` body.
    fn open_archive(&self, archive_file: &Path) -> io::Result<Box<dyn FileDataTypeManager>>;

    /// Dumps the archive's `FILE_ID` and each contained datatype's universal ID + path name to
    /// `writer`, mirroring the body of Java's `launch(GhidraApplicationLayout, String[])`.
    fn dump(&self, archive_file: &Path, writer: &mut dyn Write) -> io::Result<()> {
        let archive = self.open_archive(archive_file)?;
        archive.log_warning();
        let universal_id2 = archive.get_universal_id();
        writeln!(writer, "FILE_ID: {:x}", universal_id2.value())?;
        for dt in archive.get_all_data_types() {
            let universal_id = dt.get_universal_id();
            if universal_id.value() != 0 {
                writeln!(writer, "{:x} {}", universal_id.value(), dt.get_path_name())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
    use crate::program::model::data::file_archive_based_data_type_manager::FileArchiveBasedDataTypeManager;
    use crate::program::model::data::stand_alone_data_type_manager::{
        ArchiveWarning, ClearProgramArchitectureError, LanguageUpdateOption,
        SetProgramArchitectureError, StandAloneDataTypeManager,
    };
    use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
    use crate::program::model::lang::{CompilerSpecID, Language};
    use crate::program::seam_stubs::GhidraApplicationLayout;
    use crate::util::task::TaskMonitor;
    use crate::util::UniversalID;

    struct MockDataType {
        id: UniversalID,
        path_name: String,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.path_name.clone()
        }

        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }

        fn get_universal_id(&self) -> UniversalID {
            self.id
        }
    }

    struct MockArchive {
        universal_id: UniversalID,
        data_types: Vec<MockDataType>,
        file: Option<String>,
    }

    impl DataTypeManager for MockArchive {
        fn get_name(&self) -> String {
            "mock-archive".to_string()
        }

        fn get_universal_id(&self) -> UniversalID {
            self.universal_id
        }

        fn get_all_data_types(&self) -> Vec<Box<dyn DataType>> {
            self.data_types
                .iter()
                .map(|dt| {
                    Box::new(MockDataType {
                        id: dt.id,
                        path_name: dt.path_name.clone(),
                    }) as Box<dyn DataType>
                })
                .collect()
        }
    }

    impl DataTypeManagerDb for MockArchive {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    impl StandAloneDataTypeManager for MockArchive {
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

    impl FileBasedDataTypeManager for MockArchive {
        fn get_path(&self) -> String {
            self.file.clone().unwrap_or_default()
        }
    }

    impl FileArchiveBasedDataTypeManager for MockArchive {}

    impl FileDataTypeManager for MockArchive {
        fn save_as_with_id(
            &mut self,
            _save_file: &crate::generic::jar::resource_file::ResourceFile,
            _new_universal_id: UniversalID,
        ) -> Result<
            (),
            crate::program::model::data::file_data_type_manager::SaveAsError,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn save_as(
            &mut self,
            _save_file: &crate::generic::jar::resource_file::ResourceFile,
        ) -> Result<
            (),
            crate::program::model::data::file_data_type_manager::SaveAsError,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn save(
            &mut self,
        ) -> Result<(), crate::program::model::data::file_data_type_manager::SaveError> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_filename(&self) -> Option<String> {
            self.file.clone()
        }

        fn delete_archive(
            &mut self,
        ) -> Result<(), crate::program::model::data::file_data_type_manager::DeleteArchiveError>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_closed(&self) -> bool {
            false
        }
    }

    struct MockLayout;
    impl GhidraApplicationLayout for MockLayout {}

    struct MockDumper;

    impl GhidraLaunchable for MockDumper {
        fn launch(
            &mut self,
            _layout: &dyn GhidraApplicationLayout,
            _args: &[String],
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl DataTypeArchiveIdDumper for MockDumper {
        fn open_archive(&self, _archive_file: &Path) -> io::Result<Box<dyn FileDataTypeManager>> {
            Ok(Box::new(MockArchive {
                universal_id: UniversalID::new(0xCAFE),
                data_types: vec![
                    MockDataType {
                        id: UniversalID::new(0x2a),
                        path_name: "/Category/Foo".to_string(),
                    },
                    MockDataType {
                        id: UniversalID::new(0),
                        path_name: "/Category/NoId".to_string(),
                    },
                ],
                file: None,
            }))
        }
    }

    #[test]
    fn dump_writes_file_id_and_skips_unidentified_datatypes() {
        let dumper: Box<dyn DataTypeArchiveIdDumper> = Box::new(MockDumper);
        let mut output = Vec::new();

        dumper
            .dump(Path::new("archive.gdt"), &mut output)
            .expect("dump should succeed");

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, vec!["FILE_ID: cafe", "2a /Category/Foo"]);
    }
}
