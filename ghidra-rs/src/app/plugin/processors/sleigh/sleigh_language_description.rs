//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageDescription`.
//!
//! In Java this is a concrete class extending `BasicLanguageDescription`; it was selected as a
//! dependency-cycle cut-point, so its instance surface is promoted to the
//! [`SleighLanguageDescription`] trait here. The inherited `BasicLanguageDescription` surface is
//! already ported as the [`LanguageDescription`] trait, so this trait requires it as a supertrait
//! and adds only the Sleigh-specific members (the `.defs`/`.pspec`/manual-index files, the
//! [`SleighLanguageFile`] association, address-space truncation info, and the "same `.sla` file"
//! comparison).
//!
//! Java's `getTruncatedSpaceSize(String)` throws an unchecked `NoSuchElementException` only when
//! the truncation map itself is absent (a missing key instead NPEs on auto-unboxing, since the
//! Java return type is primitive `int`); both cases collapse naturally to `None` here.

use std::collections::HashSet;

use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::language_description::LanguageDescription;

use super::sleigh_language_file::SleighLanguageFile;

/// Sleigh-specific language description: a [`LanguageDescription`] plus the `.defs`/`.pspec`
/// specification files, the associated [`SleighLanguageFile`] (`.sla`/`.slaspec`), and address
/// space truncation info. Port of the instance contract of
/// `ghidra.app.plugin.processors.sleigh.SleighLanguageDescription` (see the module docs for why
/// this is a trait).
pub trait SleighLanguageDescription: LanguageDescription {
    /// Set of address space names which have been identified for truncation. Port of
    /// `SleighLanguageDescription.getTruncatedSpaceNames()`.
    fn get_truncated_space_names(&self) -> HashSet<String>;

    /// Get the truncated space size, in bytes, for the specified address space. Port of
    /// `SleighLanguageDescription.getTruncatedSpaceSize(String)`. Returns `None` if there is no
    /// truncation info at all, or none for `space_name` specifically (see module docs).
    fn get_truncated_space_size(&self, space_name: &str) -> Option<i32>;

    /// Get the (optional) `.defs` file associated with this language. Port of
    /// `SleighLanguageDescription.getDefsFile()`.
    fn get_defs_file(&self) -> Option<&ResourceFile>;

    /// Set the (optional) `.defs` file associated with this language. Port of
    /// `SleighLanguageDescription.setDefsFile(ResourceFile)`.
    fn set_defs_file(&mut self, defs_file: Option<ResourceFile>);

    /// Get the (optional) `.pspec` specification file associated with this language. Port of
    /// `SleighLanguageDescription.getSpecFile()`.
    fn get_spec_file(&self) -> Option<&ResourceFile>;

    /// Set the (optional) `.pspec` specification file associated with this language. Port of
    /// `SleighLanguageDescription.setSpecFile(ResourceFile)`.
    fn set_spec_file(&mut self, spec_file: Option<ResourceFile>);

    /// Get the (optional) manual index file for this language. Port of
    /// `SleighLanguageDescription.getManualIndexFile()`.
    fn get_manual_index_file(&self) -> Option<&ResourceFile>;

    /// Set the (optional) manual index file for this language. Port of
    /// `SleighLanguageDescription.setManualIndexFile(ResourceFile)`.
    fn set_manual_index_file(&mut self, manual_index_file: Option<ResourceFile>);

    /// Get the [`SleighLanguageFile`] which represents the `.sla`/`.slaspec` files. Port of
    /// `SleighLanguageDescription.getLanguageFile()`.
    fn get_language_file(&self) -> Option<&dyn SleighLanguageFile>;

    /// Set the [`SleighLanguageFile`] which represents the `.sla`/`.slaspec` files. Port of
    /// `SleighLanguageDescription.setLanguageFile(SleighLanguageFile)` (package-private in Java).
    fn set_language_file(&mut self, language_file: Option<Box<dyn SleighLanguageFile>>);

    /// Tests if two Sleigh languages are based on the same `.sla` file. Port of
    /// `SleighLanguageDescription.isSameSleighLanguageFile(SleighLanguageDescription)`.
    ///
    /// Compares [`ResourceFile::absolute_path`] of each side's [`Self::get_language_file`]'s
    /// [`SleighLanguageFile::sla_file`], mirroring Java's `ResourceFile.equals`. Returns `false`
    /// if either side has no associated language file (Java instead throws a
    /// `NullPointerException` in that case, which is not a meaningful contract to preserve).
    fn is_same_sleigh_language_file(&self, other: &dyn SleighLanguageDescription) -> bool {
        let (Some(this_file), Some(other_file)) =
            (self.get_language_file(), other.get_language_file())
        else {
            return false;
        };
        this_file.sla_file().absolute_path() == other_file.sla_file().absolute_path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::Processor;

    struct MockProcessor;
    impl Processor for MockProcessor {}

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }

        fn get_compiler_spec_name(&self) -> String {
            "Default".to_string()
        }

        fn get_source(&self) -> String {
            "default.cspec".to_string()
        }
    }

    /// Mock [`SleighLanguageFile`] that only needs to support the `.sla` file identity used by
    /// [`SleighLanguageDescription::is_same_sleigh_language_file`].
    struct MockSleighLanguageFile {
        sla: ResourceFile,
        sla_spec: ResourceFile,
    }

    impl SleighLanguageFile for MockSleighLanguageFile {
        fn sla_file(&self) -> &ResourceFile {
            &self.sla
        }

        fn sla_spec_file(&self) -> &ResourceFile {
            &self.sla_spec
        }

        fn can_lock(&self) -> bool {
            false
        }

        fn lock_file(&self) -> Option<&std::path::Path> {
            None
        }

        fn sla_version(&self) -> i32 {
            -1
        }

        fn compile_sla_file(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::app::plugin::processors::sleigh::sleigh_exception::SleighException>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn with_lock(
            &self,
            _timeout: std::time::Duration,
            _monitor: &dyn crate::util::task::TaskMonitor,
            _r: &mut dyn FnMut() -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
        ) -> Result<(), super::super::sleigh_language_file::WithLockError> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockSleighLanguageDescription {
        language_id: LanguageID,
        truncated: std::collections::HashMap<String, i32>,
        defs_file: Option<ResourceFile>,
        spec_file: Option<ResourceFile>,
        manual_index_file: Option<ResourceFile>,
        language_file: Option<Box<dyn SleighLanguageFile>>,
    }

    impl LanguageDescription for MockSleighLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }

        fn get_endian(&self) -> Endian {
            Endian::Little
        }

        fn get_instruction_endian(&self) -> Endian {
            Endian::Little
        }

        fn get_size(&self) -> i32 {
            32
        }

        fn get_variant(&self) -> String {
            "default".to_string()
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_description(&self) -> String {
            "Mock Sleigh x86 32-bit little endian".to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            if compiler_spec_id == &CompilerSpecID::new(Some("default")) {
                Ok(Box::new(MockCompilerSpecDescription))
            } else {
                Err(CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ))
            }
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    impl SleighLanguageDescription for MockSleighLanguageDescription {
        fn get_truncated_space_names(&self) -> HashSet<String> {
            self.truncated.keys().cloned().collect()
        }

        fn get_truncated_space_size(&self, space_name: &str) -> Option<i32> {
            self.truncated.get(space_name).copied()
        }

        fn get_defs_file(&self) -> Option<&ResourceFile> {
            self.defs_file.as_ref()
        }

        fn set_defs_file(&mut self, defs_file: Option<ResourceFile>) {
            self.defs_file = defs_file;
        }

        fn get_spec_file(&self) -> Option<&ResourceFile> {
            self.spec_file.as_ref()
        }

        fn set_spec_file(&mut self, spec_file: Option<ResourceFile>) {
            self.spec_file = spec_file;
        }

        fn get_manual_index_file(&self) -> Option<&ResourceFile> {
            self.manual_index_file.as_ref()
        }

        fn set_manual_index_file(&mut self, manual_index_file: Option<ResourceFile>) {
            self.manual_index_file = manual_index_file;
        }

        fn get_language_file(&self) -> Option<&dyn SleighLanguageFile> {
            self.language_file.as_deref()
        }

        fn set_language_file(&mut self, language_file: Option<Box<dyn SleighLanguageFile>>) {
            self.language_file = language_file;
        }
    }

    fn mock(sla_path: &str) -> MockSleighLanguageDescription {
        let mut truncated = std::collections::HashMap::new();
        truncated.insert("ram".to_string(), 4);
        MockSleighLanguageDescription {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
            truncated,
            defs_file: None,
            spec_file: None,
            manual_index_file: None,
            language_file: Some(Box::new(MockSleighLanguageFile {
                sla: ResourceFile::new(std::path::PathBuf::from(sla_path)),
                sla_spec: ResourceFile::new(std::path::PathBuf::from("x86.slaspec")),
            })),
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let description: Box<dyn SleighLanguageDescription> = Box::new(mock("x86.sla"));

        assert_eq!(description.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(
            description.get_truncated_space_names(),
            HashSet::from(["ram".to_string()])
        );
        assert_eq!(description.get_truncated_space_size("ram"), Some(4));
        assert_eq!(description.get_truncated_space_size("no such space"), None);
    }

    #[test]
    fn defs_spec_and_manual_index_files_round_trip_through_setters() {
        let mut description = mock("x86.sla");
        assert!(description.get_defs_file().is_none());

        description.set_defs_file(Some(ResourceFile::new(std::path::PathBuf::from("x86.defs"))));
        description.set_spec_file(Some(ResourceFile::new(std::path::PathBuf::from("x86.pspec"))));
        description.set_manual_index_file(Some(ResourceFile::new(std::path::PathBuf::from(
            "x86_manual.idx",
        ))));

        assert_eq!(description.get_defs_file().unwrap().name(), "x86.defs");
        assert_eq!(description.get_spec_file().unwrap().name(), "x86.pspec");
        assert_eq!(
            description.get_manual_index_file().unwrap().name(),
            "x86_manual.idx"
        );
    }

    #[test]
    fn is_same_sleigh_language_file_true_for_matching_sla_path() {
        let a = mock("shared/x86.sla");
        let b = mock("shared/x86.sla");
        assert!(a.is_same_sleigh_language_file(&b));
    }

    #[test]
    fn is_same_sleigh_language_file_false_for_different_sla_path() {
        let a = mock("x86.sla");
        let b = mock("arm.sla");
        assert!(!a.is_same_sleigh_language_file(&b));
    }

    #[test]
    fn is_same_sleigh_language_file_false_when_language_file_missing() {
        let mut a = mock("x86.sla");
        a.set_language_file(None);
        let b = mock("x86.sla");
        assert!(!a.is_same_sleigh_language_file(&b));
    }
}
