//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageDescription`.
//!
//! In Java this is a concrete class extending `BasicLanguageDescription`; here it composes a
//! [`BasicLanguageDescription`] (which carries the [`LanguageDescription`] data and answers the
//! trait's methods) and adds the Sleigh-specific members: the `.ldefs`/`.pspec`/manual-index
//! files, the [`SleighLanguageFile`] (`.sla`/`.slaspec`) association, and address-space
//! truncation info. Descriptions are built from `.ldefs` files by
//! [`SleighLanguageProvider`](super::sleigh_language_provider::SleighLanguageProvider).
//!
//! Java's `getTruncatedSpaceSize(String)` throws an unchecked `NoSuchElementException` only when
//! the truncation map itself is absent (a missing key instead NPEs on auto-unboxing, since the
//! Java return type is primitive `int`); both cases collapse naturally to `None` here.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::basic_language_description::{BasicLanguageDescription, ExternalNames};
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::processor::Processor;

use super::sleigh_language_file::SleighLanguageFile;

/// Sleigh-specific language description: a [`BasicLanguageDescription`] plus the `.defs`/`.pspec`
/// specification files, the associated [`SleighLanguageFile`] (`.sla`/`.slaspec`), and address
/// space truncation info. See the module docs.
pub struct SleighLanguageDescription {
    /// Composed in place of Java's `extends BasicLanguageDescription`.
    base: BasicLanguageDescription,
    /// `defsFile`: the `.ldefs` file this description was read from.
    defs_file: Option<ResourceFile>,
    /// `specFile`: the `.pspec` processor specification.
    spec_file: Option<ResourceFile>,
    /// `manualIndexFile`.
    manual_index_file: Option<ResourceFile>,
    /// `languageFile`: the `.sla`/`.slaspec` pair.
    language_file: Option<Box<dyn SleighLanguageFile>>,
    /// `truncatedSpaceMap`, which Java allows to be `null`.
    truncated_space_map: Option<HashMap<String, i32>>,
}

impl SleighLanguageDescription {
    /// Port of the `SleighLanguageDescription(LanguageID, String, Processor, Endian, Endian, int,
    /// String, int, int, boolean, Map<String,Integer>, List<CompilerSpecDescription>,
    /// Map<String,List<String>>)` constructor (same argument order).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: LanguageID,
        description: impl Into<String>,
        processor: Processor,
        endian: Endian,
        instruction_endian: Endian,
        size: i32,
        variant: impl Into<String>,
        version: i32,
        minor_version: i32,
        deprecated: bool,
        space_truncations: Option<HashMap<String, i32>>,
        compiler_spec_descriptions: Vec<Arc<dyn CompilerSpecDescription>>,
        external_names: Option<ExternalNames>,
    ) -> Self {
        Self {
            base: BasicLanguageDescription::new(
                id,
                processor,
                endian,
                instruction_endian,
                size,
                variant,
                description,
                version,
                minor_version,
                deprecated,
                compiler_spec_descriptions,
                external_names,
            ),
            defs_file: None,
            spec_file: None,
            manual_index_file: None,
            language_file: None,
            truncated_space_map: space_truncations,
        }
    }

    /// The composed [`BasicLanguageDescription`] (Java's superclass part).
    pub fn base(&self) -> &BasicLanguageDescription {
        &self.base
    }

    /// Set of address space names which have been identified for truncation. Port of
    /// `getTruncatedSpaceNames()`.
    pub fn get_truncated_space_names(&self) -> HashSet<String> {
        self.truncated_space_map
            .as_ref()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The truncated space size, in bytes, for `space_name`, or `None` (see the module docs).
    /// Port of `getTruncatedSpaceSize(String)`.
    pub fn get_truncated_space_size(&self, space_name: &str) -> Option<i32> {
        self.truncated_space_map.as_ref()?.get(space_name).copied()
    }

    /// Port of `getDefsFile()`.
    pub fn get_defs_file(&self) -> Option<&ResourceFile> {
        self.defs_file.as_ref()
    }

    /// Port of `setDefsFile(ResourceFile)`.
    pub fn set_defs_file(&mut self, defs_file: Option<ResourceFile>) {
        self.defs_file = defs_file;
    }

    /// The `.pspec` file. Port of `getSpecFile()`.
    pub fn get_spec_file(&self) -> Option<&ResourceFile> {
        self.spec_file.as_ref()
    }

    /// Port of `setSpecFile(ResourceFile)`.
    pub fn set_spec_file(&mut self, spec_file: Option<ResourceFile>) {
        self.spec_file = spec_file;
    }

    /// Port of `getManualIndexFile()`.
    pub fn get_manual_index_file(&self) -> Option<&ResourceFile> {
        self.manual_index_file.as_ref()
    }

    /// Port of `setManualIndexFile(ResourceFile)`.
    pub fn set_manual_index_file(&mut self, manual_index_file: Option<ResourceFile>) {
        self.manual_index_file = manual_index_file;
    }

    /// The `.sla`/`.slaspec` pair. Port of `getLanguageFile()`.
    pub fn get_language_file(&self) -> Option<&dyn SleighLanguageFile> {
        self.language_file.as_deref()
    }

    /// Port of the package-private `setLanguageFile(SleighLanguageFile)`.
    pub fn set_language_file(&mut self, language_file: Option<Box<dyn SleighLanguageFile>>) {
        self.language_file = language_file;
    }

    /// Tests if two Sleigh languages are based on the same `.sla` file. Port of
    /// `isSameSleighLanguageFile(SleighLanguageDescription)`.
    ///
    /// Compares [`ResourceFile::absolute_path`] of each side's `.sla` file, mirroring Java's
    /// `ResourceFile.equals`. Returns `false` if either side has no associated language file
    /// (Java instead throws a `NullPointerException` in that case).
    pub fn is_same_sleigh_language_file(&self, other: &SleighLanguageDescription) -> bool {
        let (Some(this_file), Some(other_file)) = (self.get_language_file(), other.get_language_file())
        else {
            return false;
        };
        this_file.sla_file().absolute_path() == other_file.sla_file().absolute_path()
    }
}

impl LanguageDescription for SleighLanguageDescription {
    fn get_language_id(&self) -> LanguageID {
        self.base.get_language_id()
    }
    fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
        self.base.get_processor()
    }
    fn get_endian(&self) -> Endian {
        self.base.get_endian()
    }
    fn get_instruction_endian(&self) -> Endian {
        self.base.get_instruction_endian()
    }
    fn get_size(&self) -> i32 {
        self.base.get_size()
    }
    fn get_variant(&self) -> String {
        self.base.get_variant()
    }
    fn get_version(&self) -> i32 {
        self.base.get_version()
    }
    fn get_minor_version(&self) -> i32 {
        self.base.get_minor_version()
    }
    fn get_description(&self) -> String {
        self.base.get_description()
    }
    fn is_deprecated(&self) -> bool {
        self.base.is_deprecated()
    }
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        self.base.get_compatible_compiler_spec_descriptions()
    }
    fn get_compiler_spec_description_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
        self.base.get_compiler_spec_description_by_id(compiler_spec_id)
    }
    fn get_external_names(&self, external_tool: &str) -> Option<Vec<String>> {
        self.base.get_external_names(external_tool)
    }
    fn as_sleigh(&self) -> Option<&SleighLanguageDescription> {
        Some(self)
    }
}

/// Java's inherited `BasicLanguageDescription.equals`: by language id.
impl PartialEq for SleighLanguageDescription {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base
    }
}

/// Java's inherited `BasicLanguageDescription.toString()`.
impl fmt::Display for SleighLanguageDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.base, f)
    }
}

impl fmt::Debug for SleighLanguageDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SleighLanguageDescription")
            .field("base", &self.base)
            .field("spec_file", &self.spec_file.as_ref().map(ResourceFile::absolute_path))
            .field("sla_file", &self.language_file.as_ref().map(|f| f.sla_file().absolute_path()))
            .finish_non_exhaustive()
    }
}

/// A minimal description for tests that build languages from generated `.sla` streams: language
/// `id`, processor named after the id's first field, `endian` for data and instructions, 32-bit,
/// no compiler specs, no truncations.
#[cfg(test)]
pub(crate) fn test_description(id: &str, endian: Endian) -> SleighLanguageDescription {
    let language_id = LanguageID::new(id).unwrap();
    let processor = Processor::find_or_possibly_create_processor(id.split(':').next().unwrap_or(id));
    SleighLanguageDescription::new(
        language_id,
        String::new(),
        processor,
        endian,
        endian,
        32,
        "default",
        1,
        0,
        false,
        None,
        Vec::new(),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_language_file::LocatedSleighLanguageFile;
    use crate::program::model::lang::basic_compiler_spec_description::BasicCompilerSpecDescription;

    fn description(sla_path: &str) -> SleighLanguageDescription {
        let mut truncated = HashMap::new();
        truncated.insert("ram".to_string(), 4);
        let mut d = SleighLanguageDescription::new(
            LanguageID::new("x86:LE:32:default").unwrap(),
            "Intel/AMD 32-bit x86",
            Processor::find_or_possibly_create_processor("x86"),
            Endian::Little,
            Endian::Little,
            32,
            "default",
            2,
            5,
            false,
            Some(truncated),
            vec![Arc::new(BasicCompilerSpecDescription::new(CompilerSpecID::new(Some("gcc")), "gcc"))],
            None,
        );
        d.set_language_file(Some(Box::new(LocatedSleighLanguageFile::new(
            ResourceFile::new(std::path::PathBuf::from(sla_path)),
            ResourceFile::new(std::path::PathBuf::from("x86.slaspec")),
        ))));
        d
    }

    #[test]
    fn language_description_answers_come_from_the_base() {
        let d = description("x86.sla");
        assert_eq!(d.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(d.get_description(), "Intel/AMD 32-bit x86");
        assert_eq!(d.get_processor().name(), "x86");
        assert_eq!((d.get_version(), d.get_minor_version()), (2, 5));
        assert_eq!(d.get_compatible_compiler_spec_descriptions().len(), 1);
        assert_eq!(d.to_string(), "x86/little/32/default");
        let as_dyn: &dyn LanguageDescription = &d;
        assert!(std::ptr::eq(as_dyn.as_sleigh().unwrap(), &d));
    }

    #[test]
    fn truncated_spaces() {
        let d = description("x86.sla");
        assert_eq!(d.get_truncated_space_names(), HashSet::from(["ram".to_string()]));
        assert_eq!(d.get_truncated_space_size("ram"), Some(4));
        assert_eq!(d.get_truncated_space_size("no such space"), None);
        let none = test_description("toy:LE:32:default", Endian::Little);
        assert!(none.get_truncated_space_names().is_empty());
        assert_eq!(none.get_truncated_space_size("ram"), None);
    }

    #[test]
    fn defs_spec_and_manual_index_files_round_trip_through_setters() {
        let mut d = description("x86.sla");
        assert!(d.get_defs_file().is_none());
        d.set_defs_file(Some(ResourceFile::new(std::path::PathBuf::from("x86.ldefs"))));
        d.set_spec_file(Some(ResourceFile::new(std::path::PathBuf::from("x86.pspec"))));
        d.set_manual_index_file(Some(ResourceFile::new(std::path::PathBuf::from("x86_manual.idx"))));
        assert_eq!(d.get_defs_file().unwrap().name(), "x86.ldefs");
        assert_eq!(d.get_spec_file().unwrap().name(), "x86.pspec");
        assert_eq!(d.get_manual_index_file().unwrap().name(), "x86_manual.idx");
    }

    #[test]
    fn is_same_sleigh_language_file_compares_sla_paths() {
        assert!(description("shared/x86.sla").is_same_sleigh_language_file(&description("shared/x86.sla")));
        assert!(!description("x86.sla").is_same_sleigh_language_file(&description("arm.sla")));
        let mut a = description("x86.sla");
        a.set_language_file(None);
        assert!(!a.is_same_sleigh_language_file(&description("x86.sla")));
    }

    #[test]
    fn is_send_and_sync_for_sharing_with_its_language() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SleighLanguageDescription>();
    }
}
