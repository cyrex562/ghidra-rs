//! A trait for source language-specific data archives.
//!
//! Port of `ghidra.app.util.sourcelanguage.SourceLanguageDataArchive`. This is an extension point
//! for dynamically supporting source language-specific data archives. Each implementer provides
//! rules for when a given data archive applies to a program, based on processor, endianness, size,
//! variant, and binary format.

use std::sync::Arc;

use crate::app::seam_stubs::MessageLog;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::listing::program::Program;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::task::TaskMonitor;

use super::source_language_id::SourceLanguageId;

/// A rule that determines whether a data archive applies to a program.
///
/// Port of the nested `ghidra.app.util.sourcelanguage.SourceLanguageDataArchive.DataArchiveRule`.
#[derive(Clone)]
pub struct DataArchiveRule {
    /// The name of the processor (required).
    pub processor: String,

    /// The processor endianness ("little" or "big"); empty/None for wildcard.
    pub endian: Option<String>,

    /// The processor size (e.g., "32", "64"); empty/None for wildcard.
    pub size: Option<String>,

    /// The processor variant; empty/None for wildcard.
    pub variant: Option<String>,

    /// The names of the supported binary file formats; empty/None for wildcard.
    pub formats: Option<Vec<String>>,

    /// The data archive file.
    pub data_archive_file: ResourceFile,
}

impl DataArchiveRule {
    /// Creates a new data archive rule with the given parameters.
    pub fn new(
        processor: impl Into<String>,
        endian: Option<impl Into<String>>,
        size: Option<impl Into<String>>,
        variant: Option<impl Into<String>>,
        formats: Option<Vec<String>>,
        data_archive_file: ResourceFile,
    ) -> Self {
        Self {
            processor: processor.into(),
            endian: endian.map(|e| e.into()),
            size: size.map(|s| s.into()),
            variant: variant.map(|v| v.into()),
            formats,
            data_archive_file,
        }
    }
}

/// An extension point for dynamically supporting source language-specific data archives.
///
/// Port of `ghidra.app.util.sourcelanguage.SourceLanguageDataArchive`.
pub trait SourceLanguageDataArchive: ExtensionPoint + Send + Sync {
    /// Returns the [`SourceLanguageId`] of the source language this archive is compatible with.
    fn get_compatible_source_language(&self) -> Arc<dyn SourceLanguageId>;

    /// Returns the data archive rules that apply to this source language.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to check.
    /// * `log` - The message log for recording errors/warnings.
    /// * `monitor` - The task monitor for cancellation and progress.
    ///
    /// # Returns
    ///
    /// A list of rules that apply to the given program.
    fn get_data_archive_rules(
        &self,
        program: &dyn Program,
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Vec<DataArchiveRule>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_archive_rule_new() {
        let file = ResourceFile::new("/path/to/archive".into());
        let rule = DataArchiveRule::new(
            "x86",
            Some("little"),
            Some("32"),
            Some("default"),
            Some(vec!["ELF".to_string()]),
            file,
        );

        assert_eq!(rule.processor, "x86");
        assert_eq!(rule.endian, Some("little".to_string()));
        assert_eq!(rule.size, Some("32".to_string()));
        assert_eq!(rule.variant, Some("default".to_string()));
        assert_eq!(rule.formats, Some(vec!["ELF".to_string()]));
    }

    #[test]
    fn data_archive_rule_wildcards() {
        let file = ResourceFile::new("/path/to/archive".into());
        let rule = DataArchiveRule::new("x86", None::<String>, None::<String>, None::<String>, None, file);

        assert_eq!(rule.processor, "x86");
        assert_eq!(rule.endian, None);
        assert_eq!(rule.size, None);
        assert_eq!(rule.variant, None);
        assert_eq!(rule.formats, None);
    }
}
