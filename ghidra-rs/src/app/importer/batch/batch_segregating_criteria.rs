//! Port of `ghidra.plugins.importer.batch.BatchSegregatingCriteria`.

use std::collections::BTreeSet;
use std::fmt;

use crate::app::seam_stubs::ByteProviderLike;
use crate::app::util::opinion::load_spec::LoadSpec;
use crate::app::util::opinion::loader::Loader;

use super::batch_group_load_spec::BatchGroupLoadSpec;

/// The key that segregates files in a batch import into groups: the file extension, the loader
/// name and the set of (loader-independent) load specs. Files with equal criteria are imported
/// the same way.
///
/// Port of `ghidra.plugins.importer.batch.BatchSegregatingCriteria`. Java keeps the load specs in
/// a `HashSet`; this keeps them in a [`BTreeSet`], which has the same set equality but a defined
/// iteration order, so [`get_first_preferred_load_spec`](Self::get_first_preferred_load_spec) is
/// deterministic (the first preferred spec in sorted order) where Java's pick depended on hash
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatchSegregatingCriteria {
    group_load_specs: BTreeSet<BatchGroupLoadSpec>,
    file_ext: Option<String>,
    loader: String,
}

impl BatchSegregatingCriteria {
    /// Builds the criteria for a file that `loader` can load in the ways given by `load_specs`.
    ///
    /// The file extension is taken from the loader's preferred file name for `provider`.
    pub fn new<'a>(
        loader: &dyn Loader,
        load_specs: impl IntoIterator<Item = &'a LoadSpec>,
        provider: &dyn ByteProviderLike,
    ) -> Self {
        Self {
            group_load_specs: load_specs.into_iter().map(BatchGroupLoadSpec::new).collect(),
            loader: loader.get_name(),
            file_ext: loader.get_preferred_file_name(provider).as_deref().map(get_extension),
        }
    }

    /// The file extension (empty if the name has none), or `None` if the loader had no preferred
    /// file name.
    pub fn get_file_ext(&self) -> Option<&str> {
        self.file_ext.as_deref()
    }

    /// The loader's name.
    pub fn get_loader(&self) -> &str {
        &self.loader
    }

    /// The group load specs, sorted.
    pub fn get_batch_group_load_specs(&self) -> Vec<BatchGroupLoadSpec> {
        self.group_load_specs.iter().cloned().collect()
    }

    /// The first preferred group load spec, if any.
    pub fn get_first_preferred_load_spec(&self) -> Option<&BatchGroupLoadSpec> {
        self.group_load_specs.iter().find(|s| s.preferred)
    }
}

impl fmt::Display for BatchSegregatingCriteria {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let specs: Vec<String> = self.group_load_specs.iter().map(ToString::to_string).collect();
        write!(
            f,
            "[ext: {}, loader: {}, load specs: [{}]]",
            self.file_ext.as_deref().unwrap_or(""),
            self.loader,
            specs.join(", ")
        )
    }
}

/// Apache commons-io `FilenameUtils.getExtension`: the text after the last `.`, or `""` when there
/// is no `.` in the final path component.
fn get_extension(filename: &str) -> String {
    let ext_pos = filename.rfind('.');
    let last_sep = filename.rfind(['/', '\\']);
    match (ext_pos, last_sep) {
        (Some(e), Some(s)) if s > e => String::new(),
        (Some(e), _) => filename[e + 1..].to_string(),
        (None, _) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::importer::batch::test_support::{provider, spec, NamedLoader, Provider};

    #[test]
    fn extension_matches_commons_io() {
        assert_eq!(get_extension("foo.txt"), "txt");
        assert_eq!(get_extension("a/b/c.jpg"), "jpg");
        assert_eq!(get_extension("a/b.txt/c"), "");
        assert_eq!(get_extension("a\\b.d\\c"), "");
        assert_eq!(get_extension("a/b/c"), "");
        assert_eq!(get_extension("archive.tar.gz"), "gz");
        assert_eq!(get_extension("trailing."), "");
    }

    #[test]
    fn built_from_loader_specs_and_provider() {
        let specs = vec![
            spec("ELF", Some(("x86:LE:64:default", "gcc")), true),
            spec("ELF", Some(("x86:LE:64:default", "clang")), false),
        ];
        let c = BatchSegregatingCriteria::new(
            &NamedLoader("Executable and Linking Format (ELF)"),
            &specs,
            &provider("file:///bin/ls.elf"),
        );
        assert_eq!(c.get_loader(), "Executable and Linking Format (ELF)");
        assert_eq!(c.get_file_ext(), Some("elf"));
        let names: Vec<String> = c.get_batch_group_load_specs().iter().map(ToString::to_string).collect();
        assert_eq!(names, vec!["x86:LE:64:default:clang", "x86:LE:64:default:gcc*"]);
        assert_eq!(c.get_first_preferred_load_spec().unwrap().to_string(), "x86:LE:64:default:gcc*");
        assert_eq!(
            c.to_string(),
            "[ext: elf, loader: Executable and Linking Format (ELF), load specs: \
             [x86:LE:64:default:clang, x86:LE:64:default:gcc*]]"
        );
    }

    #[test]
    fn no_preferred_and_no_name() {
        let specs = vec![spec("Raw", None, false)];
        let c = BatchSegregatingCriteria::new(&NamedLoader("Raw Binary"), &specs, &Provider { fsrl: None, name: None });
        assert_eq!(c.get_file_ext(), None);
        assert!(c.get_first_preferred_load_spec().is_none());
        assert_eq!(c.to_string(), "[ext: , loader: Raw Binary, load specs: [none]]");
    }

    #[test]
    fn equal_criteria_group_together() {
        let a_specs = vec![spec("PE", Some(("x86:LE:32:default", "windows")), true)];
        let b_specs = vec![spec("PE", Some(("x86:LE:32:default", "windows")), true)];
        let a = BatchSegregatingCriteria::new(&NamedLoader("PE"), &a_specs, &provider("file:///x/a.exe"));
        let b = BatchSegregatingCriteria::new(&NamedLoader("PE"), &b_specs, &provider("file:///y/b.exe"));
        let c = BatchSegregatingCriteria::new(&NamedLoader("PE"), &b_specs, &provider("file:///y/b.dll"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        let set: std::collections::HashSet<_> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }
}
