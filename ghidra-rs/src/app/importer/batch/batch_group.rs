//! Port of `ghidra.plugins.importer.batch.BatchGroup`.

use std::fmt;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::opinion::load_spec::LoadSpec;
use crate::app::util::opinion::loader::Loader;
use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::batch_group_load_spec::BatchGroupLoadSpec;
use super::batch_segregating_criteria::BatchSegregatingCriteria;
use super::user_added_source_info::UserAddedSourceInfoId;

/// One file in a [`BatchGroup`]: where it is, how it can be loaded and which user-added source it
/// was found under.
///
/// Port of `ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig`. Java stores the loader of
/// the first load spec separately; here [`get_loader`](Self::get_loader) reads it from that spec,
/// since the loader is owned by the spec. The user-added source is referenced by ID into the list
/// owned by the batch import session (see [`UserAddedSourceInfoId`]).
pub struct BatchLoadConfig {
    load_specs: Vec<LoadSpec>,
    fsrl: Fsrl,
    uasi: UserAddedSourceInfoId,
    preferred_file_name: Option<String>,
}

impl BatchLoadConfig {
    /// # Panics
    /// Panics if `load_specs` is empty (Java throws `NoSuchElementException`).
    fn new(
        provider: &dyn ByteProvider,
        load_specs: Vec<LoadSpec>,
        fsrl: Fsrl,
        uasi: UserAddedSourceInfoId,
    ) -> Self {
        let preferred_file_name = load_specs
            .first()
            .expect("BatchLoadConfig requires at least one load spec")
            .get_loader()
            .get_preferred_file_name(provider);
        Self { load_specs, fsrl, uasi, preferred_file_name }
    }

    /// All the ways this file can be loaded.
    pub fn get_load_specs(&self) -> &[LoadSpec] {
        &self.load_specs
    }

    /// The file's FSRL.
    pub fn get_fsrl(&self) -> &Fsrl {
        &self.fsrl
    }

    /// The load spec matching `batch_group_load_spec`, if this file has one.
    pub fn get_load_spec(&self, batch_group_load_spec: &BatchGroupLoadSpec) -> Option<&LoadSpec> {
        self.load_specs.iter().find(|s| batch_group_load_spec.matches(s))
    }

    /// The user-added source this file was found under.
    pub fn get_uasi(&self) -> UserAddedSourceInfoId {
        self.uasi
    }

    /// The loader (that of the first load spec).
    pub fn get_loader(&self) -> &dyn Loader {
        self.load_specs[0].get_loader()
    }

    /// The loader's preferred file name for this file.
    pub fn get_preferred_file_name(&self) -> Option<&str> {
        self.preferred_file_name.as_deref()
    }
}

/// A group of files that share the same [`BatchSegregatingCriteria`] and will all be imported
/// with the same selected [`BatchGroupLoadSpec`].
///
/// Port of `ghidra.plugins.importer.batch.BatchGroup`.
pub struct BatchGroup {
    criteria: BatchSegregatingCriteria,
    batch_load_configs: Vec<BatchLoadConfig>,
    /// The load spec every file in the group will be imported with; initially the criteria's
    /// first preferred spec.
    pub selected_batch_group_load_spec: Option<BatchGroupLoadSpec>,
    /// Whether this group takes part in the import; initially whether a spec was selected.
    pub enabled: bool,
}

impl BatchGroup {
    /// Creates an empty group for `criteria`.
    pub fn new(criteria: BatchSegregatingCriteria) -> Self {
        let selected = criteria.get_first_preferred_load_spec().cloned();
        Self {
            enabled: selected.is_some(),
            selected_batch_group_load_spec: selected,
            criteria,
            batch_load_configs: Vec::new(),
        }
    }

    /// Adds a file to the group.
    ///
    /// # Panics
    /// Panics if `load_specs` is empty.
    pub fn add(
        &mut self,
        provider: &dyn ByteProvider,
        load_specs: Vec<LoadSpec>,
        fsrl: Fsrl,
        uasi: UserAddedSourceInfoId,
    ) {
        self.batch_load_configs.push(BatchLoadConfig::new(provider, load_specs, fsrl, uasi));
    }

    /// The criteria shared by every file in the group.
    pub fn get_criteria(&self) -> &BatchSegregatingCriteria {
        &self.criteria
    }

    /// Number of files in the group.
    pub fn size(&self) -> usize {
        self.batch_load_configs.len()
    }

    /// Whether the group has no files.
    pub fn is_empty(&self) -> bool {
        self.batch_load_configs.is_empty()
    }

    /// The files in the group.
    pub fn get_batch_load_config(&self) -> &[BatchLoadConfig] {
        &self.batch_load_configs
    }

    /// Removes every file that is `fsrl` itself or lives inside it.
    pub fn remove_descendants_of(&mut self, fsrl: &Fsrl) {
        self.batch_load_configs
            .retain(|c| !(c.fsrl.is_equivalent(fsrl) || c.fsrl.is_descendant_of(fsrl)));
    }
}

impl fmt::Display for BatchGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} ->", self.criteria)?;
        for c in &self.batch_load_configs {
            writeln!(f, "    {}", c.preferred_file_name.as_deref().unwrap_or("null"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::importer::batch::test_support::{provider, spec, NamedLoader};

    fn elf_specs() -> Vec<LoadSpec> {
        vec![
            spec("ELF", Some(("x86:LE:64:default", "gcc")), true),
            spec("ELF", Some(("x86:LE:64:default", "clang")), false),
        ]
    }

    fn group() -> BatchGroup {
        let specs = elf_specs();
        BatchGroup::new(BatchSegregatingCriteria::new(&NamedLoader("ELF"), &specs, &provider("file:///a.so")))
    }

    fn add(g: &mut BatchGroup, fsrl: &str, uasi: usize) {
        g.add(&provider(fsrl), elf_specs(), Fsrl::from_string(fsrl).unwrap(), UserAddedSourceInfoId(uasi));
    }

    #[test]
    fn new_selects_first_preferred_and_enables() {
        let g = group();
        assert_eq!(g.selected_batch_group_load_spec.as_ref().unwrap().to_string(), "x86:LE:64:default:gcc*");
        assert!(g.enabled);
        assert!(g.is_empty());
        assert_eq!(g.size(), 0);
    }

    #[test]
    fn new_without_preferred_is_disabled() {
        let specs = vec![spec("Raw", None, false)];
        let g = BatchGroup::new(BatchSegregatingCriteria::new(&NamedLoader("Raw"), &specs, &provider("file:///x")));
        assert!(g.selected_batch_group_load_spec.is_none());
        assert!(!g.enabled);
    }

    #[test]
    fn add_records_config() {
        let mut g = group();
        add(&mut g, "file:///dir/libc.so", 2);
        assert_eq!(g.size(), 1);
        let c = &g.get_batch_load_config()[0];
        assert_eq!(c.get_preferred_file_name(), Some("libc.so"));
        assert_eq!(c.get_loader().get_name(), "ELF");
        assert_eq!(c.get_uasi(), UserAddedSourceInfoId(2));
        assert_eq!(c.get_fsrl().to_string(), "file:///dir/libc.so");
        let sel = g.selected_batch_group_load_spec.clone().unwrap();
        assert_eq!(c.get_load_spec(&sel).unwrap().get_language_compiler_spec().unwrap().to_string(), "x86:LE:64:default:gcc");
        let other = BatchGroupLoadSpec::new(&spec("X", Some(("ARM:LE:32:v8", "default")), true));
        assert!(c.get_load_spec(&other).is_none());
    }

    #[test]
    fn remove_descendants_of_drops_self_and_children() {
        let mut g = group();
        add(&mut g, "file:///dir/a.zip|zip:///x.so", 0);
        add(&mut g, "file:///dir/a.zip|zip:///sub/y.so", 0);
        add(&mut g, "file:///dir/a.zip", 0);
        add(&mut g, "file:///dir/b.so", 1);
        g.remove_descendants_of(&Fsrl::from_string("file:///dir/a.zip").unwrap());
        let left: Vec<String> = g.get_batch_load_config().iter().map(|c| c.get_fsrl().to_string()).collect();
        assert_eq!(left, vec!["file:///dir/b.so"]);
    }

    #[test]
    fn display_lists_files() {
        let mut g = group();
        add(&mut g, "file:///dir/a.so", 0);
        add(&mut g, "file:///dir/b.so", 0);
        assert_eq!(
            g.to_string(),
            "[ext: so, loader: ELF, load specs: [x86:LE:64:default:clang, x86:LE:64:default:gcc*]] ->\n    a.so\n    b.so\n"
        );
    }
}
