//! Port of `ghidra.plugins.importer.batch`: the non-UI model behind batch import, which groups
//! importable files by how they would be loaded.

pub mod batch_group;
pub mod batch_group_load_spec;
pub mod batch_segregating_criteria;
pub mod user_added_source_info;

pub use batch_group::{BatchGroup, BatchLoadConfig};
pub use batch_group_load_spec::BatchGroupLoadSpec;
pub use batch_segregating_criteria::BatchSegregatingCriteria;
pub use user_added_source_info::{UserAddedSourceInfo, UserAddedSourceInfoId};

/// Shared test doubles for the batch model: a [`Loader`](crate::app::util::opinion::loader::Loader)
/// that only has a name, and a real byte provider built from an FSRL.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io;

    use crate::app::seam_stubs::{LoadResultsLike, LoadSpecLike, OptionLike};
    use crate::app::util::bin::byte_provider::ByteProvider;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::app::util::opinion::load_spec::LoadSpec;
    use crate::app::util::opinion::loader::{ImporterSettings, LoadError, LoadIntoError, Loader};
    use crate::app::util::opinion::loader_tier::LoaderTier;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::framework::model::DomainObject;
    use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;
    use crate::program::model::listing::Program;
    use crate::util::classfinder::extension_point::ExtensionPoint;

    pub struct NamedLoader(pub &'static str);

    impl Loader for NamedLoader {
        fn find_supported_load_specs(
            &self,
            _provider: &dyn ByteProvider,
        ) -> io::Result<Vec<Box<dyn LoadSpecLike>>> {
            Ok(vec![])
        }

        fn load(&self, _settings: ImporterSettings<'_>) -> Result<Box<dyn LoadResultsLike>, LoadError> {
            unimplemented!("not exercised by the batch model tests")
        }

        fn load_into(
            &self,
            _program: &mut dyn Program,
            _settings: ImporterSettings<'_>,
        ) -> Result<(), LoadIntoError> {
            unimplemented!("not exercised by the batch model tests")
        }

        fn get_default_options(
            &self,
            _provider: &dyn ByteProvider,
            _load_spec: &dyn LoadSpecLike,
            _domain_object: &dyn DomainObject,
            _load_into_program: bool,
            _mirror_fs_layout: bool,
        ) -> Vec<Box<dyn OptionLike>> {
            vec![]
        }

        fn validate_options(
            &self,
            _provider: &dyn ByteProvider,
            _load_spec: &dyn LoadSpecLike,
            _options: &[Box<dyn OptionLike>],
            _program: Option<&dyn Program>,
        ) -> Option<String> {
            None
        }

        fn get_name(&self) -> String {
            self.0.to_string()
        }

        fn get_tier(&self) -> LoaderTier {
            LoaderTier::GenericTargetLoader
        }

        fn get_tier_priority(&self) -> i32 {
            0
        }
    }

    impl ExtensionPoint for NamedLoader {}

    /// An empty [`ByteArrayProvider`] whose identity is the given FSRL.
    pub fn provider(fsrl: &str) -> ByteArrayProvider {
        ByteArrayProvider::with_fsrl(Vec::new(), Some(Fsrl::from_string(fsrl).unwrap()))
    }

    pub fn spec(loader: &'static str, lcs: Option<(&str, &str)>, preferred: bool) -> LoadSpec {
        LoadSpec::new(
            Box::new(NamedLoader(loader)),
            0,
            lcs.map(|(l, c)| LanguageCompilerSpecPair::new(l, c)),
            preferred,
        )
    }
}
