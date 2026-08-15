//! Chooses a `LoadSpec` for a `Loader` to use based on some criteria.
//!
//! Port of `ghidra.app.util.importer.LoadSpecChooser`.

use crate::app::seam_stubs::{LoaderMap, LoadSpec};
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;

/// Chooses a [`LoadSpec`] for a [`Loader`](crate::app::util::opinion::loader::Loader) to use
/// based on some criteria.
///
/// Port of the Java `@FunctionalInterface`. `choose` borrows its result from `loader_map` rather
/// than returning an owned `LoadSpec`, since Java always returns a reference to a `LoadSpec`
/// already held by the map (or `null`); [`get_language_id`](Self::get_language_id) and
/// [`get_compiler_spec_id`](Self::get_compiler_spec_id) return owned `LanguageID`/`CompilerSpecID`
/// values since both types are cheap to clone and have no map to borrow from.
pub trait LoadSpecChooser {
    /// Chooses a [`LoadSpec`] for a [`Loader`](crate::app::util::opinion::loader::Loader) to use
    /// based on some criteria.
    ///
    /// Returns `None` if one could not be found.
    fn choose<'a>(&self, loader_map: &'a LoaderMap) -> Option<&'a LoadSpec>;

    /// The desired [`LanguageID`] associated with this chooser, or `None` to mean "any".
    fn get_language_id(&self) -> Option<LanguageID> {
        None
    }

    /// The desired [`CompilerSpecID`] associated with this chooser, or `None` to mean "any".
    fn get_compiler_spec_id(&self) -> Option<CompilerSpecID> {
        None
    }
}

/// Chooses the first "preferred" [`LoadSpec`].
///
/// Port of `LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED`.
pub struct ChooseTheFirstPreferred;

impl LoadSpecChooser for ChooseTheFirstPreferred {
    fn choose<'a>(&self, loader_map: &'a LoaderMap) -> Option<&'a LoadSpec> {
        loader_map
            .values()
            .flat_map(|load_specs| load_specs.iter())
            .find(|load_spec| load_spec.preferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::opinion::loader::Loader;
    use crate::app::util::opinion::loader::{ImporterSettings, LoadError, LoadIntoError};
    use crate::app::util::opinion::loader_tier::LoaderTier;
    use crate::app::seam_stubs::{ByteProviderLike, LoadResultsLike, LoadSpecLike, OptionLike};
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::Program;
    use std::io;

    struct StubLoader;

    impl crate::util::classfinder::extension_point::ExtensionPoint for StubLoader {}

    impl Loader for StubLoader {
        fn find_supported_load_specs(
            &self,
            _provider: &dyn ByteProviderLike,
        ) -> io::Result<Vec<Box<dyn LoadSpecLike>>> {
            Ok(vec![])
        }

        fn load(
            &self,
            _settings: ImporterSettings<'_>,
        ) -> Result<Box<dyn LoadResultsLike>, LoadError> {
            unimplemented!()
        }

        fn load_into(
            &self,
            _program: &mut dyn Program,
            _settings: ImporterSettings<'_>,
        ) -> Result<(), LoadIntoError> {
            unimplemented!()
        }

        fn get_default_options(
            &self,
            _provider: &dyn ByteProviderLike,
            _load_spec: &dyn LoadSpecLike,
            _domain_object: &dyn DomainObject,
            _load_into_program: bool,
            _mirror_fs_layout: bool,
        ) -> Vec<Box<dyn OptionLike>> {
            vec![]
        }

        fn validate_options(
            &self,
            _provider: &dyn ByteProviderLike,
            _load_spec: &dyn LoadSpecLike,
            _options: &[Box<dyn OptionLike>],
            _program: Option<&dyn Program>,
        ) -> Option<String> {
            None
        }

        fn get_name(&self) -> String {
            "Stub".to_string()
        }

        fn get_tier(&self) -> LoaderTier {
            LoaderTier::GenericTargetLoader
        }

        fn get_tier_priority(&self) -> i32 {
            0
        }
    }

    #[test]
    fn choose_the_first_preferred_skips_non_preferred() {
        let mut loader_map = LoaderMap::new();
        loader_map.insert(
            Box::new(StubLoader),
            vec![
                LoadSpec::without_language_compiler_spec(0, true),
                LoadSpec::with_language_compiler_spec(
                    0x1000,
                    crate::program::seam_stubs::LanguageCompilerSpecPair::new(
                        LanguageID::new("x86:LE:32:default").unwrap(),
                        CompilerSpecID::new(Some("gcc")),
                    ),
                    true,
                ),
            ],
        );

        let chooser = ChooseTheFirstPreferred;
        let chosen = chooser.choose(&loader_map).expect("a preferred load spec");
        assert!(chosen.preferred);
        assert_eq!(chosen.desired_image_base, 0x1000);
    }

    #[test]
    fn choose_the_first_preferred_returns_none_when_no_load_specs_are_preferred() {
        let mut loader_map = LoaderMap::new();
        loader_map.insert(
            Box::new(StubLoader),
            vec![LoadSpec::without_language_compiler_spec(0, true)],
        );

        let chooser = ChooseTheFirstPreferred;
        assert!(chooser.choose(&loader_map).is_none());
    }

    #[test]
    fn default_language_and_compiler_spec_ids_are_any() {
        let chooser = ChooseTheFirstPreferred;
        assert!(chooser.get_language_id().is_none());
        assert!(chooser.get_compiler_spec_id().is_none());
    }
}
