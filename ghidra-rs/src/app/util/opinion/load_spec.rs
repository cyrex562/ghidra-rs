//! Port of `ghidra.app.util.opinion.LoadSpec`.
//!
//! Represents a possible way for a [`Loader`] to load something: which `Loader` would do the
//! load, the desired image base, and (optionally) which language/compiler spec to use.
//!
//! A lightweight placeholder trait of the same name already exists at
//! [`crate::app::seam_stubs::LoadSpecLike`], threaded opaquely through
//! [`Loader`](crate::app::util::opinion::loader::Loader)'s trait signatures and
//! [`load_spec_chooser`](crate::app::util::importer::load_spec_chooser) before this real class
//! was ported. This module ports the real Java class independently, following the same
//! "independent, full-fidelity type coexists with an existing opaque placeholder" precedent
//! [`QueryResult`](crate::app::util::opinion::query_result) and
//! [`LoadResults`](crate::app::util::opinion::load_results) already set; rewiring `Loader`'s
//! existing `LoadSpecLike` call sites to this concrete type is a separate, larger refactor and
//! out of scope here.
//!
//! Java's three overloaded constructors become three differently-named functions, since Rust has
//! no overloading:
//! - `LoadSpec(Loader, long, LanguageCompilerSpecPair, boolean)` becomes [`LoadSpec::new`].
//! - `LoadSpec(Loader, long, QueryResult)` becomes [`LoadSpec::from_query_result`], which delegates
//!   to `new` exactly as the Java constructor delegates via `this(...)`.
//! - `LoadSpec(Loader, long, boolean)` becomes [`LoadSpec::unresolved`], for `Loader`s that don't
//!   yet know (or don't need) a language/compiler; it also delegates to `new` via `this(...)`,
//!   exactly as Java does.
//!
//! `long imageBase` becomes `i64`. The public `Loader loader` field becomes a `Box<dyn Loader>`,
//! since [`Loader`](crate::app::util::opinion::loader::Loader) was itself ported as a trait (a
//! Java interface with many implementors).
//!
//! `toString()`'s `ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE)` uses
//! Java reflection plus each field's own `toString()`/identity hash code to build its output; that
//! has no faithful Rust equivalent (no reflection, no object identity hash, and `dyn Loader` has
//! no required `Display`/`Debug` bound). [`LoadSpec`]'s [`Display`](fmt::Display) impl instead
//! renders the same fields in the same order using `Loader::get_name()` in place of the loader's
//! own `toString()`, which is the closest stable, deterministic substitute.

use std::fmt;

use crate::app::util::opinion::loader::Loader;
use crate::app::util::opinion::query_result::QueryResult;
use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;

/// Represents a possible way for a [`Loader`] to load something.
///
/// Port of `ghidra.app.util.opinion.LoadSpec`. See the module docs for the relationship to the
/// pre-existing `app::seam_stubs::LoadSpecLike` placeholder.
pub struct LoadSpec {
    loader: Box<dyn Loader>,
    image_base: i64,
    lcs: Option<LanguageCompilerSpecPair>,
    is_preferred: bool,
    requires_language_compiler_spec: bool,
}

impl LoadSpec {
    /// Constructs a [`LoadSpec`] from a manually supplied [`LanguageCompilerSpecPair`].
    ///
    /// Port of `LoadSpec(Loader, long, LanguageCompilerSpecPair, boolean)`.
    ///
    /// Java internally defines a "preferred" language/compiler being null to mean the associated
    /// `Loader` doesn't use a language/compiler at all, and a "non-preferred" language/compiler
    /// being null to mean the `Loader` does use one but wasn't able to figure it out on its own;
    /// [`LoadSpec::requires_language_compiler_spec`] is derived from `language_compiler_spec` and
    /// `is_preferred` accordingly, exactly mirroring
    /// `this.requiresLanguageCompilerSpec = lcs != null || !isPreferred;`.
    pub fn new(
        loader: Box<dyn Loader>,
        image_base: i64,
        language_compiler_spec: Option<LanguageCompilerSpecPair>,
        is_preferred: bool,
    ) -> Self {
        let requires_language_compiler_spec = language_compiler_spec.is_some() || !is_preferred;
        LoadSpec {
            loader,
            image_base,
            lcs: language_compiler_spec,
            is_preferred,
            requires_language_compiler_spec,
        }
    }

    /// Constructs a [`LoadSpec`] from a [`QueryResult`].
    ///
    /// Port of `LoadSpec(Loader, long, QueryResult)`, which delegates to the four-argument
    /// constructor with `languageCompilerSpecQueryResult.pair` and
    /// `languageCompilerSpecQueryResult.preferred`.
    pub fn from_query_result(loader: Box<dyn Loader>, image_base: i64, query_result: &QueryResult) -> Self {
        Self::new(loader, image_base, Some(query_result.pair.clone()), query_result.preferred)
    }

    /// Constructs a [`LoadSpec`] with an unknown language/compiler. Some [`Loader`]s do not
    /// require a language/compiler.
    ///
    /// Port of `LoadSpec(Loader, long, boolean)`, which delegates to the four-argument
    /// constructor as `this(loader, imageBase, null, !requiresLanguageCompilerSpec)`.
    ///
    /// If a language/compiler is required, it will have to be supplied to the `Loader` by some
    /// other means, and this [`LoadSpec`] will be considered incomplete; see
    /// [`LoadSpec::is_complete`].
    pub fn unresolved(loader: Box<dyn Loader>, image_base: i64, requires_language_compiler_spec: bool) -> Self {
        Self::new(loader, image_base, None, !requires_language_compiler_spec)
    }

    /// Gets this [`LoadSpec`]'s [`Loader`].
    ///
    /// Port of `LoadSpec.getLoader()`.
    pub fn get_loader(&self) -> &dyn Loader {
        self.loader.as_ref()
    }

    /// Gets the desired image base to use during the load.
    ///
    /// Port of `LoadSpec.getDesiredImageBase()`.
    pub fn get_desired_image_base(&self) -> i64 {
        self.image_base
    }

    /// Gets this [`LoadSpec`]'s [`LanguageCompilerSpecPair`]. Could be `None` if this `LoadSpec`
    /// doesn't need or know the language/compiler.
    ///
    /// Port of `LoadSpec.getLanguageCompilerSpec()`.
    pub fn get_language_compiler_spec(&self) -> Option<&LanguageCompilerSpecPair> {
        self.lcs.as_ref()
    }

    /// Gets whether or not this [`LoadSpec`] is a preferred `LoadSpec`.
    ///
    /// Port of `LoadSpec.isPreferred()`.
    pub fn is_preferred(&self) -> bool {
        self.is_preferred
    }

    /// Gets whether or not this [`LoadSpec`] requires a language/compiler to load something.
    ///
    /// Port of `LoadSpec.requiresLanguageCompilerSpec()`.
    pub fn requires_language_compiler_spec(&self) -> bool {
        self.requires_language_compiler_spec
    }

    /// Gets whether or not this [`LoadSpec`] is complete. A `LoadSpec` is not considered complete
    /// if it requires a language/compiler to load something, but the language/compiler is
    /// currently unknown.
    ///
    /// Port of `LoadSpec.isComplete()`.
    pub fn is_complete(&self) -> bool {
        !self.requires_language_compiler_spec || self.lcs.is_some()
    }
}

impl fmt::Display for LoadSpec {
    /// Approximates `LoadSpec.toString()`. See the module docs for why this can't reproduce
    /// `ToStringBuilder.reflectionToString` exactly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ghidra.app.util.opinion.LoadSpec[")?;
        writeln!(f, "  loader={}", self.loader.get_name())?;
        writeln!(f, "  imageBase={}", self.image_base)?;
        match &self.lcs {
            Some(lcs) => writeln!(f, "  lcs={lcs}")?,
            None => writeln!(f, "  lcs=<null>")?,
        }
        writeln!(f, "  isPreferred={}", self.is_preferred)?;
        writeln!(f, "  requiresLanguageCompilerSpec={}", self.requires_language_compiler_spec)?;
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{ByteProviderLike, LoadResultsLike, LoadSpecLike, MessageLog, OptionLike};
    use crate::app::util::opinion::loader::{ImporterSettings, LoadError, LoadIntoError};
    use crate::app::util::opinion::loader_tier::LoaderTier;
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::Program;
    use crate::util::classfinder::extension_point::ExtensionPoint;
    use std::io;

    struct MockLoader {
        name: &'static str,
    }

    impl Loader for MockLoader {
        fn find_supported_load_specs(
            &self,
            _provider: &dyn ByteProviderLike,
        ) -> io::Result<Vec<Box<dyn LoadSpecLike>>> {
            Ok(vec![])
        }

        fn load(&self, _settings: ImporterSettings<'_>) -> Result<Box<dyn LoadResultsLike>, LoadError> {
            unimplemented!("not exercised by these tests")
        }

        fn load_into(
            &self,
            _program: &mut dyn Program,
            _settings: ImporterSettings<'_>,
        ) -> Result<(), LoadIntoError> {
            unimplemented!("not exercised by these tests")
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
            self.name.to_string()
        }

        fn get_tier(&self) -> LoaderTier {
            LoaderTier::GenericTargetLoader
        }

        fn get_tier_priority(&self) -> i32 {
            0
        }
    }

    impl ExtensionPoint for MockLoader {}

    fn loader() -> Box<dyn Loader> {
        Box::new(MockLoader { name: "Mock Loader" })
    }

    fn pair() -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc")
    }

    #[test]
    fn new_with_known_lcs_and_preferred_is_complete() {
        let spec = LoadSpec::new(loader(), 0x1000, Some(pair()), true);
        assert_eq!(spec.get_desired_image_base(), 0x1000);
        assert_eq!(spec.get_language_compiler_spec(), Some(&pair()));
        assert!(spec.is_preferred());
        // lcs != null, so requiresLanguageCompilerSpec is true regardless of isPreferred.
        assert!(spec.requires_language_compiler_spec());
        assert!(spec.is_complete());
    }

    #[test]
    fn new_with_null_lcs_and_preferred_means_loader_does_not_need_one() {
        // Java's documented convention: a "preferred" LoadSpec with a null lcs means the Loader
        // doesn't use a language/compiler at all, so requiresLanguageCompilerSpec is false and
        // the spec is trivially complete.
        let spec = LoadSpec::new(loader(), 0, None, true);
        assert!(spec.get_language_compiler_spec().is_none());
        assert!(!spec.requires_language_compiler_spec());
        assert!(spec.is_complete());
    }

    #[test]
    fn new_with_null_lcs_and_not_preferred_means_unknown_but_required() {
        // The other half of the documented convention: a "non-preferred" LoadSpec with a null lcs
        // means the Loader does need one but couldn't figure it out, so this LoadSpec is
        // incomplete until the caller supplies one some other way.
        let spec = LoadSpec::new(loader(), 0, None, false);
        assert!(spec.requires_language_compiler_spec());
        assert!(!spec.is_complete());
    }

    #[test]
    fn from_query_result_copies_pair_and_preferred_flag() {
        let qr = QueryResult::new(pair(), true);
        let spec = LoadSpec::from_query_result(loader(), 42, &qr);
        assert_eq!(spec.get_desired_image_base(), 42);
        assert_eq!(spec.get_language_compiler_spec(), Some(&pair()));
        assert!(spec.is_preferred());
        assert!(spec.is_complete());

        let qr_not_preferred = QueryResult::new(pair(), false);
        let spec2 = LoadSpec::from_query_result(loader(), 42, &qr_not_preferred);
        assert!(!spec2.is_preferred());
        // Still complete: the lcs is known even though it wasn't the "preferred" match.
        assert!(spec2.is_complete());
    }

    #[test]
    fn unresolved_requiring_lcs_is_incomplete() {
        let spec = LoadSpec::unresolved(loader(), 0, true);
        assert!(spec.get_language_compiler_spec().is_none());
        assert!(spec.requires_language_compiler_spec());
        assert!(!spec.is_complete());
        assert!(!spec.is_preferred());
    }

    #[test]
    fn unresolved_not_requiring_lcs_is_complete() {
        let spec = LoadSpec::unresolved(loader(), 0, false);
        assert!(spec.get_language_compiler_spec().is_none());
        assert!(!spec.requires_language_compiler_spec());
        assert!(spec.is_complete());
        assert!(spec.is_preferred());
    }

    #[test]
    fn get_loader_exposes_the_stored_loader() {
        let spec = LoadSpec::new(loader(), 0, None, true);
        assert_eq!(spec.get_loader().get_name(), "Mock Loader");
    }

    #[test]
    fn display_renders_all_fields() {
        let spec = LoadSpec::new(loader(), 0x2000, Some(pair()), true);
        let s = spec.to_string();
        assert!(s.contains("loader=Mock Loader"));
        assert!(s.contains("imageBase=8192"));
        assert!(s.contains("isPreferred=true"));
        assert!(s.contains("requiresLanguageCompilerSpec=true"));

        let spec2 = LoadSpec::unresolved(loader(), 0, true);
        assert!(spec2.to_string().contains("lcs=<null>"));
    }
}
