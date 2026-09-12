//! Port of `ghidra.app.util.opinion.LoaderMap`.
//!
//! A map of [`Loader`]s to their respective [`LoadSpec`]s. The [`Loader`] keys are sorted
//! according to their [`Loader::compare_to`] natural ordering.
//!
//! Java's `LoaderMap extends TreeMap<Loader, Collection<LoadSpec>>`; per this crate's
//! composition-over-inheritance convention (never fake trait-based inheritance from a Java
//! `extends` clause), this is ported as a struct that owns a `Vec` of `(Loader, LoadSpecs)`
//! pairs kept sorted by [`Loader::compare_to`] on every insertion, rather than pretending Rust
//! has a `TreeMap` to "extend". `dyn Loader` cannot implement `Ord` itself (no blanket way to
//! compare two arbitrary trait objects while keeping `Loader` object-safe -- the same reason
//! [`Loader`] only exposes `compare_to` as a plain method instead of a `Comparable`/`Ord` impl),
//! so the sort key comparison here calls `Loader::compare_to` directly instead of relying on
//! `Vec::sort`/`BTreeMap`'s standard `Ord` machinery.
//!
//! A lightweight placeholder of the same name already exists at
//! [`crate::app::seam_stubs::LoaderMap`], used by
//! [`LoadSpecChooser`](crate::app::util::importer::load_spec_chooser::LoadSpecChooser) before
//! this real class was ported, and paired there with the placeholder
//! [`crate::app::seam_stubs::LoadSpec`] rather than the real, full-fidelity
//! [`LoadSpec`](crate::app::util::opinion::load_spec::LoadSpec). This module ports the real Java
//! class independently against the real `Loader` trait and real `LoadSpec` type, following the
//! same "independent, full-fidelity type coexists with an existing opaque placeholder" precedent
//! [`QueryResult`](crate::app::util::opinion::query_result),
//! [`LoadResults`](crate::app::util::opinion::load_results), and
//! [`LoadSpec`](crate::app::util::opinion::load_spec) already set; rewiring `LoadSpecChooser`'s
//! existing seam-stub call sites to this concrete type is a separate, larger refactor and out of
//! scope here.
//!
//! `TreeMap`'s key *comparator* equality (not `Loader.equals`) governs whether two `put` calls
//! collide into a single entry: two distinct `Loader` instances that compare equal via
//! [`Loader::compare_to`] (same tier, same tier priority, same name) are treated as the same key,
//! exactly like a real `TreeMap<Loader, ...>` would. This is standard `TreeMap` behavior (not a
//! `LoaderMap`-specific bug) and is faithfully reproduced, with a dedicated test
//! (`put_treats_loaders_as_equal_when_compare_to_is_equal`) proving it.

use std::cmp::Ordering;
use std::fmt;

use crate::app::util::opinion::load_spec::LoadSpec;
use crate::app::util::opinion::loader::Loader;

/// A map of [`Loader`]s to their respective [`LoadSpec`]s, sorted by [`Loader::compare_to`].
///
/// Port of `ghidra.app.util.opinion.LoaderMap`.
#[derive(Default)]
pub struct LoaderMap {
    /// Kept sorted by `Loader::compare_to` on every [`LoaderMap::put`], so
    /// [`LoaderMap::keys`]/[`LoaderMap::values`]/[`LoaderMap::iter`] all iterate in the same
    /// order a real `TreeMap<Loader, Collection<LoadSpec>>` would.
    entries: Vec<(Box<dyn Loader>, Vec<LoadSpec>)>,
}

impl LoaderMap {
    /// Creates a new, empty [`LoaderMap`].
    ///
    /// Port of the implicit no-argument constructor `TreeMap` provides, used by Java call sites
    /// as `new LoaderMap()`.
    pub fn new() -> Self {
        LoaderMap { entries: Vec::new() }
    }

    /// Associates the given [`Loader`] with the given [`LoadSpec`]s.
    ///
    /// Port of `TreeMap.put(Loader, Collection<LoadSpec>)`. If an entry whose key
    /// [`Loader::compare_to`]s equal to `loader` already exists (matching `TreeMap`'s
    /// comparator-based key lookup, not `Loader.equals`/identity), it is replaced and its
    /// previous `LoadSpec`s are returned, mirroring `Map.put`'s return value. Otherwise the new
    /// entry is inserted in sorted position and `None` is returned.
    pub fn put(&mut self, loader: Box<dyn Loader>, load_specs: Vec<LoadSpec>) -> Option<Vec<LoadSpec>> {
        if let Some(pos) =
            self.entries.iter().position(|(existing, _)| existing.compare_to(loader.as_ref()) == Ordering::Equal)
        {
            let (_, previous) = std::mem::replace(&mut self.entries[pos], (loader, load_specs));
            return Some(previous);
        }
        self.entries.push((loader, load_specs));
        self.entries.sort_by(|(a, _), (b, _)| a.compare_to(b.as_ref()));
        None
    }

    /// The [`LoadSpec`]s associated with a [`Loader`] comparing equal (via
    /// [`Loader::compare_to`]) to `loader`, if any.
    ///
    /// Port of `TreeMap.get(Object)`.
    pub fn get(&self, loader: &dyn Loader) -> Option<&Vec<LoadSpec>> {
        self.entries
            .iter()
            .find(|(existing, _)| existing.compare_to(loader) == Ordering::Equal)
            .map(|(_, load_specs)| load_specs)
    }

    /// The number of [`Loader`] keys in this map.
    ///
    /// Port of `TreeMap.size()`.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Whether this map has no entries.
    ///
    /// Port of `TreeMap.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The [`Loader`] keys, in [`Loader::compare_to`] sort order.
    ///
    /// Port of `TreeMap.keySet()`.
    pub fn keys(&self) -> impl Iterator<Item = &dyn Loader> {
        self.entries.iter().map(|(loader, _)| loader.as_ref())
    }

    /// The [`LoadSpec`] collections, in [`Loader`] key sort order.
    ///
    /// Port of `TreeMap.values()`.
    pub fn values(&self) -> impl Iterator<Item = &Vec<LoadSpec>> {
        self.entries.iter().map(|(_, load_specs)| load_specs)
    }

    /// The `(Loader, LoadSpecs)` entries, in [`Loader`] key sort order.
    ///
    /// Port of `TreeMap.entrySet()`.
    pub fn iter(&self) -> impl Iterator<Item = (&dyn Loader, &Vec<LoadSpec>)> {
        self.entries.iter().map(|(loader, load_specs)| (loader.as_ref(), load_specs))
    }
}

impl fmt::Display for LoaderMap {
    /// Port of `LoaderMap.toString()`:
    /// ```java
    /// StringBuilder sb = new StringBuilder();
    /// for (Loader loader : keySet()) {
    ///     Collection<LoadSpec> loadSpecs = get(loader);
    ///     sb.append(loader.getName() + " - " + loadSpecs.size() + " load specs\n");
    /// }
    /// return sb.toString();
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (loader, load_specs) in &self.entries {
            writeln!(f, "{} - {} load specs", loader.get_name(), load_specs.len())?;
        }
        Ok(())
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
        tier: LoaderTier,
        tier_priority: i32,
    }

    impl MockLoader {
        fn new(name: &'static str) -> Self {
            MockLoader { name, tier: LoaderTier::GenericTargetLoader, tier_priority: 0 }
        }

        fn with_tier(name: &'static str, tier: LoaderTier, tier_priority: i32) -> Self {
            MockLoader { name, tier, tier_priority }
        }
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
            self.tier
        }

        fn get_tier_priority(&self) -> i32 {
            self.tier_priority
        }
    }

    impl ExtensionPoint for MockLoader {}

    fn loader(name: &'static str) -> Box<dyn Loader> {
        Box::new(MockLoader::new(name))
    }

    fn spec(image_base: i64) -> LoadSpec {
        LoadSpec::unresolved(loader("inner"), image_base, false)
    }

    #[test]
    fn new_map_is_empty() {
        let map = LoaderMap::new();
        assert!(map.is_empty());
        assert_eq!(map.size(), 0);
        assert_eq!(map.keys().count(), 0);
    }

    #[test]
    fn put_and_get_round_trip() {
        let mut map = LoaderMap::new();
        assert!(map.put(loader("alpha"), vec![spec(0x1000)]).is_none());

        let alpha = loader("alpha");
        let load_specs = map.get(alpha.as_ref()).expect("alpha should be present");
        assert_eq!(load_specs.len(), 1);
        assert_eq!(load_specs[0].get_desired_image_base(), 0x1000);
        assert_eq!(map.size(), 1);
        assert!(!map.is_empty());
    }

    #[test]
    fn get_returns_none_for_unknown_loader() {
        let mut map = LoaderMap::new();
        map.put(loader("alpha"), vec![spec(0)]);

        let unknown = loader("zeta");
        assert!(map.get(unknown.as_ref()).is_none());
    }

    #[test]
    fn keys_are_ordered_by_loader_natural_ordering() {
        // Insert out of order; Loader::compare_to orders by tier, then tier priority, then name,
        // and all three of these share the same (default) tier/priority, so this reduces to
        // alphabetical-by-name -- exactly mirroring TreeMap<Loader, ...>'s sorted iteration.
        let mut map = LoaderMap::new();
        map.put(loader("zebra"), vec![spec(0)]);
        map.put(loader("alpha"), vec![spec(0)]);
        map.put(loader("mid"), vec![spec(0)]);

        let names: Vec<String> = map.keys().map(|l| l.get_name()).collect();
        assert_eq!(names, vec!["alpha".to_string(), "mid".to_string(), "zebra".to_string()]);
    }

    #[test]
    fn keys_are_ordered_by_tier_before_name() {
        // Names are deliberately reverse-alphabetical relative to tier rank, so a name-only sort
        // would disagree with the expected result: proves tier is compared before name in
        // Loader::compare_to's tier-first ordering, not merely consistent with it.
        let mut map = LoaderMap::new();
        map.put(
            Box::new(MockLoader::with_tier("aaa_generic_tier", LoaderTier::GenericTargetLoader, 0)),
            vec![spec(0)],
        );
        map.put(
            Box::new(MockLoader::with_tier("zzz_specialized_tier", LoaderTier::SpecializedTargetLoader, 0)),
            vec![spec(0)],
        );

        let names: Vec<String> = map.keys().map(|l| l.get_name()).collect();
        assert_eq!(names, vec!["zzz_specialized_tier".to_string(), "aaa_generic_tier".to_string()]);
    }

    #[test]
    fn put_replacing_existing_key_returns_previous_load_specs() {
        let mut map = LoaderMap::new();
        assert!(map.put(loader("alpha"), vec![spec(0x1000)]).is_none());

        let previous = map.put(loader("alpha"), vec![spec(0x2000), spec(0x3000)]);
        let previous = previous.expect("replacing an existing key must return the old value");
        assert_eq!(previous.len(), 1);
        assert_eq!(previous[0].get_desired_image_base(), 0x1000);

        assert_eq!(map.size(), 1, "replacing must not create a second entry");
        let current = map.get(loader("alpha").as_ref()).unwrap();
        assert_eq!(current.len(), 2);
    }

    #[test]
    fn put_treats_loaders_as_equal_when_compare_to_is_equal() {
        // Faithful TreeMap semantics: two *distinct* Loader instances that compare equal via
        // Loader::compare_to (same tier, same tier priority, same name) collide into a single
        // key, exactly like a real java.util.TreeMap<Loader, ...> would (key lookup uses the
        // comparator, not Loader.equals/instance identity). Not a LoaderMap-specific bug --
        // standard TreeMap behavior -- but worth proving directly since Rust has no equivalent
        // built-in comparator-keyed map to fall back on.
        let mut map = LoaderMap::new();
        map.put(loader("same-name"), vec![spec(1)]);
        map.put(loader("same-name"), vec![spec(2)]);

        assert_eq!(map.size(), 1);
        let load_specs = map.get(loader("same-name").as_ref()).unwrap();
        assert_eq!(load_specs.len(), 1);
        assert_eq!(load_specs[0].get_desired_image_base(), 2);
    }

    #[test]
    fn values_iterates_in_key_sort_order() {
        let mut map = LoaderMap::new();
        map.put(loader("zebra"), vec![spec(0), spec(1)]);
        map.put(loader("alpha"), vec![spec(2)]);

        let sizes: Vec<usize> = map.values().map(|v| v.len()).collect();
        assert_eq!(sizes, vec![1, 2], "alpha (1 spec) must come before zebra (2 specs)");
    }

    #[test]
    fn iter_yields_matching_key_value_pairs_in_sort_order() {
        let mut map = LoaderMap::new();
        map.put(loader("zebra"), vec![spec(0), spec(1)]);
        map.put(loader("alpha"), vec![spec(2)]);

        let pairs: Vec<(String, usize)> = map.iter().map(|(l, v)| (l.get_name(), v.len())).collect();
        assert_eq!(pairs, vec![("alpha".to_string(), 1), ("zebra".to_string(), 2)]);
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let mut map = LoaderMap::new();
        map.put(loader("alpha"), vec![spec(0), spec(1)]);
        map.put(loader("zebra"), vec![spec(2)]);

        assert_eq!(map.to_string(), "alpha - 2 load specs\nzebra - 1 load specs\n");
    }

    #[test]
    fn display_of_empty_map_is_empty_string() {
        let map = LoaderMap::new();
        assert_eq!(map.to_string(), "");
    }
}
