use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::app::plugin::core::osgi::GhidraBundle;
use crate::generic::jar::ResourceFile;

/// A thread-safe container that maps [`GhidraBundle`]s by file and bundle location.
///
/// Port of `ghidra.app.plugin.core.osgi.BundleMap`.
///
/// # Deviations from Java
///
/// * **`ResourceFile` doesn't implement `Eq`/`Hash`.** Java's `bundlesByFile` is a
///   `Map<ResourceFile, GhidraBundle>`, relying on `ResourceFile`'s own `equals`/`hashCode`
///   (ultimately based on the underlying file's path). The ported [`ResourceFile`] has no such
///   `Eq`/`Hash` impl, so this port keys that map by [`ResourceFile::absolute_path`] (a `String`)
///   instead, storing the bundle (from which the original `ResourceFile` can always be recovered
///   via [`GhidraBundle::file`]) as the value.
/// * **`computeAllIfAbsent`/`add`/`addAll` no longer re-acquire the write lock reentrantly.**
///   Java's `computeAllIfAbsent` takes the write lock and then calls the public `addAll(...)`,
///   which takes the *same* write lock again -- safe in Java only because
///   `ReentrantReadWriteLock`'s write lock is, as the name implies, reentrant for the owning
///   thread. [`std::sync::RwLock`] is not reentrant; a second write-lock acquisition by the same
///   thread that already holds it is a deadlock, not a safe no-op. This port avoids that hazard by
///   factoring the actual map mutations into a private, lock-free [`BundleMapInner::add`] that
///   every public method calls while already holding its own single lock acquisition, rather than
///   calling back into another public, self-locking method. The externally observable behavior
///   (which bundles end up mapped, and the value returned) is unchanged.
/// * **The two `remove` overloads that return the removed bundle can panic.** Java's
///   `remove(String bundleLocation)` and `remove(ResourceFile bundleFile)` each look the bundle up
///   in one map and then immediately dereference it (`bundle.getFile()` /
///   `bundle.getLocationIdentifier()`) to clean up the other map -- with no null check. If the
///   given key isn't actually mapped, that dereference throws `NullPointerException` in Java. This
///   is reproduced faithfully (not "fixed") as a panic in [`remove_by_location`](Self::remove_by_location)/
///   [`remove_by_file`](Self::remove_by_file) -- see their own docs and the dedicated
///   `#[should_panic]` tests below.
pub struct BundleMap {
    inner: RwLock<BundleMapInner>,
}

#[derive(Default)]
struct BundleMapInner {
    bundles_by_file: HashMap<String, Arc<dyn GhidraBundle>>,
    bundles_by_location: HashMap<String, Arc<dyn GhidraBundle>>,
}

impl BundleMapInner {
    /// The shared "insert into both maps" logic behind `add`/`addAll`/`computeAllIfAbsent`,
    /// operating directly on already-locked state (see the struct's own docs on avoiding
    /// reentrant locking).
    fn add(&mut self, bundle: Arc<dyn GhidraBundle>) {
        self.bundles_by_file.insert(bundle.file().absolute_path(), bundle.clone());
        self.bundles_by_location.insert(bundle.get_location_identifier(), bundle);
    }

    fn remove(&mut self, bundle: &Arc<dyn GhidraBundle>) {
        self.bundles_by_file.remove(&bundle.file().absolute_path());
        self.bundles_by_location.remove(&bundle.get_location_identifier());
    }
}

impl BundleMap {
    /// Creates a new, empty `BundleMap`.
    pub fn new() -> Self {
        Self { inner: RwLock::new(BundleMapInner::default()) }
    }

    /// Maps associations between a bundle, its file, and its bundle location.
    ///
    /// Mirrors `BundleMap.add(GhidraBundle)`.
    pub fn add(&self, bundle: Arc<dyn GhidraBundle>) {
        self.inner.write().unwrap().add(bundle);
    }

    /// Maps bundles in a collection.
    ///
    /// This is the same as calling [`add`](Self::add) for each bundle in `bundles`.
    ///
    /// Mirrors `BundleMap.addAll(Collection<GhidraBundle>)`.
    pub fn add_all(&self, bundles: impl IntoIterator<Item = Arc<dyn GhidraBundle>>) {
        let mut inner = self.inner.write().unwrap();
        for bundle in bundles {
            inner.add(bundle);
        }
    }

    /// Removes the mappings of a bundle.
    ///
    /// Mirrors `BundleMap.remove(GhidraBundle)`.
    pub fn remove(&self, bundle: &Arc<dyn GhidraBundle>) {
        self.inner.write().unwrap().remove(bundle);
    }

    /// Removes all mappings of each bundle from a collection.
    ///
    /// This is the same as calling [`remove`](Self::remove) for each bundle in `bundles`.
    ///
    /// Mirrors `BundleMap.removeAll(Collection<GhidraBundle>)`.
    pub fn remove_all<'a>(&self, bundles: impl IntoIterator<Item = &'a Arc<dyn GhidraBundle>>) {
        let mut inner = self.inner.write().unwrap();
        for bundle in bundles {
            inner.remove(bundle);
        }
    }

    /// Removes the mapping for a bundle with a given bundle location.
    ///
    /// Returns the bundle removed.
    ///
    /// Mirrors `BundleMap.remove(String bundleLocation)`.
    ///
    /// # Panics
    ///
    /// Panics if `bundle_location` has no mapping -- mirrors Java's `NullPointerException` when
    /// `bundlesByLocation.remove(bundleLocation)` returns `null` and is then immediately
    /// dereferenced. See the struct's own docs.
    pub fn remove_by_location(&self, bundle_location: &str) -> Arc<dyn GhidraBundle> {
        let mut inner = self.inner.write().unwrap();
        let bundle = inner.bundles_by_location.remove(bundle_location).unwrap_or_else(|| {
            panic!(
                "BundleMap::remove_by_location: no bundle mapped at location {bundle_location:?} \
                 (mirrors Java's NullPointerException from GhidraBundle.getFile() on a null lookup)"
            )
        });
        inner.bundles_by_file.remove(&bundle.file().absolute_path());
        bundle
    }

    /// Removes the mapping for a bundle with a given file.
    ///
    /// Returns the bundle removed.
    ///
    /// Mirrors `BundleMap.remove(ResourceFile bundleFile)`.
    ///
    /// # Panics
    ///
    /// Panics if `bundle_file` has no mapping -- mirrors Java's `NullPointerException` when
    /// `bundlesByFile.remove(bundleFile)` returns `null` and is then immediately dereferenced. See
    /// the struct's own docs.
    pub fn remove_by_file(&self, bundle_file: &ResourceFile) -> Arc<dyn GhidraBundle> {
        let mut inner = self.inner.write().unwrap();
        let bundle = inner.bundles_by_file.remove(&bundle_file.absolute_path()).unwrap_or_else(|| {
            panic!(
                "BundleMap::remove_by_file: no bundle mapped at file {:?} (mirrors Java's \
                 NullPointerException from GhidraBundle.getLocationIdentifier() on a null lookup)",
                bundle_file.absolute_path()
            )
        });
        inner.bundles_by_location.remove(&bundle.get_location_identifier());
        bundle
    }

    /// Creates and maps bundles from files in a collection that aren't already mapped.
    ///
    /// `ctor` constructs a `GhidraBundle` given a bundle file. Returns the newly created bundles.
    ///
    /// Mirrors `BundleMap.computeAllIfAbsent(Collection<ResourceFile>, Function<ResourceFile,
    /// GhidraBundle>)`.
    pub fn compute_all_if_absent(
        &self,
        bundle_files: &[ResourceFile],
        ctor: impl Fn(&ResourceFile) -> Arc<dyn GhidraBundle>,
    ) -> Vec<Arc<dyn GhidraBundle>> {
        let mut inner = self.inner.write().unwrap();

        // Mirrors `new HashSet<>(bundleFiles)`: de-duplicate the input by file identity
        // (approximated by absolute path, since `ResourceFile` has no `Eq`/`Hash` of its own).
        let mut distinct: HashMap<String, ResourceFile> = HashMap::new();
        for file in bundle_files {
            distinct.entry(file.absolute_path()).or_insert_with(|| file.clone());
        }

        // Mirrors `newBundleFiles.removeAll(bundlesByFile.keySet())`.
        distinct.retain(|path, _| !inner.bundles_by_file.contains_key(path));

        let new_bundles: Vec<Arc<dyn GhidraBundle>> = distinct.values().map(&ctor).collect();
        for bundle in &new_bundles {
            inner.add(bundle.clone());
        }
        new_bundles
    }

    /// Returns the bundle with the given location, or `None` if not found.
    ///
    /// Mirrors `BundleMap.getBundleAtLocation(String)`.
    pub fn get_bundle_at_location(&self, location: &str) -> Option<Arc<dyn GhidraBundle>> {
        self.inner.read().unwrap().bundles_by_location.get(location).cloned()
    }

    /// Returns the bundle with the given file, or `None` if not found.
    ///
    /// Mirrors `BundleMap.get(ResourceFile)`.
    pub fn get(&self, bundle_file: &ResourceFile) -> Option<Arc<dyn GhidraBundle>> {
        self.inner.read().unwrap().bundles_by_file.get(&bundle_file.absolute_path()).cloned()
    }

    /// Returns the currently mapped bundles.
    ///
    /// Mirrors `BundleMap.getGhidraBundles()`.
    pub fn get_ghidra_bundles(&self) -> Vec<Arc<dyn GhidraBundle>> {
        self.inner.read().unwrap().bundles_by_file.values().cloned().collect()
    }

    /// Returns the currently mapped bundle files.
    ///
    /// Mirrors `BundleMap.getBundleFiles()`.
    pub fn get_bundle_files(&self) -> Vec<ResourceFile> {
        self.inner.read().unwrap().bundles_by_file.values().map(|bundle| bundle.file().clone()).collect()
    }
}

impl Default for BundleMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::osgi::{
        BundleCapability, BundleRequirement, GhidraBundleBase, GhidraBundleException,
    };
    use crate::app::seam_stubs::BundleHost;
    use std::io::Write as _;
    use std::path::PathBuf;

    struct MockBundle {
        base: GhidraBundleBase,
        location: String,
    }

    impl MockBundle {
        fn new(path: &str, location: &str) -> Arc<dyn GhidraBundle> {
            let bundle_file = ResourceFile::new(PathBuf::from(path));
            Arc::new(MockBundle {
                base: GhidraBundleBase::new(Arc::new(BundleHost), bundle_file, true, false),
                location: location.to_string(),
            })
        }
    }

    impl GhidraBundle for MockBundle {
        fn base(&self) -> &GhidraBundleBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut GhidraBundleBase {
            &mut self.base
        }

        fn clean(&mut self) -> bool {
            false
        }

        fn build(&mut self, writer: &mut dyn std::io::Write) -> Result<bool, Box<dyn std::error::Error>> {
            writer.write_all(b"")?;
            Ok(false)
        }

        fn get_location_identifier(&self) -> String {
            self.location.clone()
        }

        fn get_all_requirements(&self) -> Result<Vec<BundleRequirement>, GhidraBundleException> {
            Ok(Vec::new())
        }

        fn get_all_capabilities(&self) -> Result<Vec<BundleCapability>, GhidraBundleException> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn new_map_is_empty() {
        let map = BundleMap::new();
        assert!(map.get_ghidra_bundles().is_empty());
        assert!(map.get_bundle_files().is_empty());
    }

    #[test]
    fn add_maps_by_both_file_and_location() {
        let map = BundleMap::new();
        let bundle = MockBundle::new("/bundles/one.jar", "file:/bundles/one.jar");
        map.add(bundle.clone());

        assert!(map.get(bundle.file()).is_some());
        assert!(map.get_bundle_at_location("file:/bundles/one.jar").is_some());
        assert_eq!(map.get_ghidra_bundles().len(), 1);
        assert_eq!(map.get_bundle_files().len(), 1);
    }

    #[test]
    fn add_all_maps_every_bundle() {
        let map = BundleMap::new();
        let a = MockBundle::new("/bundles/a.jar", "file:/bundles/a.jar");
        let b = MockBundle::new("/bundles/b.jar", "file:/bundles/b.jar");
        map.add_all(vec![a.clone(), b.clone()]);

        assert_eq!(map.get_ghidra_bundles().len(), 2);
        assert!(map.get(a.file()).is_some());
        assert!(map.get(b.file()).is_some());
    }

    #[test]
    fn remove_clears_both_mappings() {
        let map = BundleMap::new();
        let bundle = MockBundle::new("/bundles/one.jar", "file:/bundles/one.jar");
        map.add(bundle.clone());

        map.remove(&bundle);

        assert!(map.get(bundle.file()).is_none());
        assert!(map.get_bundle_at_location("file:/bundles/one.jar").is_none());
    }

    #[test]
    fn remove_all_clears_every_bundle() {
        let map = BundleMap::new();
        let a = MockBundle::new("/bundles/a.jar", "file:/bundles/a.jar");
        let b = MockBundle::new("/bundles/b.jar", "file:/bundles/b.jar");
        map.add_all(vec![a.clone(), b.clone()]);

        map.remove_all(vec![&a, &b]);

        assert!(map.get_ghidra_bundles().is_empty());
    }

    #[test]
    fn remove_by_location_returns_bundle_and_clears_both_mappings() {
        let map = BundleMap::new();
        let bundle = MockBundle::new("/bundles/one.jar", "file:/bundles/one.jar");
        map.add(bundle.clone());

        let removed = map.remove_by_location("file:/bundles/one.jar");

        assert_eq!(removed.get_location_identifier(), "file:/bundles/one.jar");
        assert!(map.get(bundle.file()).is_none());
        assert!(map.get_bundle_at_location("file:/bundles/one.jar").is_none());
    }

    /// Java quirk, reproduced faithfully: `remove(String)` dereferences the (possibly-null) result
    /// of the map lookup without a null check, throwing `NullPointerException` if the location
    /// isn't mapped. See the struct's own docs.
    #[test]
    #[should_panic(expected = "no bundle mapped at location")]
    fn remove_by_location_panics_when_not_mapped() {
        let map = BundleMap::new();
        map.remove_by_location("file:/does/not/exist.jar");
    }

    #[test]
    fn remove_by_file_returns_bundle_and_clears_both_mappings() {
        let map = BundleMap::new();
        let bundle = MockBundle::new("/bundles/one.jar", "file:/bundles/one.jar");
        map.add(bundle.clone());

        let removed = map.remove_by_file(bundle.file());

        assert_eq!(removed.get_location_identifier(), "file:/bundles/one.jar");
        assert!(map.get_bundle_at_location("file:/bundles/one.jar").is_none());
    }

    /// Java quirk, reproduced faithfully: `remove(ResourceFile)` dereferences the (possibly-null)
    /// result of the map lookup without a null check, throwing `NullPointerException` if the file
    /// isn't mapped. See the struct's own docs.
    #[test]
    #[should_panic(expected = "no bundle mapped at file")]
    fn remove_by_file_panics_when_not_mapped() {
        let map = BundleMap::new();
        let missing = ResourceFile::new(PathBuf::from("/does/not/exist.jar"));
        map.remove_by_file(&missing);
    }

    #[test]
    fn compute_all_if_absent_only_constructs_new_bundles() {
        let map = BundleMap::new();
        let existing = MockBundle::new("/bundles/existing.jar", "file:/bundles/existing.jar");
        map.add(existing.clone());

        let files = vec![
            ResourceFile::new(PathBuf::from("/bundles/existing.jar")),
            ResourceFile::new(PathBuf::from("/bundles/new.jar")),
        ];
        let constructed = std::sync::Mutex::new(Vec::new());
        let new_bundles = map.compute_all_if_absent(&files, |file| {
            constructed.lock().unwrap().push(file.absolute_path());
            MockBundle::new(&file.absolute_path(), &format!("file:{}", file.absolute_path()))
        });

        // Only the not-already-mapped file triggers construction.
        assert_eq!(constructed.into_inner().unwrap(), vec!["/bundles/new.jar".to_string()]);
        assert_eq!(new_bundles.len(), 1);
        assert_eq!(map.get_ghidra_bundles().len(), 2);
    }

    #[test]
    fn compute_all_if_absent_deduplicates_input_files() {
        let map = BundleMap::new();
        let files = vec![
            ResourceFile::new(PathBuf::from("/bundles/dup.jar")),
            ResourceFile::new(PathBuf::from("/bundles/dup.jar")),
        ];
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let new_bundles = map.compute_all_if_absent(&files, |file| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            MockBundle::new(&file.absolute_path(), "file:/bundles/dup.jar")
        });

        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(new_bundles.len(), 1);
    }

    #[test]
    fn compute_all_if_absent_returns_empty_when_nothing_new() {
        let map = BundleMap::new();
        let bundle = MockBundle::new("/bundles/one.jar", "file:/bundles/one.jar");
        map.add(bundle);

        let files = vec![ResourceFile::new(PathBuf::from("/bundles/one.jar"))];
        let new_bundles = map.compute_all_if_absent(&files, |file| {
            MockBundle::new(&file.absolute_path(), "unused")
        });
        assert!(new_bundles.is_empty());
    }

    #[test]
    fn get_returns_none_for_unmapped_file() {
        let map = BundleMap::new();
        let missing = ResourceFile::new(PathBuf::from("/does/not/exist.jar"));
        assert!(map.get(&missing).is_none());
    }

    #[test]
    fn get_bundle_at_location_returns_none_for_unmapped_location() {
        let map = BundleMap::new();
        assert!(map.get_bundle_at_location("nowhere").is_none());
    }

    #[test]
    fn default_is_empty() {
        let map = BundleMap::default();
        assert!(map.get_ghidra_bundles().is_empty());
    }
}
