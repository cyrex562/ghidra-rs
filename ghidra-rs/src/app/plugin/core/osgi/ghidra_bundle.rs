use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use crate::app::seam_stubs::BundleHost;
use crate::generic::jar::ResourceFile;

use super::{Bundle, BundleCapability, BundleRequirement, BundleState, GhidraBundleException};

/// The kind of a [`GhidraBundle`], decided by its backing file.
///
/// Port of the nested enum `ghidra.app.plugin.core.osgi.GhidraBundle.Type`. A `GhidraBundle` can
/// be a Bndtools `.bnd` script, an OSGi bundle `.jar` file, or a directory of Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhidraBundleType {
    /// A Bndtools `.bnd` script.
    BndScript,
    /// An OSGi bundle `.jar` file.
    Jar,
    /// A directory of Java source.
    SourceDir,
    /// Neither a recognized script, jar, nor directory.
    Invalid,
}

impl GhidraBundleType {
    /// Determine the type of a bundle from its [`ResourceFile`].
    ///
    /// Mirrors the package-private `GhidraBundle.getType(ResourceFile)`.
    pub fn of_resource_file(file: &ResourceFile) -> Self {
        if file.is_directory() {
            return GhidraBundleType::SourceDir;
        }
        Self::of_file_name(&file.name())
    }

    /// Determine the type of a bundle from a plain filesystem [`Path`].
    ///
    /// Mirrors the public `GhidraBundle.getType(File)`.
    pub fn of_path(file: &Path) -> Self {
        if file.is_dir() {
            return GhidraBundleType::SourceDir;
        }
        let file_name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::of_file_name(&file_name)
    }

    fn of_file_name(file_name: &str) -> Self {
        let lower = file_name.to_lowercase();
        if lower.ends_with(".bnd") {
            GhidraBundleType::BndScript
        } else if lower.ends_with(".jar") {
            GhidraBundleType::Jar
        } else {
            GhidraBundleType::Invalid
        }
    }
}

/// Shared state for every [`GhidraBundle`] implementation: the backing file, the owning
/// [`BundleHost`], and the enabled/system-bundle flags.
///
/// Port of the field half of `ghidra.app.plugin.core.osgi.GhidraBundle`, an abstract class.
/// Rust has no field inheritance, so this struct holds what Java's four instance fields held.
/// A concrete bundle kind (the not-yet-ported `GhidraJarBundle`, `GhidraSourceBundle`,
/// `GhidraPlaceholderBundle`) embeds one of these and implements
/// [`GhidraBundle::base`]/[`GhidraBundle::base_mut`] to expose it; the trait's default methods
/// (mirroring `GhidraBundle`'s concrete methods) are built on top of it.
pub struct GhidraBundleBase {
    /// The file this bundle is loaded from -- can be a directory or a jar file.
    pub bundle_file: ResourceFile,
    /// The host that manages this bundle, shared by every bundle it tracks.
    pub bundle_host: Arc<BundleHost>,
    /// Whether this bundle is enabled; if enabled, its contents are scanned (e.g. for scripts).
    pub enabled: bool,
    /// Whether this is a "system bundle": it cannot be removed and its contents cannot be
    /// edited.
    pub system_bundle: bool,
}

impl GhidraBundleBase {
    /// Mirrors the package-private constructor
    /// `GhidraBundle(BundleHost, ResourceFile, boolean, boolean)`.
    pub fn new(
        bundle_host: Arc<BundleHost>,
        bundle_file: ResourceFile,
        enabled: bool,
        system_bundle: bool,
    ) -> Self {
        Self { bundle_host, bundle_file, enabled, system_bundle }
    }
}

/// Proxy for an OSGi bundle that may require being built.
///
/// Port of `ghidra.app.plugin.core.osgi.GhidraBundle`. The abstract methods (`clean`, `build`
/// with an explicit writer, `getLocationIdentifier`, `getAllRequirements`,
/// `getAllCapabilities`) are required here; the methods Java implements directly on the abstract
/// class are provided as defaults built atop [`base`](GhidraBundle::base)/
/// [`base_mut`](GhidraBundle::base_mut).
pub trait GhidraBundle: Send + Sync {
    /// Access the shared bundle state.
    fn base(&self) -> &GhidraBundleBase;

    /// Mutably access the shared bundle state.
    fn base_mut(&mut self) -> &mut GhidraBundleBase;

    /// Clean build artifacts generated during build of this bundle.
    ///
    /// Returns `true` if anything was done.
    fn clean(&mut self) -> bool;

    /// Build the OSGi bundle if needed and if possible.
    ///
    /// `writer` receives build messages for the user. Returns `true` if a build happened,
    /// `false` if it was already built or could not be built.
    fn build(&mut self, writer: &mut dyn Write) -> Result<bool, Box<dyn std::error::Error>>;

    /// The location identifier of the bundle that this `GhidraBundle` represents.
    ///
    /// Used by the framework, e.g. passed to `BundleContext#installBundle` when the bundle is
    /// first installed. Although the bundle location is a URI, outside of interactions with the
    /// framework the bundle location should remain opaque.
    fn get_location_identifier(&self) -> String;

    /// All bundle requirements.
    fn get_all_requirements(&self) -> Result<Vec<BundleRequirement>, GhidraBundleException>;

    /// All bundle capabilities.
    fn get_all_capabilities(&self) -> Result<Vec<BundleCapability>, GhidraBundleException>;

    /// Same as [`build`](Self::build), writing build messages to stderr.
    fn build_default(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stderr = io::stderr();
        self.build(&mut stderr)
    }

    /// The file where this bundle is loaded from.
    fn file(&self) -> &ResourceFile {
        &self.base().bundle_file
    }

    /// True if this bundle is enabled.
    fn is_enabled(&self) -> bool {
        self.base().enabled
    }

    /// Set the enablement flag for this bundle. If enabled, its contents will be scanned, e.g.
    /// for scripts.
    fn set_enabled(&mut self, enabled: bool) {
        self.base_mut().enabled = enabled;
    }

    /// True if this is a "system bundle": it cannot be removed and its contents cannot be
    /// edited.
    fn is_system_bundle(&self) -> bool {
        self.base().system_bundle
    }

    /// The OSGi bundle represented by this `GhidraBundle`, or `None` if it isn't in the
    /// "installed" state.
    fn os_gi_bundle(&self) -> Option<Bundle> {
        let location = self.get_location_identifier();
        self.base().bundle_host.get_os_gi_bundle(&location)
    }

    /// True if this bundle is active.
    fn is_active(&self) -> bool {
        self.os_gi_bundle()
            .map(|bundle| bundle.get_state() == BundleState::Active)
            .unwrap_or(false)
    }

    /// A human-readable identifier for this bundle: the installed OSGi bundle's location if
    /// active, otherwise the backing file's path.
    ///
    /// Mirrors `GhidraBundle.toString()`, approximated: the real OSGi framework's
    /// `Bundle.getSymbolicName()` isn't modeled by this crate's simplified [`Bundle`] type, so
    /// the bundle's location identifier is used in its place.
    fn to_display_string(&self) -> String {
        match self.os_gi_bundle() {
            Some(bundle) => bundle.get_location().to_string(),
            None => self.base().bundle_file.absolute_path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBundle {
        base: GhidraBundleBase,
        location: String,
        clean_calls: usize,
    }

    impl MockBundle {
        fn new(location: &str, enabled: bool, system_bundle: bool) -> Self {
            let bundle_file = ResourceFile::new(std::path::PathBuf::from("/bundles/example.jar"));
            MockBundle {
                base: GhidraBundleBase::new(Arc::new(BundleHost), bundle_file, enabled, system_bundle),
                location: location.to_string(),
                clean_calls: 0,
            }
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
            self.clean_calls += 1;
            true
        }

        fn build(&mut self, writer: &mut dyn Write) -> Result<bool, Box<dyn std::error::Error>> {
            writer.write_all(b"building\n")?;
            Ok(true)
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
    fn get_type_matches_java_extension_rules() {
        // Java's GhidraBundle.getType(File): directory -> SOURCE_DIR, ".bnd" -> BND_SCRIPT,
        // ".jar" -> JAR, anything else -> INVALID. Case-insensitive on the extension.
        assert_eq!(
            GhidraBundleType::of_path(Path::new("/scripts/Foo.BND")),
            GhidraBundleType::BndScript
        );
        assert_eq!(
            GhidraBundleType::of_path(Path::new("/bundles/foo.jar")),
            GhidraBundleType::Jar
        );
        assert_eq!(
            GhidraBundleType::of_path(Path::new("/bundles/foo.txt")),
            GhidraBundleType::Invalid
        );
    }

    #[test]
    fn get_type_from_resource_file_directory_is_source_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file = ResourceFile::new(temp_dir.path().to_path_buf());
        assert_eq!(GhidraBundleType::of_resource_file(&file), GhidraBundleType::SourceDir);
    }

    #[test]
    fn accessors_reflect_constructed_state() {
        let bundle = MockBundle::new("file:/bundles/example.jar", true, false);
        assert!(bundle.is_enabled());
        assert!(!bundle.is_system_bundle());
        assert_eq!(bundle.get_location_identifier(), "file:/bundles/example.jar");
    }

    #[test]
    fn set_enabled_mutates_shared_base_state() {
        let mut bundle = MockBundle::new("file:/bundles/example.jar", false, false);
        assert!(!bundle.is_enabled());
        bundle.set_enabled(true);
        assert!(bundle.is_enabled());
    }

    #[test]
    fn is_active_is_false_while_bundle_host_is_unported() {
        // The BundleHost stub always reports no installed OSGi bundle, so isActive() is false
        // just like an uninstalled bundle in Java.
        let bundle = MockBundle::new("file:/bundles/example.jar", true, false);
        assert!(!bundle.is_active());
        assert!(bundle.os_gi_bundle().is_none());
    }

    #[test]
    fn to_display_string_falls_back_to_file_path_when_not_installed() {
        let bundle = MockBundle::new("file:/bundles/example.jar", true, false);
        assert_eq!(bundle.to_display_string(), "/bundles/example.jar");
    }

    #[test]
    fn build_default_delegates_to_build_with_stderr() {
        let mut bundle = MockBundle::new("file:/bundles/example.jar", true, false);
        let result = bundle.build_default();
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn clean_and_build_reach_the_concrete_implementation() {
        let mut bundle = MockBundle::new("file:/bundles/example.jar", true, false);
        assert!(bundle.clean());
        assert_eq!(bundle.clean_calls, 1);

        let mut out = Vec::new();
        let built = bundle.build(&mut out).unwrap();
        assert!(built);
        assert_eq!(out, b"building\n");
    }
}
