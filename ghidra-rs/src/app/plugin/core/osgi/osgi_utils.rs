use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::util::msg::Msg;

use super::OSGiException;

/// Matches group 1 = the file name from a resource string, e.g. from
/// `file:/path/to/some.jar!/Some.class` matches group 1 as `/path/to/some.jar`,
/// everything between ':' and '!'.
static JAR_FILENAME_EXTRACTOR: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.*:(.*)!.*$").unwrap());

/// Matches group 1 = the name of the Java package from an OSGi resolution error message.
/// If present, group 2 is the version constraint.
///
/// e.g. for the requirement `(&(osgi.wiring.package=x.y.z)(version>=1.2.3))`, this matches
/// with group 1 `x.y.z` and group 2 `(version>=1.2.3)`.
static PACKAGE_NAME_EXTRACTOR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(osgi\.wiring\.package=([^)]*)\)(\(version[^)]*\))?").unwrap()
});

const EXPORT_PACKAGE_HEADER: &str = "Export-Package";

/// The kind of OSGi bundle lifecycle event.
///
/// Simplified port of the `BundleEvent` type constants from `org.osgi.framework.BundleEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleEventType {
    Installed,
    Resolved,
    LazyActivation,
    Starting,
    Started,
    Stopping,
    Stopped,
    Updated,
    Unresolved,
    Uninstalled,
}

/// The lifecycle state of an OSGi bundle.
///
/// Simplified port of the `Bundle` state constants from `org.osgi.framework.Bundle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleState {
    Uninstalled,
    Installed,
    Resolved,
    Starting,
    Stopping,
    Active,
}

/// A single parsed clause from an OSGi `Import-Package` header: a package name plus the
/// attributes/directives (e.g. `version`, `resolution`) shared by its clause.
///
/// Simplified port of `org.osgi.framework.wiring.BundleRequirement`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleRequirement {
    pub package_name: String,
    pub attributes: BTreeMap<String, String>,
}

impl std::fmt::Display for BundleRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "osgi.wiring.package={}", self.package_name)?;
        for (key, value) in &self.attributes {
            write!(f, ";{key}={value}")?;
        }
        Ok(())
    }
}

/// A single parsed clause from an OSGi `Export-Package` header: a package name plus the
/// attributes/directives (e.g. `version`, `uses`) shared by its clause.
///
/// Simplified port of `org.osgi.framework.wiring.BundleCapability`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleCapability {
    pub package_name: String,
    pub attributes: BTreeMap<String, String>,
}

impl std::fmt::Display for BundleCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "osgi.wiring.package={}", self.package_name)?;
        for (key, value) in &self.attributes {
            write!(f, ";{key}={value}")?;
        }
        Ok(())
    }
}

/// Static utility methods for working with OSGi bundles, manifests, and the classpath.
///
/// Port of `ghidra.app.plugin.core.osgi.OSGiUtils`. The original class delegates most of its
/// manifest-header parsing to Apache Felix's `ManifestParser`; since no OSGi framework is
/// available in this crate, [`OSGiUtils::parse_import_package`] and
/// [`OSGiUtils::parse_export_package`] implement the OSGi header-clause grammar directly.
pub struct OSGiUtils;

impl OSGiUtils {
    /// The syntax of the error generated when OSGi requirements cannot be resolved is
    /// difficult to parse, so this extracts package names and versions.
    ///
    /// # Arguments
    /// * `osgi_exception_message` - the exception message
    ///
    /// # Returns
    /// a list of package names, possibly including versions
    pub fn extract_package_names_from_failed_resolution(osgi_exception_message: &str) -> Vec<String> {
        PACKAGE_NAME_EXTRACTOR
            .captures_iter(osgi_exception_message)
            .map(|caps| {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                match caps.get(2) {
                    Some(version) => format!("{name} {}", version.as_str()),
                    None => name.to_string(),
                }
            })
            .collect()
    }

    pub fn get_event_type_string(event_type: BundleEventType) -> &'static str {
        match event_type {
            BundleEventType::Installed => "INSTALLED",
            BundleEventType::Resolved => "RESOLVED",
            BundleEventType::LazyActivation => "LAZY_ACTIVATION",
            BundleEventType::Starting => "STARTING",
            BundleEventType::Started => "STARTED",
            BundleEventType::Stopping => "STOPPING",
            BundleEventType::Stopped => "STOPPED",
            BundleEventType::Updated => "UPDATED",
            BundleEventType::Unresolved => "UNRESOLVED",
            BundleEventType::Uninstalled => "UNINSTALLED",
        }
    }

    pub fn get_state_string(state: BundleState) -> &'static str {
        match state {
            BundleState::Uninstalled => "UNINSTALLED",
            BundleState::Installed => "INSTALLED",
            BundleState::Resolved => "RESOLVED",
            BundleState::Starting => "STARTING",
            BundleState::Stopping => "STOPPING",
            BundleState::Active => "ACTIVE",
        }
    }

    /// Parses an `Import-Package` string from a bundle manifest.
    ///
    /// # Arguments
    /// * `import_package_string` - `Import-Package` value
    ///
    /// # Returns
    /// the deduced requirements
    ///
    /// # Errors
    /// returns [`OSGiException`] on parse failure
    pub fn parse_import_package(
        import_package_string: &str,
    ) -> Result<Vec<BundleRequirement>, OSGiException> {
        let clauses = parse_header_clauses(import_package_string)?;
        Ok(clauses
            .into_iter()
            .flat_map(|(package_names, attributes)| {
                package_names
                    .into_iter()
                    .map(move |package_name| BundleRequirement {
                        package_name,
                        attributes: attributes.clone(),
                    })
            })
            .collect())
    }

    /// Parses an `Export-Package` string from a bundle manifest.
    ///
    /// # Arguments
    /// * `export_package_string` - `Export-Package` value
    ///
    /// # Returns
    /// the deduced capabilities
    ///
    /// # Errors
    /// returns [`OSGiException`] on parse failure
    pub fn parse_export_package(
        export_package_string: &str,
    ) -> Result<Vec<BundleCapability>, OSGiException> {
        let clauses = parse_header_clauses(export_package_string)?;
        Ok(clauses
            .into_iter()
            .flat_map(|(package_names, attributes)| {
                package_names
                    .into_iter()
                    .map(move |package_name| BundleCapability {
                        package_name,
                        attributes: attributes.clone(),
                    })
            })
            .collect())
    }

    /// Extracts the jar file path from a class-resource location string, e.g. given
    /// `file:/path/to/some.jar!/Some.class` returns `/path/to/some.jar`.
    ///
    /// Adapted from `findJarForClass`, which additionally resolved a `Class`'s resource
    /// location via Java's `ClassLoader`. Rust has no classloader/resource-location concept,
    /// so callers supply the resource location string directly.
    ///
    /// # Returns
    /// the jar path, or `None` if the location was not inside a jar
    pub fn find_jar_for_class_location(resource_location: &str) -> Option<String> {
        JAR_FILENAME_EXTRACTOR
            .captures(resource_location)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    pub fn get_packages_from_classpath(classpath_elements: &[PathBuf], packages: &mut HashSet<String>) {
        for path in classpath_elements {
            if path.is_dir() {
                Self::collect_packages_from_directory(path, packages);
            } else if path.extension().and_then(|e| e.to_str()) == Some("jar") {
                Self::collect_packages_from_jar(path, packages);
            }
        }
    }

    /// Splits a classpath string into its normalized path elements.
    ///
    /// Adapted from `getClasspathElements`, which read the classpath from the JVM's
    /// `java.class.path` system property; Rust has no equivalent runtime classpath, so
    /// callers supply the classpath string directly.
    pub fn get_classpath_elements(classpath: &str) -> Vec<PathBuf> {
        let separator = if cfg!(windows) { ';' } else { ':' };
        classpath
            .split(separator)
            .filter(|element| !element.is_empty())
            .map(|element| normalize_lexically(Path::new(element)))
            .collect()
    }

    pub fn collect_packages_from_directory(dir_path: &Path, packages: &mut HashSet<String>) {
        if let Err(e) = collect_class_files(dir_path, dir_path, packages) {
            Msg::error_with_error(
                "OSGiUtils",
                &"Error while collecting packages from directory",
                &e,
            );
        }
    }

    pub fn collect_packages_from_jar(jar_path: &Path, packages: &mut HashSet<String>) {
        if let Err(e) = collect_packages_from_jar_inner(jar_path, packages) {
            Msg::error_with_error("OSGiUtils", &"Error while collecting packages from jar", &*e);
        }
    }
}

/// Parses a comma-separated OSGi manifest header into clauses, where each clause is the set
/// of package names it applies to together with its shared attributes/directives.
///
/// This directly implements the OSGi header-clause grammar (see the `Import-Package` and
/// `Export-Package` header syntax in the OSGi Core specification) since no OSGi framework's
/// manifest parser is available in this crate.
fn parse_header_clauses(
    header: &str,
) -> Result<Vec<(Vec<String>, BTreeMap<String, String>)>, OSGiException> {
    let mut clauses = Vec::new();
    for raw_clause in split_top_level(header, ',') {
        let clause = raw_clause.trim();
        if clause.is_empty() {
            continue;
        }

        let mut package_names = Vec::new();
        let mut attributes = BTreeMap::new();
        for raw_part in split_top_level(clause, ';') {
            let part = raw_part.trim();
            if part.is_empty() {
                continue;
            }
            match split_attribute(part) {
                Some((key, value)) => {
                    attributes.insert(key, value);
                }
                None => package_names.push(part.to_string()),
            }
        }

        if package_names.is_empty() {
            return Err(OSGiException::new(&format!(
                "invalid OSGi header clause: '{clause}'"
            )));
        }
        clauses.push((package_names, attributes));
    }
    Ok(clauses)
}

/// Splits `part` into an attribute/directive key and value if it contains one, e.g.
/// `version=1.2.3` or `resolution:=optional`; returns `None` for a bare package name path.
fn split_attribute(part: &str) -> Option<(String, String)> {
    let eq_idx = part.find('=')?;
    let mut key = part[..eq_idx].trim();
    if let Some(stripped) = key.strip_suffix(':') {
        key = stripped;
    }
    // drop a typed-attribute suffix, e.g. "version:Version" -> "version"
    let key = key.split(':').next().unwrap_or(key).trim();
    let value = part[eq_idx + 1..].trim().trim_matches('"').to_string();
    Some((key.to_string(), value))
}

/// Splits `s` on `sep`, ignoring occurrences of `sep` inside double-quoted segments.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c == sep && !in_quotes {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    parts
}

/// Lexically normalizes `path`, collapsing `.` segments and resolving `..` segments against
/// preceding normal components without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(result.components().next_back(), Some(Component::Normal(_))) {
                    result.push("..");
                } else {
                    result.pop();
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn collect_class_files(root: &Path, dir: &Path, packages: &mut HashSet<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_class_files(root, &path, packages)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("class") {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            let relative_str = relative.to_string_lossy();
            match relative_str.rfind(std::path::MAIN_SEPARATOR) {
                Some(last_slash) if last_slash > 0 => {
                    packages.insert(relative_str[..last_slash].replace(std::path::MAIN_SEPARATOR, "."));
                }
                _ => {
                    packages.insert(String::new());
                }
            }
        }
    }
    Ok(())
}

fn collect_packages_from_jar_inner(
    jar_path: &Path,
    packages: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(jar_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let export_package_string = read_manifest_attribute(&mut archive, EXPORT_PACKAGE_HEADER)?;

    match export_package_string {
        Some(export_package_string) => {
            for package_name in split_top_level(&export_package_string, ',') {
                packages.insert(package_name);
            }
        }
        None => {
            for i in 0..archive.len() {
                let entry = archive.by_index(i)?;
                let name = entry.name();
                if name.ends_with(".class") {
                    if let Some(last_slash) = name.rfind('/') {
                        if last_slash > 0 {
                            packages.insert(name[..last_slash].replace('/', "."));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn read_manifest_attribute(
    archive: &mut zip::ZipArchive<File>,
    key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut manifest_text = String::new();
    match archive.by_name("META-INF/MANIFEST.MF") {
        Ok(mut entry) => {
            entry.read_to_string(&mut manifest_text)?;
        }
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(Box::new(e)),
    }

    let mut unfolded_lines: Vec<String> = Vec::new();
    for raw_line in manifest_text.lines() {
        if let Some(continuation) = raw_line.strip_prefix(' ') {
            if let Some(last) = unfolded_lines.last_mut() {
                last.push_str(continuation);
                continue;
            }
        }
        if !raw_line.is_empty() {
            unfolded_lines.push(raw_line.to_string());
        }
    }

    for line in unfolded_lines {
        if let Some((attr_key, value)) = line.split_once(':') {
            if attr_key.trim() == key {
                return Ok(Some(value.trim().to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extract_package_names_from_failed_resolution_parses_name_and_version() {
        let message =
            "Unable to resolve: (&(osgi.wiring.package=x.y.z)(version>=1.2.3)); \
             (osgi.wiring.package=a.b.c)";
        let names = OSGiUtils::extract_package_names_from_failed_resolution(message);
        assert_eq!(names, vec!["x.y.z (version>=1.2.3)", "a.b.c"]);
    }

    #[test]
    fn extract_package_names_from_failed_resolution_empty_when_no_match() {
        let names = OSGiUtils::extract_package_names_from_failed_resolution("no packages here");
        assert!(names.is_empty());
    }

    #[test]
    fn get_event_type_string_maps_all_variants() {
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Installed), "INSTALLED");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Resolved), "RESOLVED");
        assert_eq!(
            OSGiUtils::get_event_type_string(BundleEventType::LazyActivation),
            "LAZY_ACTIVATION"
        );
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Starting), "STARTING");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Started), "STARTED");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Stopping), "STOPPING");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Stopped), "STOPPED");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Updated), "UPDATED");
        assert_eq!(OSGiUtils::get_event_type_string(BundleEventType::Unresolved), "UNRESOLVED");
        assert_eq!(
            OSGiUtils::get_event_type_string(BundleEventType::Uninstalled),
            "UNINSTALLED"
        );
    }

    #[test]
    fn get_state_string_maps_all_variants() {
        assert_eq!(OSGiUtils::get_state_string(BundleState::Uninstalled), "UNINSTALLED");
        assert_eq!(OSGiUtils::get_state_string(BundleState::Installed), "INSTALLED");
        assert_eq!(OSGiUtils::get_state_string(BundleState::Resolved), "RESOLVED");
        assert_eq!(OSGiUtils::get_state_string(BundleState::Starting), "STARTING");
        assert_eq!(OSGiUtils::get_state_string(BundleState::Stopping), "STOPPING");
        assert_eq!(OSGiUtils::get_state_string(BundleState::Active), "ACTIVE");
    }

    #[test]
    fn parse_import_package_single_clause() {
        let reqs = OSGiUtils::parse_import_package("org.foo;version=\"1.2.3\"").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].package_name, "org.foo");
        assert_eq!(reqs[0].attributes.get("version").unwrap(), "1.2.3");
    }

    #[test]
    fn parse_import_package_shares_attributes_across_grouped_packages() {
        let reqs = OSGiUtils::parse_import_package("org.foo;org.bar;version=\"1.0\"").unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].package_name, "org.foo");
        assert_eq!(reqs[1].package_name, "org.bar");
        assert_eq!(reqs[0].attributes.get("version").unwrap(), "1.0");
        assert_eq!(reqs[1].attributes.get("version").unwrap(), "1.0");
    }

    #[test]
    fn parse_import_package_multiple_clauses_and_directive() {
        let reqs =
            OSGiUtils::parse_import_package("org.foo;resolution:=optional,org.bar").unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].package_name, "org.foo");
        assert_eq!(reqs[0].attributes.get("resolution").unwrap(), "optional");
        assert_eq!(reqs[1].package_name, "org.bar");
        assert!(reqs[1].attributes.is_empty());
    }

    #[test]
    fn parse_import_package_keeps_commas_inside_quotes_together() {
        let reqs =
            OSGiUtils::parse_import_package("org.foo;uses:=\"org.baz,org.qux\"").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].attributes.get("uses").unwrap(), "org.baz,org.qux");
    }

    #[test]
    fn parse_import_package_rejects_clause_without_package_name() {
        let result = OSGiUtils::parse_import_package("version=\"1.0\"");
        assert!(result.is_err());
    }

    #[test]
    fn parse_export_package_produces_capabilities() {
        let caps = OSGiUtils::parse_export_package("org.foo;version=\"2.0\"").unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].package_name, "org.foo");
        assert_eq!(caps[0].attributes.get("version").unwrap(), "2.0");
    }

    #[test]
    fn bundle_requirement_display_includes_namespace_and_attributes() {
        let req = BundleRequirement {
            package_name: "org.foo".to_string(),
            attributes: BTreeMap::from([("version".to_string(), "1.0".to_string())]),
        };
        assert_eq!(req.to_string(), "osgi.wiring.package=org.foo;version=1.0");
    }

    #[test]
    fn find_jar_for_class_location_extracts_jar_path() {
        let location = "file:/path/to/some.jar!/Some.class";
        assert_eq!(
            OSGiUtils::find_jar_for_class_location(location),
            Some("/path/to/some.jar".to_string())
        );
    }

    #[test]
    fn find_jar_for_class_location_none_when_not_in_jar() {
        assert_eq!(OSGiUtils::find_jar_for_class_location("/plain/path/Some.class"), None);
    }

    #[test]
    fn get_classpath_elements_splits_and_normalizes() {
        let elements = OSGiUtils::get_classpath_elements("/a/b:/a/./c:/a/b/../d");
        assert_eq!(
            elements,
            vec![PathBuf::from("/a/b"), PathBuf::from("/a/c"), PathBuf::from("/a/d")]
        );
    }

    #[test]
    fn get_classpath_elements_skips_empty_entries() {
        let elements = OSGiUtils::get_classpath_elements("/a/b::/a/c:");
        assert_eq!(elements, vec![PathBuf::from("/a/b"), PathBuf::from("/a/c")]);
    }

    #[test]
    fn collect_packages_from_directory_finds_class_file_packages() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_dir = temp_dir.path().join("com").join("example");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("Foo.class"), b"").unwrap();
        std::fs::write(temp_dir.path().join("Root.class"), b"").unwrap();

        let mut packages = HashSet::new();
        OSGiUtils::collect_packages_from_directory(temp_dir.path(), &mut packages);

        assert!(packages.contains("com.example"));
        assert!(packages.contains(""));
    }

    #[test]
    fn get_packages_from_classpath_dispatches_directories_and_jars() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_dir = temp_dir.path().join("com").join("example");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("Foo.class"), b"").unwrap();

        let jar_path = temp_dir.path().join("lib.jar");
        {
            let file = File::create(&jar_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer.start_file("org/bar/Baz.class", opts).unwrap();
            writer.write_all(b"").unwrap();
            writer.finish().unwrap();
        }

        let mut packages = HashSet::new();
        OSGiUtils::get_packages_from_classpath(
            &[temp_dir.path().to_path_buf(), jar_path],
            &mut packages,
        );

        assert!(packages.contains("com.example"));
        assert!(packages.contains("org.bar"));
    }

    #[test]
    fn collect_packages_from_jar_uses_export_package_manifest_attribute() {
        let temp_dir = tempfile::tempdir().unwrap();
        let jar_path = temp_dir.path().join("exported.jar");
        {
            let file = File::create(&jar_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer.start_file("META-INF/MANIFEST.MF", opts).unwrap();
            writer
                .write_all(b"Manifest-Version: 1.0\nExport-Package: org.foo,org.bar\n")
                .unwrap();
            writer.finish().unwrap();
        }

        let mut packages = HashSet::new();
        OSGiUtils::collect_packages_from_jar(&jar_path, &mut packages);

        assert!(packages.contains("org.foo"));
        assert!(packages.contains("org.bar"));
    }

    #[test]
    fn collect_packages_from_jar_falls_back_to_class_entries_without_manifest() {
        let temp_dir = tempfile::tempdir().unwrap();
        let jar_path = temp_dir.path().join("noexport.jar");
        {
            let file = File::create(&jar_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            writer.start_file("org/bar/Baz.class", opts).unwrap();
            writer.write_all(b"").unwrap();
            writer.finish().unwrap();
        }

        let mut packages = HashSet::new();
        OSGiUtils::collect_packages_from_jar(&jar_path, &mut packages);

        assert!(packages.contains("org.bar"));
    }

    #[test]
    fn split_top_level_respects_quotes() {
        let parts = split_top_level("org.foo,org.bar;uses=\"org.baz,org.qux\"", ',');
        assert_eq!(parts, vec!["org.foo", "org.bar;uses=\"org.baz,org.qux\""]);
    }
}
