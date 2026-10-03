//! Port of `ghidra.framework.model.DomainObjectDisplayUtils`.
//!
//! Java's version is a static-only utility class (private constructor, all methods `static`).
//! Following the convention used by sibling static-utility ports in this crate (e.g.
//! [`NamingUtilities`](crate::util::naming_utilities::NamingUtilities),
//! [`MathUtilities`](crate::util::math_utilities::MathUtilities)), it is ported as a unit
//! struct with an `impl` block of associated functions rather than free functions.

use crate::framework::model::domain_file::{DomainFile, DEFAULT_VERSION};
use crate::framework::model::domain_object::DomainObject;
use crate::framework::store::{SEPARATOR, SEPARATOR_CHAR};
use crate::util::StringUtilities;

const VERSION_SEP: &str = "@";
const CHANGE_INDICATOR: &str = "*";
const READ_ONLY: &str = " [Read-Only]";

/// Java: `":" + FileSystem.SEPARATOR + "..." + FileSystem.SEPARATOR`. Hardcoded rather than
/// built from [`SEPARATOR`] via `concat!` (which requires literal arguments, not a path to
/// another module's `const`); [`SEPARATOR`] is `"/"`, matched here.
const PROJECT_SEP_ELLIPSES: &str = ":/.../";

const TOOLTIP_PATH_LENGTH_LIMIT: usize = 100;
const TAB_NAME_LENGTH_LIMIT: usize = 40;

/// Stand-in for a [`DomainFile`] with no real backing, used where Java's `object.getDomainFile()`
/// is documented to never return `null` but this port's [`DomainObject::get_domain_file`]
/// returns `Option` (`None` "if it has never been saved"). Mirrors the crate's own private
/// `ProxyDomainFile` in `domain_file.rs`, which cannot be reused directly since it is not
/// exported from that module.
struct ProxyDomainFile;
impl DomainFile for ProxyDomainFile {}

/// Static utility methods for formatting [`DomainFile`]/[`DomainObject`] names and paths for
/// display (tooltips, editor tab labels).
pub struct DomainObjectDisplayUtils;

impl DomainObjectDisplayUtils {
    /// Returns the `toString()` representation a [`DomainFile`] would have if backed by the
    /// concrete `GhidraFile` implementation — Java's `DomainFile` interface leaves `toString()`
    /// to be overridden per-implementor (`GhidraFile`, `DomainFileProxy`, ...), and this crate's
    /// [`DomainFile`] trait has no such polymorphic hook to dispatch through. `GhidraFile` is the
    /// implementation backing ordinary project files, which is what this display-formatting
    /// utility is written for, so its formula — `projectLocator.getName() + ":" +
    /// getPathname()`, or without the `:` if the project location is transient — is reproduced
    /// directly from the accessors [`DomainFile`] does expose.
    fn path_string(df: &dyn DomainFile) -> String {
        let locator = df.get_project_locator();
        let pathname = df.get_pathname();
        if locator.is_transient() {
            format!("{}{}", locator.get_name(), pathname)
        } else {
            format!("{}:{}", locator.get_name(), pathname)
        }
    }

    /// Splits `s` on `sep`, then drops *all* trailing empty strings.
    ///
    /// Mirrors `String.split(String)`'s default behavior (an implicit `limit` of `0`), which
    /// discards trailing empty strings from the result but keeps leading/interior ones. Rust's
    /// [`str::split`] keeps every empty string, so this reproduces the Java-specific trimming on
    /// top of it.
    fn java_style_split(s: &str, sep: char) -> Vec<&str> {
        let mut parts: Vec<&str> = s.split(sep).collect();
        while parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
        parts
    }

    /// Returns a shortened form of `df`'s path suitable for a tooltip: the full path if it's
    /// under [`TOOLTIP_PATH_LENGTH_LIMIT`] characters (or has at most one path separator), else
    /// `"<project>:/.../<parent-folder>/<filename>"`.
    ///
    /// # Panics
    /// Faithfully reproduces a genuine bug in `DomainObjectDisplayUtils.getShortPath(DomainFile)`
    /// (orig_src `ghidra/framework/model/DomainObjectDisplayUtils.java`, the
    /// `pathParts.length - 2` / `pathParts[parentFolderIndex]` lines): the method guards against
    /// `pathParts.length == 2` (a path with exactly a project-name segment and one more) by
    /// returning early, but does *not* guard against `pathParts.length` being `0` or `1` — a
    /// path string with fewer than one separator. If such a string is also `>=
    /// TOOLTIP_PATH_LENGTH_LIMIT` characters long (e.g. an unusually long project name paired
    /// with an empty path), Java computes a negative `parentFolderIndex` and throws
    /// `ArrayIndexOutOfBoundsException` indexing `pathParts[parentFolderIndex]`. This port
    /// panics in the equivalent situation instead of silently producing a nonsensical result.
    /// See [`tests::get_short_path_panics_on_pathological_input_matching_java_aioobe`].
    pub fn get_short_path(df: &dyn DomainFile) -> String {
        let path_string = Self::path_string(df);
        let length = path_string.chars().count();
        if length < TOOLTIP_PATH_LENGTH_LIMIT {
            return path_string;
        }

        let path_parts = Self::java_style_split(&path_string, SEPARATOR_CHAR);
        if path_parts.len() == 2 {
            // at least 2 for project name and filename
            return path_string;
        }

        let project_name = df.get_project_locator().get_name();
        let parent_folder_index = path_parts.len().checked_sub(2).unwrap_or_else(|| {
            panic!(
                "path {path_string:?} has {} '/'-delimited segment(s); Java throws \
                 ArrayIndexOutOfBoundsException indexing pathParts[pathParts.length - 2] here",
                path_parts.len()
            )
        });
        let parent_name = path_parts[parent_folder_index];
        let filename = df.get_name();
        format!("{project_name}{PROJECT_SEP_ELLIPSES}{parent_name}{SEPARATOR}{filename}")
    }

    /// Returns tooltip text for `object`: its short path (see [`Self::get_short_path`]), with a
    /// `" [Read-Only]"` suffix if its domain file is not in a writable project, and a trailing
    /// `"*"` if the object has unsaved changes.
    pub fn get_tool_tip(object: &dyn DomainObject) -> String {
        let df = object.get_domain_file();
        let df: &dyn DomainFile = match df.as_ref() {
            Some(df) => df.as_ref(),
            None => &ProxyDomainFile,
        };
        let change_indicator = if object.is_changed() { CHANGE_INDICATOR } else { "" };
        let path_string = Self::get_short_path(df);
        if !df.is_in_writable_project() {
            format!("{path_string}{READ_ONLY}{change_indicator}")
        } else {
            format!("{path_string}{change_indicator}")
        }
    }

    /// Returns editor-tab label text for `df`: its name, trimmed to
    /// [`TAB_NAME_LENGTH_LIMIT`] characters, with a `"@<version>"` suffix (when read-only, not
    /// save-able, and not the default/latest version) and a `" [Read-Only]"` suffix (when
    /// read-only).
    ///
    /// Named distinctly from [`Self::get_tab_text_for_object`] since Rust has no method
    /// overloading; Java overloads both as `getTabText`.
    pub fn get_tab_text_for_file(df: &dyn DomainFile) -> String {
        let tab_name = df.get_name();
        let mut trimmed_name = tab_name.trim_middle(TAB_NAME_LENGTH_LIMIT);
        if !df.is_read_only() {
            return trimmed_name;
        }

        let version = df.get_version();
        if !df.can_save() && version != DEFAULT_VERSION {
            trimmed_name.push_str(VERSION_SEP);
            trimmed_name.push_str(&version.to_string());
        }
        trimmed_name.push_str(READ_ONLY);
        trimmed_name
    }

    /// Returns editor-tab label text for `object`: [`Self::get_tab_text_for_file`] for its
    /// domain file, with a leading `"*"` prepended if the object has unsaved changes.
    ///
    /// Named distinctly from [`Self::get_tab_text_for_file`] since Rust has no method
    /// overloading; Java overloads both as `getTabText`.
    pub fn get_tab_text_for_object(object: &dyn DomainObject) -> String {
        let df = object.get_domain_file();
        let df: &dyn DomainFile = match df.as_ref() {
            Some(df) => df.as_ref(),
            None => &ProxyDomainFile,
        };
        if object.is_changed() {
            format!("{CHANGE_INDICATOR}{}", Self::get_tab_text_for_file(df))
        } else {
            Self::get_tab_text_for_file(df)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::project_locator::ProjectLocator;

    struct MockLocator {
        name: &'static str,
        transient: bool,
    }
    impl ProjectLocator for MockLocator {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn is_transient(&self) -> bool {
            self.transient
        }
    }

    #[derive(Default)]
    struct MockFile {
        name: &'static str,
        pathname: &'static str,
        project_name: &'static str,
        transient: bool,
        read_only: bool,
        can_save: bool,
        writable_project: bool,
        version: i32,
    }
    impl DomainFile for MockFile {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_pathname(&self) -> String {
            self.pathname.to_string()
        }
        fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
            Box::new(MockLocator { name: self.project_name, transient: self.transient })
        }
        fn is_read_only(&self) -> bool {
            self.read_only
        }
        fn can_save(&self) -> bool {
            self.can_save
        }
        fn is_in_writable_project(&self) -> bool {
            self.writable_project
        }
        fn get_version(&self) -> i32 {
            self.version
        }
    }

    struct MockObject {
        file: Option<MockFile>,
        changed: bool,
    }
    impl DomainObject for MockObject {
        fn is_changed(&self) -> bool {
            self.changed
        }
        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            self.file.as_ref().map(|f| {
                Box::new(MockFile {
                    name: f.name,
                    pathname: f.pathname,
                    project_name: f.project_name,
                    transient: f.transient,
                    read_only: f.read_only,
                    can_save: f.can_save,
                    writable_project: f.writable_project,
                    version: f.version,
                }) as Box<dyn DomainFile>
            })
        }
    }

    #[test]
    fn get_short_path_returns_full_path_when_under_limit() {
        let df = MockFile {
            name: "program.gzf",
            pathname: "/folder/program.gzf",
            project_name: "MyProject",
            ..Default::default()
        };
        assert_eq!(DomainObjectDisplayUtils::get_short_path(&df), "MyProject:/folder/program.gzf");
    }

    #[test]
    fn get_short_path_returns_full_path_when_only_two_segments() {
        // Long project name, but the path has exactly 2 '/'-delimited segments (project name
        // segment + filename), so the length-100 threshold alone doesn't trigger truncation --
        // the pathParts.length == 2 guard does.
        let long_name = "P".repeat(120);
        let df = MockFile {
            name: "program.gzf",
            pathname: "/program.gzf",
            project_name: Box::leak(long_name.into_boxed_str()),
            ..Default::default()
        };
        let expected = format!("{}:/program.gzf", df.project_name);
        assert_eq!(DomainObjectDisplayUtils::get_short_path(&df), expected);
    }

    #[test]
    fn get_short_path_abbreviates_long_deep_path() {
        let df = MockFile {
            name: "prog.gzf",
            pathname: "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/parent/prog.gzf",
            project_name: "MyProject",
            ..Default::default()
        };
        assert_eq!(
            DomainObjectDisplayUtils::get_short_path(&df),
            "MyProject:/.../parent/prog.gzf"
        );
    }

    /// Reproduces the genuine Java `ArrayIndexOutOfBoundsException` bug documented on
    /// [`DomainObjectDisplayUtils::get_short_path`]: an over-length path string with fewer than
    /// 2 '/'-delimited segments (here: a project name alone, >= 100 characters, no path
    /// separator at all since the domain file's pathname is empty).
    #[test]
    #[should_panic(expected = "ArrayIndexOutOfBoundsException")]
    fn get_short_path_panics_on_pathological_input_matching_java_aioobe() {
        let long_name = "P".repeat(120);
        let df = MockFile {
            name: "x",
            pathname: "", // no leading '/' at all, unlike a real GhidraFile
            project_name: Box::leak(long_name.into_boxed_str()),
            ..Default::default()
        };
        DomainObjectDisplayUtils::get_short_path(&df);
    }

    #[test]
    fn get_tool_tip_marks_read_only_and_changed() {
        let object = MockObject {
            file: Some(MockFile {
                name: "prog.gzf",
                pathname: "/prog.gzf",
                project_name: "Proj",
                writable_project: false,
                ..Default::default()
            }),
            changed: true,
        };
        assert_eq!(
            DomainObjectDisplayUtils::get_tool_tip(&object),
            "Proj:/prog.gzf [Read-Only]*"
        );
    }

    #[test]
    fn get_tool_tip_writable_unchanged_has_no_suffix() {
        let object = MockObject {
            file: Some(MockFile {
                name: "prog.gzf",
                pathname: "/prog.gzf",
                project_name: "Proj",
                writable_project: true,
                ..Default::default()
            }),
            changed: false,
        };
        assert_eq!(DomainObjectDisplayUtils::get_tool_tip(&object), "Proj:/prog.gzf");
    }

    #[test]
    fn get_tool_tip_falls_back_to_proxy_when_object_never_saved() {
        let object = MockObject { file: None, changed: false };
        // ProxyDomainFile's defaults: is_in_writable_project() is false (a proxy is never in a
        // writable project) and the path is empty (project locator name is "" for an unrelated
        // stand-in), so the tooltip is just the read-only marker.
        let tip = DomainObjectDisplayUtils::get_tool_tip(&object);
        assert!(tip.ends_with(READ_ONLY));
    }

    #[test]
    fn get_tab_text_for_file_trims_long_names() {
        let df = MockFile {
            name: "a_very_long_program_name_that_exceeds_the_forty_character_limit.gzf",
            pathname: "/a_very_long_program_name_that_exceeds_the_forty_character_limit.gzf",
            project_name: "Proj",
            ..Default::default()
        };
        let tab_text = DomainObjectDisplayUtils::get_tab_text_for_file(&df);
        assert!(tab_text.len() <= TAB_NAME_LENGTH_LIMIT);
        assert!(tab_text.contains("..."));
    }

    #[test]
    fn get_tab_text_for_file_not_read_only_returns_plain_trimmed_name() {
        let df = MockFile { name: "prog.gzf", read_only: false, ..Default::default() };
        assert_eq!(DomainObjectDisplayUtils::get_tab_text_for_file(&df), "prog.gzf");
    }

    #[test]
    fn get_tab_text_for_file_read_only_uncheckoutable_shows_version() {
        let df = MockFile {
            name: "prog.gzf",
            read_only: true,
            can_save: false,
            version: 5,
            ..Default::default()
        };
        assert_eq!(
            DomainObjectDisplayUtils::get_tab_text_for_file(&df),
            "prog.gzf@5 [Read-Only]"
        );
    }

    #[test]
    fn get_tab_text_for_file_read_only_default_version_omits_version_suffix() {
        let df = MockFile {
            name: "prog.gzf",
            read_only: true,
            can_save: false,
            version: DEFAULT_VERSION,
            ..Default::default()
        };
        assert_eq!(DomainObjectDisplayUtils::get_tab_text_for_file(&df), "prog.gzf [Read-Only]");
    }

    #[test]
    fn get_tab_text_for_file_read_only_but_savable_omits_version_suffix() {
        // can_save() == true means this is a checked-out file, not a specific historical
        // version, so no "@version" suffix even though it's marked read-only.
        let df = MockFile {
            name: "prog.gzf",
            read_only: true,
            can_save: true,
            version: 5,
            ..Default::default()
        };
        assert_eq!(DomainObjectDisplayUtils::get_tab_text_for_file(&df), "prog.gzf [Read-Only]");
    }

    #[test]
    fn get_tab_text_for_object_prepends_change_indicator() {
        let object = MockObject {
            file: Some(MockFile { name: "prog.gzf", ..Default::default() }),
            changed: true,
        };
        assert_eq!(DomainObjectDisplayUtils::get_tab_text_for_object(&object), "*prog.gzf");
    }

    #[test]
    fn get_tab_text_for_object_unchanged_has_no_indicator() {
        let object = MockObject {
            file: Some(MockFile { name: "prog.gzf", ..Default::default() }),
            changed: false,
        };
        assert_eq!(DomainObjectDisplayUtils::get_tab_text_for_object(&object), "prog.gzf");
    }
}
