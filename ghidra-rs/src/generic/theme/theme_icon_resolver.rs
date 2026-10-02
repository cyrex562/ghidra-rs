//! Toolkit-neutral answer to "which image file does theme icon id X resolve to?".
//!
//! Loads a set of `*.theme.properties` files the way Java's `PropertyFileThemeDefaults`
//! does (each file's sections merged in order, later files winning), selects the light or
//! dark values the way a theme does (defaults, then dark defaults on top for a dark
//! theme), follows icon references, and locates the base image with
//! [`IconResourceLocator`]. Modifiers (`[size(..)]`, overlays, ...) are returned for the
//! renderer to apply.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::g_theme_value_map::GThemeValueMap;
use super::icon_resource_locator::{
    discover_resource_roots, discover_theme_property_files, IconResourceLocator,
};
use super::icon_value::{IconSpec, ResolvedIcon};
use super::theme_property_file_reader::ThemePropertyFileReader;
use super::theme_value::UnresolvedReference;

/// Which default values a theme uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThemeVariant {
    /// `[Defaults]` only.
    Light,
    /// `[Defaults]` overlaid with `[Dark Defaults]`.
    Dark,
}

/// Why an icon id could not be resolved to a file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IconResolveError {
    /// No icon value has this id.
    #[error("no icon theme value with id \"{0}\"")]
    UnknownId(String),
    /// The id's reference chain is broken or loops (Java would use `images/core.png`).
    #[error(transparent)]
    Unresolved(#[from] UnresolvedReference),
    /// The chain ends in an image resource that no resource root contains.
    #[error("icon \"{id}\" names resource \"{resource}\", which was not found")]
    ResourceNotFound {
        /// The requested icon id.
        id: String,
        /// The image resource name from the theme file.
        resource: String,
    },
}

/// A resolved icon: its base image file and the modifiers to apply to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIconFile {
    /// The resolved icon (base spec plus modifiers, in application order).
    pub icon: ResolvedIcon,
    /// The base image file; `None` for `EMPTY_ICON`.
    pub path: Option<PathBuf>,
}

/// Theme icon values loaded from property files, with a locator for their images.
#[derive(Debug, Clone)]
pub struct ThemeIconResolver {
    values: GThemeValueMap,
    locator: IconResourceLocator,
    errors: Vec<String>,
}

impl ThemeIconResolver {
    /// Reads `theme_files` in order (later files win) and keeps the values of `variant`.
    /// Parse problems are collected in [`errors`](Self::errors); unreadable files are
    /// I/O errors.
    pub fn load(
        theme_files: &[PathBuf],
        locator: IconResourceLocator,
        variant: ThemeVariant,
    ) -> io::Result<Self> {
        let mut defaults = GThemeValueMap::new();
        let mut dark_defaults = GThemeValueMap::new();
        let mut errors = Vec::new();
        for file in theme_files {
            let reader = ThemePropertyFileReader::from_path(file)?;
            defaults.load(reader.default_values());
            dark_defaults.load(reader.dark_default_values());
            errors.extend_from_slice(reader.errors());
        }
        if variant == ThemeVariant::Dark {
            defaults.load(&dark_defaults);
        }
        Ok(Self {
            values: defaults,
            locator,
            errors,
        })
    }

    /// Discovers every `data/*.theme.properties` file and every `src/main/resources`
    /// root under `root` (e.g. a Ghidra source tree) and loads them.
    pub fn from_ghidra_root(root: &Path, variant: ThemeVariant) -> io::Result<Self> {
        let files = discover_theme_property_files(root);
        let locator = IconResourceLocator::new(discover_resource_roots(root));
        Self::load(&files, locator, variant)
    }

    /// The merged theme values.
    pub fn values(&self) -> &GThemeValueMap {
        &self.values
    }

    /// The locator used for image files.
    pub fn locator(&self) -> &IconResourceLocator {
        &self.locator
    }

    /// Parse errors from all files read.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Resolves icon `id` through references to its base image file and modifiers.
    pub fn resolve_icon(&self, id: &str) -> Result<ResolvedIconFile, IconResolveError> {
        let value = self
            .values
            .get_icon(id)
            .ok_or_else(|| IconResolveError::UnknownId(id.to_string()))?;
        let icon = value.get(&self.values)?;
        let path = match &icon.base {
            IconSpec::Empty { .. } => None,
            IconSpec::Resource(resource) => {
                Some(self.locator.locate(resource).ok_or_else(|| {
                    IconResolveError::ResourceNotFound {
                        id: id.to_string(),
                        resource: resource.clone(),
                    }
                })?)
            }
        };
        Ok(ResolvedIconFile { icon, path })
    }

    /// The image file icon `id` resolves to, or `None` if it can't be resolved or has no
    /// file (`EMPTY_ICON`).
    pub fn resolve_icon_path(&self, id: &str) -> Option<PathBuf> {
        self.resolve_icon(id).ok().and_then(|r| r.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::theme::icon_value::IconValue;
    use std::fs;
    use std::path::PathBuf;

    fn touch(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn orig_src() -> Option<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../orig_src");
        let probe = root.join("Ghidra/Framework/Gui/data/gui.theme.properties");
        if probe.exists() {
            Some(root)
        } else {
            eprintln!("skipping: {} not present", probe.display());
            None
        }
    }

    #[test]
    fn later_files_win_and_references_cross_files() {
        let dir = tempfile::tempdir().unwrap();
        let res = dir.path().join("mod/src/main/resources");
        touch(&res.join("images/left.png"), "png");
        touch(&res.join("images/right.png"), "png");
        let gui = dir.path().join("gui/data/gui.theme.properties");
        touch(&gui, "[Defaults]\nicon.left = left.png\nicon.right = right.png\n[Dark Defaults]\nicon.left = right.png\n");
        let base = dir.path().join("base/data/base.theme.properties");
        touch(&base, "[Defaults]\nicon.prev = icon.left\nicon.right = left.png\nicon.gone = gone.png\nicon.empty = EMPTY_ICON\n");
        let locator = IconResourceLocator::new(vec![res.clone()]);
        let light = ThemeIconResolver::load(
            &[gui.clone(), base.clone()],
            locator.clone(),
            ThemeVariant::Light,
        )
        .unwrap();
        assert!(light.errors().is_empty(), "{:?}", light.errors());
        assert_eq!(
            light.resolve_icon_path("icon.prev"),
            Some(res.join("images/left.png"))
        );
        assert_eq!(
            light.resolve_icon_path("icon.right"),
            Some(res.join("images/left.png"))
        );
        let dark = ThemeIconResolver::load(&[gui, base], locator, ThemeVariant::Dark).unwrap();
        assert_eq!(
            dark.resolve_icon_path("icon.prev"),
            Some(res.join("images/right.png"))
        );

        assert_eq!(
            light.resolve_icon("icon.nope").unwrap_err(),
            IconResolveError::UnknownId("icon.nope".into())
        );
        assert_eq!(
            light.resolve_icon("icon.gone").unwrap_err(),
            IconResolveError::ResourceNotFound {
                id: "icon.gone".into(),
                resource: "gone.png".into()
            }
        );
        let empty = light.resolve_icon("icon.empty").unwrap();
        assert_eq!(empty.path, None);
        assert_eq!(
            empty.icon.base,
            IconSpec::Empty {
                width: 16,
                height: 16
            }
        );
        assert_eq!(light.resolve_icon_path("icon.empty"), None);
    }

    #[test]
    fn unresolvable_reference_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x/data/x.theme.properties");
        touch(&file, "[Defaults]\nicon.a = icon.b\n");
        let r = ThemeIconResolver::load(
            &[file],
            IconResourceLocator::new(Vec::new()),
            ThemeVariant::Light,
        )
        .unwrap();
        assert!(matches!(
            r.resolve_icon("icon.a"),
            Err(IconResolveError::Unresolved(_))
        ));
    }

    #[test]
    fn real_ghidra_icons_resolve_to_files() {
        let Some(root) = orig_src() else { return };
        let resolver = ThemeIconResolver::from_ghidra_root(&root, ThemeVariant::Light).unwrap();
        let left = root.join("Ghidra/Framework/Gui/src/main/resources/images/left.png");
        assert_eq!(resolver.resolve_icon_path("icon.left"), Some(left.clone()));
        assert_eq!(
            resolver.resolve_icon_path("icon.plugin.navigation.location.previous"),
            Some(left)
        );
        assert_eq!(
            resolver.resolve_icon_path("icon.search"),
            Some(root.join("Ghidra/Framework/Docking/src/main/resources/images/magnifier.png"))
        );
    }

    #[test]
    fn real_ghidra_theme_files_parse_and_references_resolve() {
        let Some(root) = orig_src() else { return };
        let resolver = ThemeIconResolver::from_ghidra_root(&root, ThemeVariant::Light).unwrap();
        assert!(resolver.errors().is_empty(), "{:#?}", resolver.errors());
        assert!(resolver.values().icon_ids().count() > 100);
        let unresolved: Vec<_> = resolver
            .values()
            .icons()
            .filter_map(|v| v.get(resolver.values()).err())
            // laf.* ids are supplied by the Java look and feel at runtime, not by files
            .filter(|e| !e.unresolved_id.starts_with(IconValue::LAF_ID_PREFIX))
            .collect();
        assert!(unresolved.is_empty(), "{unresolved:#?}");
    }
}
