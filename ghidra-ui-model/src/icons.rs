//! Theme icon lookup seam: the renderer shows images, Rust decides which
//! file a theme icon id (`icon.search`, `icon.plugin.navigation.location.previous`)
//! means. The theme port (`generic::theme`) supplies the real resolver.

use std::path::PathBuf;

/// Resolves theme icon ids to image files.
pub trait IconResolver: Send + Sync {
    /// The image file for `id`, if the theme defines one that exists.
    fn resolve(&self, id: &str) -> Option<PathBuf>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fixed id → path table.
    pub(crate) struct TableResolver(pub HashMap<&'static str, &'static str>);

    impl IconResolver for TableResolver {
        fn resolve(&self, id: &str) -> Option<PathBuf> {
            self.0.get(id).map(PathBuf::from)
        }
    }

    #[test]
    fn a_session_without_a_resolver_has_no_icons() {
        let s = crate::session::UiSession::new();
        assert_eq!(s.icon_path("icon.search"), None);
    }

    #[test]
    fn a_session_resolves_through_its_resolver() {
        let mut s = crate::session::UiSession::new();
        s.set_icon_resolver(Box::new(TableResolver(HashMap::from([("icon.search", "/x/magnifier.png")]))));
        assert_eq!(s.icon_path("icon.search"), Some(PathBuf::from("/x/magnifier.png")));
        assert_eq!(s.icon_path("icon.missing"), None);
    }
}

/// The theme port's resolver behind the seam.
impl IconResolver for ghidra_rs::generic::theme::theme_icon_resolver::ThemeIconResolver {
    fn resolve(&self, id: &str) -> Option<PathBuf> {
        self.resolve_icon_path(id)
    }
}

/// Ghidra's theme files and images: `$GHIDRA_RS_THEME_ROOT`, else the
/// development checkout's `orig_src/Ghidra` (packaging ships them later).
pub fn default_theme_root() -> Option<PathBuf> {
    let root = std::env::var_os("GHIDRA_RS_THEME_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../orig_src/Ghidra")));
    let root = root.canonicalize().ok()?;
    root.is_dir().then_some(root)
}

/// Loads the light theme from [`default_theme_root`], if there is one.
pub fn load_default_theme() -> Option<Box<dyn IconResolver>> {
    use ghidra_rs::generic::theme::theme_icon_resolver::{ThemeIconResolver, ThemeVariant};
    let resolver = ThemeIconResolver::from_ghidra_root(&default_theme_root()?, ThemeVariant::Light).ok()?;
    Some(Box::new(resolver))
}

#[cfg(test)]
mod theme_tests {
    #[test]
    fn the_demo_resolves_ghidra_navigation_icons() {
        let Some(root) = super::default_theme_root() else { return };
        let s = crate::demo_tool::build_demo_session();
        let path = s.icon_path("icon.plugin.navigation.location.previous").expect("resolved");
        assert_eq!(path, root.join("Framework/Gui/src/main/resources/images/left.png"));
        assert!(s.icon_path("icon.search").is_some_and(|p| p.ends_with("images/magnifier.png")));
    }
}
