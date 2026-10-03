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

/// Ghidra's theme files and icons (vendored by `scripts/vendor_ghidra_theme.py`,
/// licences in `ICON_LICENSES.tsv`): `$GHIDRA_RS_THEME_ROOT`, else a
/// packaged `ghidra-theme` directory beside the executable, else this crate's
/// `resources/ghidra-theme`.
pub fn default_theme_root() -> Option<PathBuf> {
    let packaged = std::env::current_exe().ok().and_then(|e| Some(e.parent()?.join("ghidra-theme")));
    let candidates = [
        std::env::var_os("GHIDRA_RS_THEME_ROOT").map(PathBuf::from),
        packaged,
        Some(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/resources/ghidra-theme"))),
    ];
    candidates.into_iter().flatten().filter_map(|p| p.canonicalize().ok()).find(|p| p.is_dir())
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
    fn the_default_theme_is_the_vendored_copy() {
        if std::env::var_os("GHIDRA_RS_THEME_ROOT").is_some() {
            return;
        }
        let vendored = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/ghidra-theme").canonicalize().unwrap();
        assert_eq!(super::default_theme_root(), Some(vendored));
    }

    #[test]
    fn every_vendored_theme_icon_resolves_to_a_vendored_file() {
        use ghidra_rs::generic::theme::theme_icon_resolver::{ThemeIconResolver, ThemeVariant};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/ghidra-theme");
        let r = ThemeIconResolver::from_ghidra_root(&root, ThemeVariant::Light).unwrap();
        let ids: Vec<String> = r.values().icon_ids().cloned().collect();
        assert!(ids.len() > 400, "{}", ids.len());
        let bad: Vec<String> = ids
            .iter()
            .filter(|id| !id.starts_with("laf."))
            .filter(|id| matches!(r.resolve_icon(id), Err(ghidra_rs::generic::theme::theme_icon_resolver::IconResolveError::ResourceNotFound { .. })))
            .cloned()
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    /// Every licence named in ICON_LICENSES.tsv ships the texts it requires:
    /// LGPL 2.1 the full LGPL 2.1, LGPL 3.0 the LGPL 3.0 and GPL 3 texts,
    /// modified LGPL icons their sources, CC BY 2.5 the licence + attribution.
    #[test]
    fn vendored_icons_carry_the_licence_texts_they_require() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/ghidra-theme");
        let tsv = std::fs::read_to_string(root.join("ICON_LICENSES.tsv")).unwrap();
        let lic = root.join("licenses");
        let need = |f: &str| assert!(lic.join(f).is_file(), "missing licences/{f}");
        let mut seen = std::collections::BTreeSet::new();
        for line in tsv.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(cols.len(), 3, "{line}");
            assert!(root.join(cols[0]).is_file(), "{}", cols[0]);
            assert!(!cols[2].contains('|') && !cols[2].contains("END"), "manifest junk in note: {line}");
            seen.insert(cols[1].to_owned());
        }
        for l in &seen {
            match l.as_str() {
                "GHIDRA" => {
                    need("GHIDRA_LICENSE");
                    need("GHIDRA_NOTICE");
                }
                "FAMFAMFAM Icons - CC 2.5" => {
                    need("FAMFAMFAM_Icons_-_CC_2.5.txt");
                    need("Creative_Commons_Attribution_2.5.html");
                }
                l if l.ends_with("LGPL 2.1") => need("LGPL_2.1.txt"),
                l if l.ends_with("LGPL 3.0") => {
                    need("LGPL_3.0.html");
                    need("GPL_3.html");
                }
                "MIT" => need("MIT.txt"),
                l if l.ends_with("Public Domain") => need(&format!("{}.txt", l.replace(' ', "_"))),
                other => panic!("unhandled licence {other}"),
            }
        }
        if seen.contains("Modified Nuvola Icons - LGPL 2.1") {
            let src = root.join("GPL/Icons/ModifiedNuvola");
            let svgs = std::fs::read_dir(&src).map(|d| d.filter(|e| e.as_ref().is_ok_and(|e| e.path().extension().is_some_and(|x| x == "svg"))).count()).unwrap_or(0);
            assert!(svgs >= 27, "modified LGPL icons need their sources: {svgs} svgs in {}", src.display());
        }
        let version = std::fs::read_to_string(root.join("SOURCE_VERSION")).unwrap();
        assert!(version.starts_with("Ghidra "), "{version}");
    }

    #[test]
    fn the_demo_resolves_ghidra_navigation_icons() {
        let Some(root) = super::default_theme_root() else { return };
        let s = crate::demo_tool::build_demo_session();
        let path = s.icon_path("icon.plugin.navigation.location.previous").expect("resolved");
        assert_eq!(path, root.join("Framework/Gui/src/main/resources/images/left.png"));
        assert!(s.icon_path("icon.search").is_some_and(|p| p.ends_with("images/magnifier.png")));
    }
}
