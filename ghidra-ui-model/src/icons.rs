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
