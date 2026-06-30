/// Trait for icons that are backed by a named file.
///
/// Port of `resources.icons.FileBasedIcon`.
pub trait FileBasedIcon {
    /// Returns the name of the image, which in most cases is the associated file path.
    fn filename(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NamedIcon {
        path: String,
    }

    impl FileBasedIcon for NamedIcon {
        fn filename(&self) -> &str {
            &self.path
        }
    }

    #[test]
    fn filename_returns_path() {
        let icon = NamedIcon { path: "/images/foo.png".to_string() };
        assert_eq!(icon.filename(), "/images/foo.png");
    }

    #[test]
    fn filename_empty_string() {
        let icon = NamedIcon { path: String::new() };
        assert_eq!(icon.filename(), "");
    }

    #[test]
    fn filename_basename_only() {
        let icon = NamedIcon { path: "icon.gif".to_string() };
        assert_eq!(icon.filename(), "icon.gif");
    }
}
