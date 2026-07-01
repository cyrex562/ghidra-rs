pub trait JarEntry: Send + Sync {
    fn name(&self) -> &str;
    fn is_directory(&self) -> bool;
}

pub trait JarEntryFilter: Send + Sync {
    fn accepts(&self, jar_entry: &dyn JarEntry) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockJarEntry {
        name: String,
        is_dir: bool,
    }

    impl MockJarEntry {
        fn new(name: &str, is_dir: bool) -> Self {
            Self {
                name: name.to_string(),
                is_dir,
            }
        }
    }

    impl JarEntry for MockJarEntry {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_directory(&self) -> bool {
            self.is_dir
        }
    }

    struct TestFilter;

    impl JarEntryFilter for TestFilter {
        fn accepts(&self, jar_entry: &dyn JarEntry) -> bool {
            let name = jar_entry.name();
            !name.ends_with(".class") && !name.ends_with(".png") && !name.ends_with(".gif")
        }
    }

    #[test]
    fn test_accepts_regular_file() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("data.txt", false);
        assert!(filter.accepts(&entry));
    }

    #[test]
    fn test_rejects_class_file() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("Main.class", false);
        assert!(!filter.accepts(&entry));
    }

    #[test]
    fn test_rejects_png_file() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("image.png", false);
        assert!(!filter.accepts(&entry));
    }

    #[test]
    fn test_rejects_gif_file() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("animation.gif", false);
        assert!(!filter.accepts(&entry));
    }

    #[test]
    fn test_accepts_directory() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("folder/", true);
        assert!(filter.accepts(&entry));
    }

    #[test]
    fn test_multiple_extensions() {
        let filter = TestFilter;
        let entry = MockJarEntry::new("image.png.backup", false);
        assert!(filter.accepts(&entry));
    }
}
