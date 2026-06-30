use super::ClassFileInfo;

/// Trait for filtering classes during class discovery.
///
/// Port of `ghidra.util.classfinder.ClassFilter`.
pub trait ClassFilter {
    /// Returns `true` if the given class should be accepted.
    fn accepts(&self, class_info: &ClassFileInfo) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::classfinder::ClassFileInfo;

    struct AcceptAll;

    impl ClassFilter for AcceptAll {
        fn accepts(&self, _class_info: &ClassFileInfo) -> bool {
            true
        }
    }

    struct RejectAll;

    impl ClassFilter for RejectAll {
        fn accepts(&self, _class_info: &ClassFileInfo) -> bool {
            false
        }
    }

    struct AcceptBySuffix {
        suffix: String,
    }

    impl ClassFilter for AcceptBySuffix {
        fn accepts(&self, class_info: &ClassFileInfo) -> bool {
            class_info.suffix == self.suffix
        }
    }

    fn make_info(suffix: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/path/to/class".to_string(),
            "com.example.MyClass".to_string(),
            suffix.to_string(),
            "module".to_string(),
        )
    }

    #[test]
    fn accept_all_accepts_any_class() {
        let filter = AcceptAll;
        assert!(filter.accepts(&make_info("Any")));
    }

    #[test]
    fn reject_all_rejects_any_class() {
        let filter = RejectAll;
        assert!(!filter.accepts(&make_info("Any")));
    }

    #[test]
    fn accept_by_suffix_matches() {
        let filter = AcceptBySuffix { suffix: "Plugin".to_string() };
        assert!(filter.accepts(&make_info("Plugin")));
    }

    #[test]
    fn accept_by_suffix_rejects_other() {
        let filter = AcceptBySuffix { suffix: "Plugin".to_string() };
        assert!(!filter.accepts(&make_info("Analyzer")));
    }

    #[test]
    fn accept_by_suffix_empty_suffix() {
        let filter = AcceptBySuffix { suffix: String::new() };
        assert!(filter.accepts(&make_info("")));
        assert!(!filter.accepts(&make_info("Something")));
    }
}
