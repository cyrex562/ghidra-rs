use crate::framework::model::DomainFile;

/// A context that provides information to actions about domain files that are selected in the tool.
///
/// Stands in for `ghidra.framework.main.datatable.DomainFileContext`.
pub trait DomainFileContext {
    /// The selected files or empty if no files are selected.
    fn get_selected_files(&self) -> Vec<Box<dyn DomainFile>>;

    /// Returns the count of selected files.
    fn get_file_count(&self) -> usize {
        self.get_selected_files().len()
    }

    /// True if the current set of files is in the active project (false implies a non-active,
    /// read-only project).
    fn is_in_active_project(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainFile {
        name: String,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct TestDomainFileContext {
        files: Vec<Box<dyn DomainFile>>,
        is_active: bool,
    }

    impl TestDomainFileContext {
        fn new(files: Vec<Box<dyn DomainFile>>, is_active: bool) -> Self {
            Self { files, is_active }
        }
    }

    impl DomainFileContext for TestDomainFileContext {
        fn get_selected_files(&self) -> Vec<Box<dyn DomainFile>> {
            self.files.iter().map(|f| Box::new(MockDomainFile { name: f.get_name() }) as Box<dyn DomainFile>).collect()
        }

        fn is_in_active_project(&self) -> bool {
            self.is_active
        }
    }

    #[test]
    fn get_file_count_returns_zero_for_empty_selection() {
        let ctx = TestDomainFileContext::new(vec![], true);
        assert_eq!(ctx.get_file_count(), 0);
    }

    #[test]
    fn get_file_count_returns_count_of_selected_files() {
        let files: Vec<Box<dyn DomainFile>> = vec![
            Box::new(MockDomainFile { name: "file1".to_string() }),
            Box::new(MockDomainFile { name: "file2".to_string() }),
            Box::new(MockDomainFile { name: "file3".to_string() }),
        ];
        let ctx = TestDomainFileContext::new(files, true);
        assert_eq!(ctx.get_file_count(), 3);
    }

    #[test]
    fn get_selected_files_returns_empty_when_no_files() {
        let ctx = TestDomainFileContext::new(vec![], true);
        assert_eq!(ctx.get_selected_files().len(), 0);
    }

    #[test]
    fn is_in_active_project_returns_true_when_active() {
        let ctx = TestDomainFileContext::new(vec![], true);
        assert!(ctx.is_in_active_project());
    }

    #[test]
    fn is_in_active_project_returns_false_when_inactive() {
        let ctx = TestDomainFileContext::new(vec![], false);
        assert!(!ctx.is_in_active_project());
    }

    #[test]
    fn get_file_count_with_multiple_files() {
        let files: Vec<Box<dyn DomainFile>> = (0..5)
            .map(|i| Box::new(MockDomainFile { name: format!("file{}", i) }) as Box<dyn DomainFile>)
            .collect();
        let ctx = TestDomainFileContext::new(files, true);
        assert_eq!(ctx.get_file_count(), 5);
    }

    #[test]
    fn active_and_inactive_projects_both_supported() {
        let active_ctx = TestDomainFileContext::new(vec![], true);
        let inactive_ctx = TestDomainFileContext::new(vec![], false);

        assert!(active_ctx.is_in_active_project());
        assert!(!inactive_ctx.is_in_active_project());
    }
}
