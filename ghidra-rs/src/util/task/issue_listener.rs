use super::super::issue::Issue;

/// A callback listener for receiving notifications about issues that occur during operations.
///
/// Port of `ghidra.util.task.IssueListener`.
pub trait IssueListener: Send + Sync {
    /// Called when an issue is reported.
    fn issue_reported(&self, issue: &dyn Issue);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestIssue {
        category: String,
        description: String,
    }

    impl Issue for TestIssue {
        fn get_category(&self) -> String {
            self.category.clone()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }

        fn get_primary_location(&self) -> Option<Box<dyn crate::util::seam_stubs::Location>> {
            None
        }

        fn get_secondary_locations(&self) -> Vec<Box<dyn crate::util::seam_stubs::Location>> {
            Vec::new()
        }

        fn get_possible_fixups(&self) -> Vec<Box<dyn crate::util::fixup::Fixup>> {
            Vec::new()
        }
    }

    struct RecordingIssueListener {
        reported: Mutex<Vec<String>>,
    }

    impl IssueListener for RecordingIssueListener {
        fn issue_reported(&self, issue: &dyn Issue) {
            self.reported
                .lock()
                .unwrap()
                .push(issue.get_description());
        }
    }

    #[test]
    fn issue_reported_single() {
        let listener = RecordingIssueListener {
            reported: Mutex::new(Vec::new()),
        };
        let issue = TestIssue {
            category: "test.category".to_string(),
            description: "test issue".to_string(),
        };
        listener.issue_reported(&issue);
        let reported = listener.reported.lock().unwrap();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0], "test issue");
    }

    #[test]
    fn issue_reported_multiple() {
        let listener = RecordingIssueListener {
            reported: Mutex::new(Vec::new()),
        };
        let issue1 = TestIssue {
            category: "category.one".to_string(),
            description: "first issue".to_string(),
        };
        let issue2 = TestIssue {
            category: "category.two".to_string(),
            description: "second issue".to_string(),
        };
        listener.issue_reported(&issue1);
        listener.issue_reported(&issue2);
        let reported = listener.reported.lock().unwrap();
        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0], "first issue");
        assert_eq!(reported[1], "second issue");
    }

    #[test]
    fn as_trait_object() {
        let listener: Box<dyn IssueListener> = Box::new(RecordingIssueListener {
            reported: Mutex::new(Vec::new()),
        });
        let issue = TestIssue {
            category: "category".to_string(),
            description: "trait object test".to_string(),
        };
        listener.issue_reported(&issue);
    }
}
