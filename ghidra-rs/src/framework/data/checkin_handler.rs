use crate::util::exception::CancelledException;

/// Facilitates application callbacks during the check-in of a DomainFile.
///
/// Port of `ghidra.framework.data.CheckinHandler`.
pub trait CheckinHandler {
    /// Returns the check-in comment.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the user cancels the check-in.
    fn get_comment(&self) -> Result<String, CancelledException>;

    /// Returns true if check-out state should be retained.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the user cancels the check-in.
    fn keep_checked_out(&self) -> Result<bool, CancelledException>;

    /// Returns true if the system should create a keep file copy of the user's check-in file.
    ///
    /// # Errors
    ///
    /// Returns `CancelledException` if the user cancels the check-in.
    fn create_keep_file(&self) -> Result<bool, CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCheckinHandler {
        comment: String,
        keep_checked_out: bool,
        create_keep_file: bool,
        should_cancel: bool,
    }

    impl CheckinHandler for MockCheckinHandler {
        fn get_comment(&self) -> Result<String, CancelledException> {
            if self.should_cancel {
                Err(CancelledException::default())
            } else {
                Ok(self.comment.clone())
            }
        }

        fn keep_checked_out(&self) -> Result<bool, CancelledException> {
            if self.should_cancel {
                Err(CancelledException::default())
            } else {
                Ok(self.keep_checked_out)
            }
        }

        fn create_keep_file(&self) -> Result<bool, CancelledException> {
            if self.should_cancel {
                Err(CancelledException::default())
            } else {
                Ok(self.create_keep_file)
            }
        }
    }

    #[test]
    fn get_comment_returns_comment() {
        let handler = MockCheckinHandler {
            comment: "Test comment".to_string(),
            keep_checked_out: false,
            create_keep_file: false,
            should_cancel: false,
        };

        let result = handler.get_comment();
        assert_eq!(result.unwrap(), "Test comment");
    }

    #[test]
    fn get_comment_throws_cancelled_exception_when_cancelled() {
        let handler = MockCheckinHandler {
            comment: "Test comment".to_string(),
            keep_checked_out: false,
            create_keep_file: false,
            should_cancel: true,
        };

        let result = handler.get_comment();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CancelledException(_)));
    }

    #[test]
    fn keep_checked_out_returns_true() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: true,
            create_keep_file: false,
            should_cancel: false,
        };

        let result = handler.keep_checked_out();
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn keep_checked_out_returns_false() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: false,
            create_keep_file: true,
            should_cancel: false,
        };

        let result = handler.keep_checked_out();
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn keep_checked_out_throws_cancelled_exception_when_cancelled() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: false,
            create_keep_file: false,
            should_cancel: true,
        };

        let result = handler.keep_checked_out();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CancelledException(_)));
    }

    #[test]
    fn create_keep_file_returns_true() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: false,
            create_keep_file: true,
            should_cancel: false,
        };

        let result = handler.create_keep_file();
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn create_keep_file_returns_false() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: false,
            create_keep_file: false,
            should_cancel: false,
        };

        let result = handler.create_keep_file();
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn create_keep_file_throws_cancelled_exception_when_cancelled() {
        let handler = MockCheckinHandler {
            comment: String::new(),
            keep_checked_out: false,
            create_keep_file: false,
            should_cancel: true,
        };

        let result = handler.create_keep_file();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CancelledException(_)));
    }

    #[test]
    fn all_methods_work_together() {
        let handler = MockCheckinHandler {
            comment: "Version 2.0".to_string(),
            keep_checked_out: true,
            create_keep_file: true,
            should_cancel: false,
        };

        assert_eq!(handler.get_comment().unwrap(), "Version 2.0");
        assert_eq!(handler.keep_checked_out().unwrap(), true);
        assert_eq!(handler.create_keep_file().unwrap(), true);
    }
}
