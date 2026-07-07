use crate::util::exception::CancelledException;
use super::CheckinHandler;

/// A simple check-in handler for use with `DomainFile::checkin()`.
///
/// Port of `ghidra.framework.data.DefaultCheckinHandler`.
pub struct DefaultCheckinHandler {
    comment: String,
    keep_checked_out: bool,
    create_keep_file: bool,
}

impl DefaultCheckinHandler {
    /// Creates a new check-in handler with the specified parameters.
    pub fn new(comment: String, keep_checked_out: bool, create_keep_file: bool) -> Self {
        DefaultCheckinHandler {
            comment,
            keep_checked_out,
            create_keep_file,
        }
    }
}

impl CheckinHandler for DefaultCheckinHandler {
    fn get_comment(&self) -> Result<String, CancelledException> {
        Ok(self.comment.clone())
    }

    fn keep_checked_out(&self) -> Result<bool, CancelledException> {
        Ok(self.keep_checked_out)
    }

    fn create_keep_file(&self) -> Result<bool, CancelledException> {
        Ok(self.create_keep_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_handler_with_correct_values() {
        let handler = DefaultCheckinHandler::new(
            "Test comment".to_string(),
            true,
            false,
        );
        assert_eq!(handler.get_comment().unwrap(), "Test comment");
        assert_eq!(handler.keep_checked_out().unwrap(), true);
        assert_eq!(handler.create_keep_file().unwrap(), false);
    }

    #[test]
    fn test_get_comment_returns_stored_comment() {
        let handler = DefaultCheckinHandler::new(
            "Version 2.0".to_string(),
            false,
            false,
        );
        assert_eq!(handler.get_comment().unwrap(), "Version 2.0");
    }

    #[test]
    fn test_get_comment_with_empty_string() {
        let handler = DefaultCheckinHandler::new(
            String::new(),
            false,
            false,
        );
        assert_eq!(handler.get_comment().unwrap(), "");
    }

    #[test]
    fn test_get_comment_with_multiline_text() {
        let comment = "Fixed bug #123\nUpdated documentation\nPerformance improvements";
        let handler = DefaultCheckinHandler::new(
            comment.to_string(),
            false,
            false,
        );
        assert_eq!(handler.get_comment().unwrap(), comment);
    }

    #[test]
    fn test_keep_checked_out_returns_true() {
        let handler = DefaultCheckinHandler::new(
            String::new(),
            true,
            false,
        );
        assert_eq!(handler.keep_checked_out().unwrap(), true);
    }

    #[test]
    fn test_keep_checked_out_returns_false() {
        let handler = DefaultCheckinHandler::new(
            String::new(),
            false,
            false,
        );
        assert_eq!(handler.keep_checked_out().unwrap(), false);
    }

    #[test]
    fn test_create_keep_file_returns_true() {
        let handler = DefaultCheckinHandler::new(
            String::new(),
            false,
            true,
        );
        assert_eq!(handler.create_keep_file().unwrap(), true);
    }

    #[test]
    fn test_create_keep_file_returns_false() {
        let handler = DefaultCheckinHandler::new(
            String::new(),
            false,
            false,
        );
        assert_eq!(handler.create_keep_file().unwrap(), false);
    }

    #[test]
    fn test_all_true_flags() {
        let handler = DefaultCheckinHandler::new(
            "Test".to_string(),
            true,
            true,
        );
        assert_eq!(handler.get_comment().unwrap(), "Test");
        assert_eq!(handler.keep_checked_out().unwrap(), true);
        assert_eq!(handler.create_keep_file().unwrap(), true);
    }

    #[test]
    fn test_all_false_flags() {
        let handler = DefaultCheckinHandler::new(
            "Test".to_string(),
            false,
            false,
        );
        assert_eq!(handler.get_comment().unwrap(), "Test");
        assert_eq!(handler.keep_checked_out().unwrap(), false);
        assert_eq!(handler.create_keep_file().unwrap(), false);
    }

    #[test]
    fn test_multiple_instances_independent() {
        let handler1 = DefaultCheckinHandler::new(
            "Comment 1".to_string(),
            true,
            false,
        );
        let handler2 = DefaultCheckinHandler::new(
            "Comment 2".to_string(),
            false,
            true,
        );

        assert_eq!(handler1.get_comment().unwrap(), "Comment 1");
        assert_eq!(handler1.keep_checked_out().unwrap(), true);
        assert_eq!(handler1.create_keep_file().unwrap(), false);

        assert_eq!(handler2.get_comment().unwrap(), "Comment 2");
        assert_eq!(handler2.keep_checked_out().unwrap(), false);
        assert_eq!(handler2.create_keep_file().unwrap(), true);
    }
}
