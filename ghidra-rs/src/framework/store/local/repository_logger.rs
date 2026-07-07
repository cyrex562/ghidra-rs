/// Callback interface for appending repository log entries.
pub trait RepositoryLogger {
    /// Append a log entry for the given folder or item path.
    ///
    /// * `path` – folder or item path
    /// * `msg` – descriptive message
    /// * `user` – associated user, or `None`
    fn log(&mut self, path: &str, msg: &str, user: Option<&str>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        entries: Vec<(String, String, Option<String>)>,
    }

    impl Recorder {
        fn new() -> Self {
            Self { entries: Vec::new() }
        }
    }

    impl RepositoryLogger for Recorder {
        fn log(&mut self, path: &str, msg: &str, user: Option<&str>) {
            self.entries.push((path.to_owned(), msg.to_owned(), user.map(str::to_owned)));
        }
    }

    #[test]
    fn test_log_with_user() {
        let mut r = Recorder::new();
        r.log("/repo/file", "checked out", Some("alice"));
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0], ("/repo/file".to_owned(), "checked out".to_owned(), Some("alice".to_owned())));
    }

    #[test]
    fn test_log_without_user() {
        let mut r = Recorder::new();
        r.log("/repo/folder", "created", None);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0], ("/repo/folder".to_owned(), "created".to_owned(), None));
    }

    #[test]
    fn test_multiple_entries() {
        let mut r = Recorder::new();
        r.log("/a", "msg1", Some("bob"));
        r.log("/b", "msg2", None);
        r.log("/c", "msg3", Some("carol"));
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.entries[1].2, None);
        assert_eq!(r.entries[2].1, "msg3");
    }
}
