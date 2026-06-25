/// A trait for managing command history in the interpreter.
///
/// This trait provides methods to add commands to history and navigate through them,
/// similar to shell history functionality (up/down arrow navigation).
pub trait HistoryManager {
    /// Adds a command to the history.
    fn add_history(&mut self, command: String);

    /// Retrieves the previous command from history.
    /// Returns `None` if at the beginning of history.
    fn get_history_up(&mut self) -> Option<String>;

    /// Retrieves the next command from history.
    /// Returns `None` if beyond the end of history.
    fn get_history_down(&mut self) -> Option<String>;

    /// Sets the maximum number of history items to retain.
    fn set_retention(&mut self, retention: usize);

    /// Gets the maximum number of history items to retain.
    fn get_retention(&self) -> usize;
}

/// A default implementation of HistoryManager.
pub struct HistoryManagerImpl {
    history: Vec<String>,
    position: usize,
    retention: usize,
}

impl HistoryManagerImpl {
    /// Creates a new history manager with the default retention policy.
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            position: 0,
            retention: usize::MAX,
        }
    }

    /// Creates a new history manager with the specified retention limit.
    pub fn with_retention(retention: usize) -> Self {
        Self {
            history: Vec::new(),
            position: 0,
            retention,
        }
    }
}

impl Default for HistoryManagerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoryManager for HistoryManagerImpl {
    fn add_history(&mut self, mut command: String) {
        // Ignore empty lines (whitespace only)
        if command.trim().is_empty() {
            return;
        }

        // Remove trailing newline if present
        if command.ends_with('\n') {
            command.pop();
        }

        // Apply retention limit by removing oldest entries if necessary
        if self.retention > 0 && self.history.len() >= self.retention {
            self.history.remove(0);
        }

        self.history.push(command);
        self.position = self.history.len();
    }

    fn get_history_up(&mut self) -> Option<String> {
        if self.position > 0 {
            self.position -= 1;
            Some(self.history[self.position].clone())
        } else {
            None
        }
    }

    fn get_history_down(&mut self) -> Option<String> {
        if self.position < self.history.len() - 1 {
            self.position += 1;
            Some(self.history[self.position].clone())
        } else if self.position == self.history.len() - 1 {
            self.position = self.history.len();
            Some(String::new())
        } else {
            None
        }
    }

    fn set_retention(&mut self, retention: usize) {
        self.retention = retention;
        // Trim history if it exceeds the new retention limit
        if self.retention > 0 && self.history.len() > self.retention {
            let remove_count = self.history.len() - self.retention;
            self.history.drain(0..remove_count);
            // Adjust position if necessary
            if self.position >= self.history.len() {
                self.position = self.history.len();
            }
        }
    }

    fn get_retention(&self) -> usize {
        self.retention
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_history() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("command1".to_string());
        manager.add_history("command2".to_string());

        assert_eq!(manager.get_history_up(), Some("command2".to_string()));
    }

    #[test]
    fn test_ignore_empty_lines() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("command1".to_string());
        manager.add_history("   ".to_string());
        manager.add_history("\n".to_string());

        // Only one command should be in history
        assert_eq!(manager.get_history_up(), Some("command1".to_string()));
        assert_eq!(manager.get_history_up(), None);
    }

    #[test]
    fn test_remove_trailing_newline() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("command1\n".to_string());

        let cmd = manager.get_history_up();
        assert_eq!(cmd, Some("command1".to_string()));
    }

    #[test]
    fn test_history_navigation() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("cmd1".to_string());
        manager.add_history("cmd2".to_string());
        manager.add_history("cmd3".to_string());

        // Navigate up
        assert_eq!(manager.get_history_up(), Some("cmd3".to_string()));
        assert_eq!(manager.get_history_up(), Some("cmd2".to_string()));
        assert_eq!(manager.get_history_up(), Some("cmd1".to_string()));
        assert_eq!(manager.get_history_up(), None);

        // Navigate down
        assert_eq!(manager.get_history_down(), Some("cmd2".to_string()));
        assert_eq!(manager.get_history_down(), Some("cmd3".to_string()));
        assert_eq!(manager.get_history_down(), Some(String::new()));
        assert_eq!(manager.get_history_down(), None);
    }

    #[test]
    fn test_get_history_down_at_end() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("cmd1".to_string());

        // Position is at the end after adding
        assert_eq!(manager.get_history_down(), None);
    }

    #[test]
    fn test_retention_limit() {
        let mut manager = HistoryManagerImpl::with_retention(2);
        manager.add_history("cmd1".to_string());
        manager.add_history("cmd2".to_string());
        manager.add_history("cmd3".to_string());

        // Only the last 2 commands should be retained
        assert_eq!(manager.get_history_up(), Some("cmd3".to_string()));
        assert_eq!(manager.get_history_up(), Some("cmd2".to_string()));
        assert_eq!(manager.get_history_up(), None);
    }

    #[test]
    fn test_set_retention() {
        let mut manager = HistoryManagerImpl::new();
        manager.add_history("cmd1".to_string());
        manager.add_history("cmd2".to_string());
        manager.add_history("cmd3".to_string());

        manager.set_retention(2);

        // After setting retention to 2, oldest command should be removed
        assert_eq!(manager.get_history_up(), Some("cmd3".to_string()));
        assert_eq!(manager.get_history_up(), Some("cmd2".to_string()));
        assert_eq!(manager.get_history_up(), None);
    }

    #[test]
    fn test_retention_max() {
        let mut manager = HistoryManagerImpl::new();
        assert_eq!(manager.get_retention(), usize::MAX);

        manager.set_retention(5);
        assert_eq!(manager.get_retention(), 5);
    }

    #[test]
    fn test_default() {
        let manager = HistoryManagerImpl::default();
        assert_eq!(manager.get_retention(), usize::MAX);
    }
}
