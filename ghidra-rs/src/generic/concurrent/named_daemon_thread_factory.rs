/// A thread factory configuration that creates daemon threads with a specified name prefix.
///
/// In Rust, daemon threads don't have a direct equivalent, but this type captures the
/// naming pattern from the Java version: threads are named with the format "prefix-defaultname".
pub struct NamedDaemonThreadFactory {
    name: String,
}

impl NamedDaemonThreadFactory {
    /// Creates a new named daemon thread factory with the given name prefix.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
        }
    }

    /// Returns the name prefix for this factory.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Formats a thread name by prepending the name prefix.
    ///
    /// Given a default thread name, returns the formatted name with the prefix.
    /// Pattern: "prefix-defaultname"
    pub fn format_thread_name(&self, default_name: &str) -> String {
        format!("{}-{}", self.name, default_name)
    }

    /// Formats a thread name with an index, useful for thread pools.
    ///
    /// Pattern: "prefix-index"
    pub fn format_thread_name_with_index(&self, index: usize) -> String {
        format!("{}-{}", self.name, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let factory = NamedDaemonThreadFactory::new("worker");
        assert_eq!(factory.name(), "worker");
    }

    #[test]
    fn test_format_thread_name() {
        let factory = NamedDaemonThreadFactory::new("pool");
        let formatted = factory.format_thread_name("thread-1");
        assert_eq!(formatted, "pool-thread-1");
    }

    #[test]
    fn test_format_thread_name_with_index() {
        let factory = NamedDaemonThreadFactory::new("executor");
        let formatted = factory.format_thread_name_with_index(5);
        assert_eq!(formatted, "executor-5");
    }

    #[test]
    fn test_name_with_different_prefixes() {
        let factory1 = NamedDaemonThreadFactory::new("bg");
        let factory2 = NamedDaemonThreadFactory::new("io");
        let factory3 = NamedDaemonThreadFactory::new("network");

        assert_eq!(factory1.name(), "bg");
        assert_eq!(factory2.name(), "io");
        assert_eq!(factory3.name(), "network");
    }

    #[test]
    fn test_format_preserves_default_name() {
        let factory = NamedDaemonThreadFactory::new("worker");
        let default = "thread-0";
        let formatted = factory.format_thread_name(default);

        assert!(formatted.contains("worker"));
        assert!(formatted.contains("thread-0"));
        assert_eq!(formatted, "worker-thread-0");
    }

    #[test]
    fn test_into_string() {
        let factory = NamedDaemonThreadFactory::new("test");
        let factory2 = NamedDaemonThreadFactory::new(String::from("test"));

        assert_eq!(factory.name(), factory2.name());
    }
}
