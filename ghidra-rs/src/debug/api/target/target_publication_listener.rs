use crate::app::seam_stubs::Target;

/// A listener for changes to the set of published targets.
///
/// Mirrors `ghidra.debug.api.target.TargetPublicationListener`.
pub trait TargetPublicationListener: Send + Sync {
    /// The given target was published.
    ///
    /// Mirrors `TargetPublicationListener.targetPublished(Target)`.
    fn target_published(&self, target: &dyn Target);

    /// The given target was withdrawn, usually because it's no longer valid.
    ///
    /// Mirrors `TargetPublicationListener.targetWithdrawn(Target)`.
    fn target_withdrawn(&self, target: &dyn Target);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListener {
        published_targets: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        withdrawn_targets: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl TargetPublicationListener for MockListener {
        fn target_published(&self, target: &dyn Target) {
            let snap = target.get_snap();
            self.published_targets.lock().unwrap().push(format!("published: snap={}", snap));
        }

        fn target_withdrawn(&self, target: &dyn Target) {
            let snap = target.get_snap();
            self.withdrawn_targets.lock().unwrap().push(format!("withdrawn: snap={}", snap));
        }
    }

    struct MockTarget {
        snap: i64,
    }

    impl Target for MockTarget {
        fn is_valid(&self) -> bool {
            true
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    #[test]
    fn test_target_published_event() {
        let published = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let withdrawn = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let listener = MockListener {
            published_targets: published.clone(),
            withdrawn_targets: withdrawn.clone(),
        };

        let target = MockTarget { snap: 42 };
        listener.target_published(&target);

        assert_eq!(published.lock().unwrap().len(), 1);
        assert_eq!(published.lock().unwrap()[0], "published: snap=42");
        assert_eq!(withdrawn.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_target_withdrawn_event() {
        let published = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let withdrawn = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let listener = MockListener {
            published_targets: published.clone(),
            withdrawn_targets: withdrawn.clone(),
        };

        let target = MockTarget { snap: 42 };
        listener.target_withdrawn(&target);

        assert_eq!(withdrawn.lock().unwrap().len(), 1);
        assert_eq!(withdrawn.lock().unwrap()[0], "withdrawn: snap=42");
        assert_eq!(published.lock().unwrap().len(), 0);
    }
}
