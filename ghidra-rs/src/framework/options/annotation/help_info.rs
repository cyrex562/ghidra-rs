/// Metadata for a help topic reference, mirroring Java's `@HelpInfo` runtime annotation.
///
/// In Java this annotation is placed on classes or fields so that the options
/// framework can associate UI elements with specific help topics and anchors.
/// In Rust, where there is no reflective annotation system, the same metadata
/// is carried in this struct.
///
/// Both fields default to empty/absent, matching the Java defaults
/// (`topic = {}` and `anchor = ""`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HelpInfo {
    /// Help topic path components (Java: `topic = {"Topic", "SubTopic"}`).
    pub topic: Vec<String>,
    /// In-page anchor within the help topic (Java: `anchor = "my-anchor"`).
    pub anchor: String,
}

impl HelpInfo {
    /// Creates a `HelpInfo` with no topic and no anchor (matches the Java defaults).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a `HelpInfo` with a topic and no anchor.
    pub fn with_topic(topic: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            topic: topic.into_iter().map(Into::into).collect(),
            anchor: String::new(),
        }
    }

    /// Creates a `HelpInfo` with both a topic and an anchor.
    pub fn with_topic_and_anchor(
        topic: impl IntoIterator<Item = impl Into<String>>,
        anchor: impl Into<String>,
    ) -> Self {
        Self {
            topic: topic.into_iter().map(Into::into).collect(),
            anchor: anchor.into(),
        }
    }

    /// Returns `true` when no topic was specified (the default).
    pub fn has_topic(&self) -> bool {
        !self.topic.is_empty()
    }

    /// Returns `true` when an anchor was specified (non-empty).
    pub fn has_anchor(&self) -> bool {
        !self.anchor.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_empty_topic_and_anchor() {
        let h = HelpInfo::new();
        assert!(h.topic.is_empty());
        assert!(h.anchor.is_empty());
        assert!(!h.has_topic());
        assert!(!h.has_anchor());
    }

    #[test]
    fn with_topic_stores_topic_and_empty_anchor() {
        let h = HelpInfo::with_topic(["MyTopic"]);
        assert_eq!(h.topic, vec!["MyTopic"]);
        assert!(h.anchor.is_empty());
        assert!(h.has_topic());
        assert!(!h.has_anchor());
    }

    #[test]
    fn with_topic_multiple_segments() {
        let h = HelpInfo::with_topic(["Parent", "Child"]);
        assert_eq!(h.topic, vec!["Parent", "Child"]);
    }

    #[test]
    fn with_empty_topic_has_no_topic() {
        let h = HelpInfo::with_topic([] as [&str; 0]);
        assert!(h.topic.is_empty());
        assert!(!h.has_topic());
    }

    #[test]
    fn with_topic_and_anchor_stores_both() {
        let h = HelpInfo::with_topic_and_anchor(["Debug"], "section-1");
        assert_eq!(h.topic, vec!["Debug"]);
        assert_eq!(h.anchor, "section-1");
        assert!(h.has_topic());
        assert!(h.has_anchor());
    }

    #[test]
    fn equality_holds_for_identical_instances() {
        let a = HelpInfo::with_topic_and_anchor(["T"], "a");
        let b = HelpInfo::with_topic_and_anchor(["T"], "a");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_when_topics_differ() {
        let a = HelpInfo::with_topic(["A"]);
        let b = HelpInfo::with_topic(["B"]);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_when_anchors_differ() {
        let a = HelpInfo::with_topic_and_anchor(["T"], "anchor-a");
        let b = HelpInfo::with_topic_and_anchor(["T"], "anchor-b");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let h = HelpInfo::with_topic_and_anchor(["Topic"], "anch");
        assert_eq!(h.clone(), h);
    }

    #[test]
    fn debug_contains_topic() {
        let h = HelpInfo::with_topic(["DebugTopic"]);
        let s = format!("{h:?}");
        assert!(s.contains("DebugTopic"));
    }

    #[test]
    fn default_trait_matches_new() {
        assert_eq!(HelpInfo::default(), HelpInfo::new());
    }
}
