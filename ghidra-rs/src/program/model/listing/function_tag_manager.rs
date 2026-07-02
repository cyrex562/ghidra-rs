use super::FunctionTag;

/// Interface for managing function tags. Tags are simple objects consisting of a name and an
/// optional comment, which can be applied to functions.
///
/// See `FunctionTagAdapter` and `FunctionTagMappingAdapter` in the Java source.
pub trait FunctionTagManager {
    /// Returns the function tag with the given name.
    ///
    /// # Arguments
    /// * `name` - the tag name
    ///
    /// # Returns
    /// The function tag, or `None` if not found.
    fn get_function_tag_by_name(&self, name: &str) -> Option<&dyn FunctionTag>;

    /// Returns the function tag with the given database id.
    ///
    /// # Arguments
    /// * `id` - the tag's database id
    ///
    /// # Returns
    /// The function tag, or `None` if not found.
    fn get_function_tag_by_id(&self, id: i64) -> Option<&dyn FunctionTag>;

    /// Returns all function tags in the database.
    fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag>;

    /// Returns `true` if the given tag is assigned to a function.
    ///
    /// # Arguments
    /// * `name` - the tag name
    fn is_tag_assigned(&self, name: &str) -> bool;

    /// Creates a new function tag with the given attributes if one does not already exist.
    /// Otherwise, returns the existing tag.
    ///
    /// # Arguments
    /// * `name` - the tag name
    /// * `comment` - the comment associated with the tag (optional)
    fn create_function_tag(&mut self, name: &str, comment: &str) -> &dyn FunctionTag;

    /// Returns the number of times the given tag has been applied to a function.
    fn get_use_count(&self, tag: &dyn FunctionTag) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockTag {
        id: i64,
        name: String,
        comment: String,
    }

    impl MockTag {
        fn new(id: i64, name: &str, comment: &str) -> Self {
            Self {
                id,
                name: name.to_string(),
                comment: comment.to_string(),
            }
        }
    }

    impl FunctionTag for MockTag {
        fn id(&self) -> i64 {
            self.id
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn comment(&self) -> &str {
            &self.comment
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn set_comment(&mut self, comment: &str) {
            self.comment = comment.to_string();
        }

        fn delete(&mut self) {}

        fn compare_to(&self, other: &dyn FunctionTag) -> std::cmp::Ordering {
            self.name.as_str().cmp(other.name())
        }
    }

    struct MockTagManager {
        tags: HashMap<String, Box<MockTag>>,
        next_id: i64,
        assignments: HashMap<String, usize>,
    }

    impl MockTagManager {
        fn new() -> Self {
            Self {
                tags: HashMap::new(),
                next_id: 1,
                assignments: HashMap::new(),
            }
        }

        fn add_tag(&mut self, name: &str, comment: &str) {
            let tag = MockTag::new(self.next_id, name, comment);
            self.next_id += 1;
            self.tags.insert(name.to_string(), Box::new(tag));
        }

        fn mark_assigned(&mut self, name: &str, count: usize) {
            self.assignments.insert(name.to_string(), count);
        }
    }

    impl FunctionTagManager for MockTagManager {
        fn get_function_tag_by_name(&self, name: &str) -> Option<&dyn FunctionTag> {
            self.tags.get(name).map(|tag| tag.as_ref() as &dyn FunctionTag)
        }

        fn get_function_tag_by_id(&self, id: i64) -> Option<&dyn FunctionTag> {
            self.tags
                .values()
                .find(|tag| tag.id() == id)
                .map(|tag| tag.as_ref() as &dyn FunctionTag)
        }

        fn get_all_function_tags(&self) -> Vec<&dyn FunctionTag> {
            self.tags
                .values()
                .map(|tag| tag.as_ref() as &dyn FunctionTag)
                .collect()
        }

        fn is_tag_assigned(&self, name: &str) -> bool {
            self.assignments.get(name).map_or(false, |count| *count > 0)
        }

        fn create_function_tag(&mut self, name: &str, comment: &str) -> &dyn FunctionTag {
            if !self.tags.contains_key(name) {
                let tag = MockTag::new(self.next_id, name, comment);
                self.next_id += 1;
                self.tags.insert(name.to_string(), Box::new(tag));
            }
            self.tags.get(name).unwrap().as_ref()
        }

        fn get_use_count(&self, tag: &dyn FunctionTag) -> usize {
            self.assignments.get(tag.name()).copied().unwrap_or(0)
        }
    }

    #[test]
    fn get_function_tag_by_name_returns_existing_tag() {
        let mut manager = MockTagManager::new();
        manager.add_tag("hot", "hot function");
        let tag = manager.get_function_tag_by_name("hot");
        assert!(tag.is_some());
        assert_eq!(tag.unwrap().name(), "hot");
        assert_eq!(tag.unwrap().comment(), "hot function");
    }

    #[test]
    fn get_function_tag_by_name_returns_none_for_missing() {
        let manager = MockTagManager::new();
        let tag = manager.get_function_tag_by_name("nonexistent");
        assert!(tag.is_none());
    }

    #[test]
    fn get_function_tag_by_id_returns_existing_tag() {
        let mut manager = MockTagManager::new();
        manager.add_tag("inline", "");
        let tag = manager.get_function_tag_by_id(1);
        assert!(tag.is_some());
        assert_eq!(tag.unwrap().name(), "inline");
    }

    #[test]
    fn get_function_tag_by_id_returns_none_for_missing() {
        let manager = MockTagManager::new();
        let tag = manager.get_function_tag_by_id(999);
        assert!(tag.is_none());
    }

    #[test]
    fn get_all_function_tags_returns_all_tags() {
        let mut manager = MockTagManager::new();
        manager.add_tag("alpha", "");
        manager.add_tag("beta", "");
        manager.add_tag("gamma", "");
        let tags = manager.get_all_function_tags();
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn get_all_function_tags_returns_empty_when_no_tags() {
        let manager = MockTagManager::new();
        let tags = manager.get_all_function_tags();
        assert!(tags.is_empty());
    }

    #[test]
    fn is_tag_assigned_returns_true_when_assigned() {
        let mut manager = MockTagManager::new();
        manager.add_tag("hot", "");
        manager.mark_assigned("hot", 3);
        assert!(manager.is_tag_assigned("hot"));
    }

    #[test]
    fn is_tag_assigned_returns_false_when_not_assigned() {
        let mut manager = MockTagManager::new();
        manager.add_tag("hot", "");
        assert!(!manager.is_tag_assigned("hot"));
    }

    #[test]
    fn is_tag_assigned_returns_false_for_nonexistent_tag() {
        let manager = MockTagManager::new();
        assert!(!manager.is_tag_assigned("nonexistent"));
    }

    #[test]
    fn create_function_tag_creates_new_tag() {
        let mut manager = MockTagManager::new();
        let tag = manager.create_function_tag("new_tag", "new comment");
        assert_eq!(tag.name(), "new_tag");
        assert_eq!(tag.comment(), "new comment");
    }

    #[test]
    fn create_function_tag_returns_existing_tag_when_present() {
        let mut manager = MockTagManager::new();
        manager.add_tag("existing", "existing comment");
        let tag = manager.create_function_tag("existing", "different comment");
        assert_eq!(tag.name(), "existing");
        assert_eq!(tag.comment(), "existing comment");
    }

    #[test]
    fn get_use_count_returns_count_for_assigned_tag() {
        let mut manager = MockTagManager::new();
        manager.add_tag("frequent", "");
        manager.mark_assigned("frequent", 5);
        let tag = manager.get_function_tag_by_name("frequent").unwrap();
        assert_eq!(manager.get_use_count(tag), 5);
    }

    #[test]
    fn get_use_count_returns_zero_for_unassigned_tag() {
        let mut manager = MockTagManager::new();
        manager.add_tag("unused", "");
        let tag = manager.get_function_tag_by_name("unused").unwrap();
        assert_eq!(manager.get_use_count(tag), 0);
    }

    #[test]
    fn multiple_ids_for_different_tags() {
        let mut manager = MockTagManager::new();
        manager.add_tag("first", "");
        manager.add_tag("second", "");
        let tag1 = manager.get_function_tag_by_id(1);
        let tag2 = manager.get_function_tag_by_id(2);
        assert!(tag1.is_some());
        assert!(tag2.is_some());
        assert_ne!(tag1.unwrap().id(), tag2.unwrap().id());
    }

    #[test]
    fn create_and_retrieve_new_tag() {
        let mut manager = MockTagManager::new();
        manager.create_function_tag("test_tag", "test comment");
        let tag = manager.get_function_tag_by_name("test_tag");
        assert!(tag.is_some());
        assert_eq!(tag.unwrap().name(), "test_tag");
    }

    #[test]
    fn tag_names_are_case_sensitive() {
        let mut manager = MockTagManager::new();
        manager.add_tag("Hot", "");
        assert!(manager.get_function_tag_by_name("Hot").is_some());
        assert!(manager.get_function_tag_by_name("hot").is_none());
    }

    #[test]
    fn empty_comment_is_valid() {
        let mut manager = MockTagManager::new();
        let tag = manager.create_function_tag("tag", "");
        assert_eq!(tag.comment(), "");
    }
}
