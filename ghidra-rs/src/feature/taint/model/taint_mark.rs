use std::collections::HashSet;

/// A taint mark — a named symbol with an immutable set of tags.
///
/// This is the bottom-most component in a `TaintVec`. Two marks are equal only
/// when both their name and tag-set are equal, so a mark without tags and the
/// same-named mark *with* tags are considered distinct.
#[derive(Clone, Debug)]
pub struct TaintMark {
    name: String,
    tags: HashSet<String>,
    hash: u64,
}

impl TaintMark {
    /// Construct a new taint mark from a name and a set of tags.
    pub fn new(name: impl Into<String>, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let name = name.into();
        let tags: HashSet<String> = tags.into_iter().map(Into::into).collect();
        let hash = Self::compute_hash(&name, &tags);
        Self { name, tags, hash }
    }

    /// Parse a mark from a string of the form `name` or `name:tag1,tag2,...`.
    pub fn parse(s: &str) -> Self {
        match s.split_once(':') {
            None => Self::new(s, std::iter::empty::<String>()),
            Some((name, tag_part)) => {
                let tags: Vec<&str> = tag_part.split(',').collect();
                Self::new(name, tags)
            }
        }
    }

    /// Return the name of this mark.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the tags associated with this mark.
    pub fn tags(&self) -> &HashSet<String> {
        &self.tags
    }

    /// Return a new mark with the given tag added.
    ///
    /// If the tag is already present this returns a clone of `self`.
    pub fn tagged(&self, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        if self.tags.contains(&tag) {
            return self.clone();
        }
        let mut new_tags = self.tags.clone();
        new_tags.insert(tag);
        let hash = Self::compute_hash(&self.name, &new_tags);
        Self { name: self.name.clone(), tags: new_tags, hash }
    }

    fn compute_hash(name: &str, tags: &HashSet<String>) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        name.hash(&mut h);
        // Sort tags so hash is order-independent.
        let mut sorted: Vec<&str> = tags.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.hash(&mut h);
        h.finish()
    }
}

impl std::fmt::Display for TaintMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.tags.is_empty() {
            write!(f, "{}", self.name)
        } else {
            let mut sorted: Vec<&str> = self.tags.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            write!(f, "{}:{}", self.name, sorted.join(","))
        }
    }
}

impl PartialEq for TaintMark {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.tags == other.tags
    }
}

impl Eq for TaintMark {}

impl std::hash::Hash for TaintMark {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_only() {
        let m = TaintMark::parse("foo");
        assert_eq!(m.name(), "foo");
        assert!(m.tags().is_empty());
        assert_eq!(m.to_string(), "foo");
    }

    #[test]
    fn parse_name_with_tags() {
        let m = TaintMark::parse("foo:a,b,c");
        assert_eq!(m.name(), "foo");
        assert!(m.tags().contains("a"));
        assert!(m.tags().contains("b"));
        assert!(m.tags().contains("c"));
        assert_eq!(m.tags().len(), 3);
    }

    #[test]
    fn to_string_round_trip() {
        // Single-tag round-trip is deterministic.
        let m = TaintMark::parse("bar:x");
        assert_eq!(m.to_string(), "bar:x");
    }

    #[test]
    fn to_string_no_tags() {
        let m = TaintMark::new("baz", std::iter::empty::<String>());
        assert_eq!(m.to_string(), "baz");
    }

    #[test]
    fn equality_name_and_tags_must_match() {
        let a = TaintMark::parse("x");
        let b = TaintMark::parse("x:tag");
        assert_ne!(a, b, "mark without tags != same-named mark with tags");

        let c = TaintMark::parse("x:tag");
        assert_eq!(b, c);
    }

    #[test]
    fn tagged_adds_tag() {
        let m = TaintMark::parse("v");
        let m2 = m.tagged("indirect");
        assert!(m2.tags().contains("indirect"));
        assert_ne!(m, m2);
    }

    #[test]
    fn tagged_idempotent() {
        let m = TaintMark::parse("v:indirect");
        let m2 = m.tagged("indirect");
        assert_eq!(m, m2);
    }

    #[test]
    fn hash_equal_objects_same_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = TaintMark::parse("x:a,b");
        let b = TaintMark::parse("x:b,a");
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn can_be_used_in_hashset() {
        let mut set = std::collections::HashSet::new();
        set.insert(TaintMark::parse("a:t1"));
        set.insert(TaintMark::parse("a:t1"));
        set.insert(TaintMark::parse("a"));
        assert_eq!(set.len(), 2);
    }
}
