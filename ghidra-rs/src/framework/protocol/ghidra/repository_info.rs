use std::fmt;
use std::hash::{Hash, Hasher};

/// Information describing a Ghidra repository, including its URL and access mode.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepositoryInfo {
    repository_url: String,
    repository_name: String,
    read_only: bool,
}

impl RepositoryInfo {
    /// Creates a new `RepositoryInfo`.
    pub fn new(
        repository_url: impl Into<String>,
        repository_name: impl Into<String>,
        read_only: bool,
    ) -> Self {
        Self {
            repository_url: repository_url.into(),
            repository_name: repository_name.into(),
            read_only,
        }
    }

    /// Returns the URL corresponding to the repository.
    pub fn url(&self) -> &str {
        &self.repository_url
    }

    /// Returns the repository name.
    pub fn repository_name(&self) -> &str {
        &self.repository_name
    }

    /// Returns `true` if the repository is read-only.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Returns a short string identifying the repository by name and access mode.
    pub fn to_short_string(&self) -> String {
        format!(
            "{}{}",
            self.repository_name,
            if self.read_only { "(read-only)" } else { "" }
        )
    }
}

/// Equality is determined by URL and read-only status only, mirroring the Java implementation
/// which excludes `repositoryName` from `equals()`.
impl PartialEq for RepositoryInfo {
    fn eq(&self, other: &Self) -> bool {
        self.read_only == other.read_only && self.repository_url == other.repository_url
    }
}

impl Eq for RepositoryInfo {}

impl Hash for RepositoryInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.repository_url.hash(state);
        self.read_only.hash(state);
    }
}

impl fmt::Display for RepositoryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.repository_url,
            if self.read_only { "(read-only)" } else { "" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::collections::hash_map::DefaultHasher;

    fn hash_of(v: &RepositoryInfo) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    fn info(url: &str, name: &str, ro: bool) -> RepositoryInfo {
        RepositoryInfo::new(url, name, ro)
    }

    #[test]
    fn fields_are_accessible() {
        let i = info("ghidra://localhost/repo", "MyRepo", false);
        assert_eq!(i.url(), "ghidra://localhost/repo");
        assert_eq!(i.repository_name(), "MyRepo");
        assert!(!i.read_only());
    }

    #[test]
    fn equality_excludes_repository_name() {
        let a = info("ghidra://localhost/repo", "Name1", false);
        let b = info("ghidra://localhost/repo", "Name2", false);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_url() {
        let a = info("ghidra://host1/repo", "Repo", false);
        let b = info("ghidra://host2/repo", "Repo", false);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_read_only() {
        let a = info("ghidra://localhost/repo", "Repo", true);
        let b = info("ghidra://localhost/repo", "Repo", false);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_for_equal_instances() {
        let a = info("ghidra://localhost/repo", "Name1", true);
        let b = info("ghidra://localhost/repo", "Name2", true);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn display_url_only_when_not_read_only() {
        let i = info("ghidra://localhost/repo", "Repo", false);
        assert_eq!(i.to_string(), "ghidra://localhost/repo");
    }

    #[test]
    fn display_appends_read_only_suffix() {
        let i = info("ghidra://localhost/repo", "Repo", true);
        assert_eq!(i.to_string(), "ghidra://localhost/repo(read-only)");
    }

    #[test]
    fn to_short_string_uses_name() {
        let i = info("ghidra://localhost/repo", "MyRepo", false);
        assert_eq!(i.to_short_string(), "MyRepo");
    }

    #[test]
    fn to_short_string_appends_read_only_suffix() {
        let i = info("ghidra://localhost/repo", "MyRepo", true);
        assert_eq!(i.to_short_string(), "MyRepo(read-only)");
    }

    #[test]
    fn deduplicates_in_hash_set_by_url_and_access() {
        let mut set = HashSet::new();
        let a = info("ghidra://localhost/repo", "NameA", false);
        let b = info("ghidra://localhost/repo", "NameB", false);
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn distinct_access_modes_are_separate_entries() {
        let mut set = HashSet::new();
        set.insert(info("ghidra://localhost/repo", "Repo", true));
        set.insert(info("ghidra://localhost/repo", "Repo", false));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = info("ghidra://localhost/repo", "Repo", false);
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_struct_name() {
        let i = info("ghidra://localhost/repo", "Repo", false);
        assert!(format!("{i:?}").contains("RepositoryInfo"));
    }
}
