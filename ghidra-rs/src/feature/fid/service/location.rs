use std::fmt;
use std::hash::{Hash, Hasher};

use crate::framework::model::DomainFile;
use crate::program::model::address::Address;

/// Identifies a specific function by the domain file that contains it, the function's name,
/// and its entry point address.
///
/// Port of `ghidra.feature.fid.service.Location`.
pub struct Location {
    domain_file: Option<Box<dyn DomainFile>>,
    function_name: Option<String>,
    entry_point: Option<Address>,
}

impl Location {
    /// Creates a new location for the given function.
    pub fn new(
        domain_file: Option<Box<dyn DomainFile>>,
        function_name: Option<String>,
        entry_point: Option<Address>,
    ) -> Self {
        Self {
            domain_file,
            function_name,
            entry_point,
        }
    }

    /// Returns the domain file containing the function, or `None` if not associated with one.
    pub fn domain_file(&self) -> Option<&dyn DomainFile> {
        self.domain_file.as_deref()
    }

    /// Returns the name of the function at this location.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Returns the entry point address of the function, or `None` if not known.
    pub fn function_entry_point(&self) -> Option<&Address> {
        self.entry_point.as_ref()
    }

    fn file_id(&self) -> Option<String> {
        self.domain_file.as_ref().and_then(|f| f.get_file_id())
    }
}

impl PartialEq for Location {
    fn eq(&self, other: &Self) -> bool {
        self.file_id() == other.file_id()
            && self.entry_point == other.entry_point
            && self.function_name == other.function_name
    }
}

impl Eq for Location {}

impl Hash for Location {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.file_id().hash(state);
        self.entry_point.hash(state);
        self.function_name.hash(state);
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(domain_file) = &self.domain_file {
            write!(f, "{}:", domain_file.get_pathname())?;
        }
        match &self.function_name {
            Some(name) => write!(f, "{name}")?,
            None => write!(f, "null")?,
        }
        if let Some(entry_point) = &self.entry_point {
            write!(f, " ({entry_point})")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockDomainFile {
        file_id: Option<String>,
        pathname: String,
    }

    impl DomainFile for MockDomainFile {
        fn get_file_id(&self) -> Option<String> {
            self.file_id.clone()
        }

        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }
    }

    #[test]
    fn accessors_return_constructed_values() {
        let address = make_address(0x1000);
        let file = Box::new(MockDomainFile {
            file_id: Some("id1".to_string()),
            pathname: "/a/b".to_string(),
        });
        let loc = Location::new(Some(file), Some("foo".to_string()), Some(address.clone()));

        assert_eq!(loc.domain_file().unwrap().get_pathname(), "/a/b");
        assert_eq!(loc.function_name(), Some("foo"));
        assert_eq!(loc.function_entry_point(), Some(&address));
    }

    #[test]
    fn all_none_fields_are_supported() {
        let loc = Location::new(None, None, None);
        assert!(loc.domain_file().is_none());
        assert!(loc.function_name().is_none());
        assert!(loc.function_entry_point().is_none());
    }

    #[test]
    fn equality_compares_domain_file_by_file_id_not_identity() {
        let a = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id1".to_string()), pathname: "/a".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        let b = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id1".to_string()), pathname: "/different/path".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn equality_detects_different_file_id() {
        let a = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id1".to_string()), pathname: "/a".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        let b = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id2".to_string()), pathname: "/a".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn equality_detects_different_function_name_and_entry_point() {
        let a = Location::new(None, Some("foo".to_string()), Some(make_address(0x1000)));
        let b = Location::new(None, Some("bar".to_string()), Some(make_address(0x1000)));
        let c = Location::new(None, Some("foo".to_string()), Some(make_address(0x2000)));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn none_domain_file_equals_missing_file_id() {
        let a = Location::new(None, Some("foo".to_string()), None);
        let b = Location::new(
            Some(Box::new(MockDomainFile { file_id: None, pathname: "/a".to_string() })),
            Some("foo".to_string()),
            None,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn equal_locations_have_equal_hashes() {
        use std::collections::hash_map::DefaultHasher;

        fn hash_of(loc: &Location) -> u64 {
            let mut hasher = DefaultHasher::new();
            loc.hash(&mut hasher);
            hasher.finish()
        }

        let a = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id1".to_string()), pathname: "/a".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        let b = Location::new(
            Some(Box::new(MockDomainFile { file_id: Some("id1".to_string()), pathname: "/other".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn display_includes_pathname_name_and_entry_point() {
        let loc = Location::new(
            Some(Box::new(MockDomainFile { file_id: None, pathname: "/a/b".to_string() })),
            Some("foo".to_string()),
            Some(make_address(0x1000)),
        );
        let text = loc.to_string();
        assert!(text.starts_with("/a/b:foo ("));
        assert!(text.contains("foo"));
    }

    #[test]
    fn display_with_no_domain_file_and_no_entry_point() {
        let loc = Location::new(None, Some("foo".to_string()), None);
        assert_eq!(loc.to_string(), "foo");
    }

    #[test]
    fn display_with_no_function_name_prints_null() {
        let loc = Location::new(None, None, None);
        assert_eq!(loc.to_string(), "null");
    }
}
