use std::cmp::Ordering;
use std::fmt;

/// Holds information extracted from a PE resource data directory.
///
/// This is a pure storage type created during PE header parsing; it does not
/// map back to any PE on-disk data structure directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceInfo {
    address: u32,
    name: String,
    size: u32,
    type_id: i32,
    id: u32,
}

impl ResourceInfo {
    /// Creates a new `ResourceInfo` with the given address, name, and size.
    pub fn new(address: u32, name: String, size: u32) -> Self {
        Self { address, name, size, type_id: 0, id: 0 }
    }

    /// Returns the adjusted address where the resource exists.
    pub fn address(&self) -> u32 {
        self.address
    }

    /// Returns the name of the resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the name of the resource.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Returns the size of the resource in bytes.
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Returns the ID of the resource.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sets the ID of the resource.
    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    /// Returns the resource type ID (e.g. RT_CURSOR, RT_BITMAP).
    ///
    /// Returns `-1` if this is a named resource.
    pub fn type_id(&self) -> i32 {
        self.type_id
    }

    /// Sets the resource type ID.
    pub fn set_type_id(&mut self, type_id: i32) {
        self.type_id = type_id;
    }
}

impl fmt::Display for ResourceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - 0x{:x}", self.name, self.address)
    }
}

impl PartialOrd for ResourceInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResourceInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.type_id.cmp(&other.type_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(address: u32, name: &str, size: u32) -> ResourceInfo {
        ResourceInfo::new(address, name.to_string(), size)
    }

    #[test]
    fn constructor_and_getters() {
        let info = make(0x1000, "ICON", 256);
        assert_eq!(info.address(), 0x1000);
        assert_eq!(info.name(), "ICON");
        assert_eq!(info.size(), 256);
        assert_eq!(info.type_id(), 0);
        assert_eq!(info.id(), 0);
    }

    #[test]
    fn set_name() {
        let mut info = make(0x2000, "OLD", 64);
        info.set_name("NEW".to_string());
        assert_eq!(info.name(), "NEW");
    }

    #[test]
    fn set_id() {
        let mut info = make(0x1000, "R", 10);
        info.set_id(42);
        assert_eq!(info.id(), 42);
    }

    #[test]
    fn set_type_id() {
        let mut info = make(0x1000, "R", 10);
        info.set_type_id(3);
        assert_eq!(info.type_id(), 3);
    }

    #[test]
    fn named_resource_type_id_sentinel() {
        let mut info = make(0x1000, "MyResource", 100);
        info.set_type_id(-1);
        assert_eq!(info.type_id(), -1);
    }

    #[test]
    fn display_matches_java_tostring() {
        let info = make(0x00401000, "BITMAP", 128);
        assert_eq!(info.to_string(), "BITMAP - 0x401000");
    }

    #[test]
    fn display_zero_address() {
        let info = make(0, "X", 0);
        assert_eq!(info.to_string(), "X - 0x0");
    }

    #[test]
    fn ordering_by_type_id() {
        let mut a = make(0x1000, "A", 10);
        let mut b = make(0x2000, "B", 20);
        a.set_type_id(1);
        b.set_type_id(3);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn ordering_equal_type_id() {
        let mut a = make(0x1000, "A", 10);
        let mut b = make(0x2000, "B", 20);
        a.set_type_id(5);
        b.set_type_id(5);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    #[test]
    fn ordering_named_resource_negative_type_id() {
        let mut named = make(0x1000, "Named", 10);
        let mut typed = make(0x2000, "Typed", 20);
        named.set_type_id(-1);
        typed.set_type_id(2);
        assert!(named < typed);
    }

    #[test]
    fn sort_by_type_id() {
        let mut items: Vec<ResourceInfo> = vec![
            { let mut r = make(0, "C", 0); r.set_type_id(3); r },
            { let mut r = make(0, "A", 0); r.set_type_id(1); r },
            { let mut r = make(0, "B", 0); r.set_type_id(2); r },
        ];
        items.sort();
        assert_eq!(items[0].name(), "A");
        assert_eq!(items[1].name(), "B");
        assert_eq!(items[2].name(), "C");
    }

    #[test]
    fn clone_is_independent() {
        let a = make(0x1000, "R", 50);
        let mut b = a.clone();
        b.set_name("S".to_string());
        assert_eq!(a.name(), "R");
        assert_eq!(b.name(), "S");
    }

    #[test]
    fn equality() {
        let mut a = make(0x1000, "R", 50);
        let mut b = make(0x1000, "R", 50);
        a.set_type_id(2);
        b.set_type_id(2);
        assert_eq!(a, b);
    }
}
