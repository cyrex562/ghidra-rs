/// Holds the information extracted from a resource data directory string entry.
///
/// This is a pure storage type created during PE header parsing; it does not
/// map back to any PE on-disk data structure directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStringInfo {
    address: u32,
    string: String,
    length: u32,
}

impl ResourceStringInfo {
    /// Creates a new `ResourceStringInfo`.
    ///
    /// # Parameters
    /// - `address`: the adjusted address where the resource exists
    /// - `string`: the resource string
    /// - `length`: the length of the resource
    pub fn new(address: u32, string: String, length: u32) -> Self {
        Self { address, string, length }
    }

    /// Returns the adjusted address where the resource exists.
    pub fn address(&self) -> u32 {
        self.address
    }

    /// Returns the resource string.
    pub fn string(&self) -> &str {
        &self.string
    }

    /// Returns the length of the resource.
    pub fn length(&self) -> u32 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_and_getters() {
        let info = ResourceStringInfo::new(0x1000, "Hello".to_string(), 5);
        assert_eq!(info.address(), 0x1000);
        assert_eq!(info.string(), "Hello");
        assert_eq!(info.length(), 5);
    }

    #[test]
    fn empty_string() {
        let info = ResourceStringInfo::new(0, String::new(), 0);
        assert_eq!(info.address(), 0);
        assert_eq!(info.string(), "");
        assert_eq!(info.length(), 0);
    }

    #[test]
    fn clone_is_independent() {
        let a = ResourceStringInfo::new(0x2000, "resource".to_string(), 8);
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(b.string(), "resource");
    }

    #[test]
    fn equality() {
        let a = ResourceStringInfo::new(0x1000, "foo".to_string(), 3);
        let b = ResourceStringInfo::new(0x1000, "foo".to_string(), 3);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_address() {
        let a = ResourceStringInfo::new(0x1000, "foo".to_string(), 3);
        let b = ResourceStringInfo::new(0x2000, "foo".to_string(), 3);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_string() {
        let a = ResourceStringInfo::new(0x1000, "foo".to_string(), 3);
        let b = ResourceStringInfo::new(0x1000, "bar".to_string(), 3);
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_length() {
        let a = ResourceStringInfo::new(0x1000, "foo".to_string(), 3);
        let b = ResourceStringInfo::new(0x1000, "foo".to_string(), 99);
        assert_ne!(a, b);
    }

    #[test]
    fn large_address() {
        let info = ResourceStringInfo::new(0xFFFF_FFFF, "big".to_string(), 100);
        assert_eq!(info.address(), 0xFFFF_FFFF);
    }
}
