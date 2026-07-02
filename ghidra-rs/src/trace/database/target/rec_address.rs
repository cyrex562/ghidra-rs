/// A record address representing a location in an address space.
///
/// This is the Rust equivalent of `ghidra.util.database.DBCachedObjectStoreFactory.RecAddress`,
/// a simple record storing a space ID and offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecAddress {
    /// The ID of the address space.
    pub space_id: i32,
    /// The offset within the address space.
    pub offset: i64,
}

impl RecAddress {
    /// Creates a new record address.
    pub fn new(space_id: i32, offset: i64) -> Self {
        Self { space_id, offset }
    }

    /// Returns the offset within the address space.
    pub fn offset(&self) -> i64 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let addr = RecAddress::new(1, 0x1000);
        assert_eq!(addr.space_id, 1);
        assert_eq!(addr.offset, 0x1000);
    }

    #[test]
    fn offset_method_returns_offset() {
        let addr = RecAddress::new(2, 0x2000);
        assert_eq!(addr.offset(), 0x2000);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let addr1 = RecAddress::new(3, 0x3000);
        let addr2 = addr1.clone();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn equality() {
        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(1, 0x1000);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn inequality_on_different_space() {
        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(2, 0x1000);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn inequality_on_different_offset() {
        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(1, 0x2000);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn ordering() {
        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(1, 0x2000);
        let addr3 = RecAddress::new(2, 0x1000);
        assert!(addr1 < addr2);
        assert!(addr1 < addr3);
        assert!(addr2 < addr3);
    }

    #[test]
    fn hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let addr1 = RecAddress::new(1, 0x1000);
        let addr2 = RecAddress::new(1, 0x1000);

        let mut hasher1 = DefaultHasher::new();
        addr1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        addr2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }
}
