/// Container pairing a hex-byte string with its disassembly text.
///
/// Mirrors `ghidra.bitpatterns.info.BytesAndDisassembly`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BytesAndDisassembly {
    bytes: String,
    disassembly: String,
}

impl BytesAndDisassembly {
    pub fn new(bytes: impl Into<String>, disassembly: impl Into<String>) -> Self {
        Self {
            bytes: bytes.into(),
            disassembly: disassembly.into(),
        }
    }

    pub fn bytes(&self) -> &str {
        &self.bytes
    }

    pub fn disassembly(&self) -> &str {
        &self.disassembly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_getters() {
        let bd = BytesAndDisassembly::new("deadbeef", "NOP");
        assert_eq!(bd.bytes(), "deadbeef");
        assert_eq!(bd.disassembly(), "NOP");
    }

    #[test]
    fn test_equality_same_fields() {
        let a = BytesAndDisassembly::new("aabb", "MOV");
        let b = BytesAndDisassembly::new("aabb", "MOV");
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_different_bytes() {
        let a = BytesAndDisassembly::new("aabb", "MOV");
        let b = BytesAndDisassembly::new("ccdd", "MOV");
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_different_disassembly() {
        let a = BytesAndDisassembly::new("aabb", "MOV");
        let b = BytesAndDisassembly::new("aabb", "NOP");
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_equal_objects_same_bucket() {
        let a = BytesAndDisassembly::new("ff00", "JMP");
        let b = BytesAndDisassembly::new("ff00", "JMP");
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_hash_distinct_objects_in_set() {
        let a = BytesAndDisassembly::new("ff00", "JMP");
        let b = BytesAndDisassembly::new("00ff", "CALL");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_empty_strings() {
        let bd = BytesAndDisassembly::new("", "");
        assert_eq!(bd.bytes(), "");
        assert_eq!(bd.disassembly(), "");
        assert_eq!(bd, BytesAndDisassembly::new("", ""));
    }
}
