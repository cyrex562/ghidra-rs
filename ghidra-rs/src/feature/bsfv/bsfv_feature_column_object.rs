use std::fmt;

/// Wraps a BSim feature hash (32-bit) for unsigned hexadecimal display and
/// unsigned ordering in the BSim feature table.
///
/// Mirrors `ghidra.bsfv.BsfvFeatureColumnObject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BsfvFeatureColumnObject {
    bsim_feature: u32,
}

impl BsfvFeatureColumnObject {
    /// Creates a new [`BsfvFeatureColumnObject`] for the BSim feature with the
    /// given hash value.
    pub fn new(hash: u32) -> Self {
        Self { bsim_feature: hash }
    }

    /// Returns the raw feature hash.
    pub fn hash(&self) -> u32 {
        self.bsim_feature
    }
}

/// Displays the feature hash as a lowercase hexadecimal string, matching
/// Java's `Integer.toHexString`.
impl fmt::Display for BsfvFeatureColumnObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.bsim_feature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hex_zero() {
        assert_eq!(BsfvFeatureColumnObject::new(0).to_string(), "0");
    }

    #[test]
    fn display_hex_positive() {
        assert_eq!(BsfvFeatureColumnObject::new(255).to_string(), "ff");
        assert_eq!(BsfvFeatureColumnObject::new(0xDEAD_BEEF).to_string(), "deadbeef");
    }

    #[test]
    fn display_hex_max() {
        // Java Integer.toHexString(0xFFFF_FFFF) == "ffffffff"
        assert_eq!(BsfvFeatureColumnObject::new(u32::MAX).to_string(), "ffffffff");
    }

    #[test]
    fn display_hex_high_bit() {
        // Java Integer.toHexString(-1) == "ffffffff"
        // In Java the int -1 is 0xFFFF_FFFF; we store as u32::MAX.
        let obj = BsfvFeatureColumnObject::new(0x8000_0000);
        assert_eq!(obj.to_string(), "80000000");
    }

    #[test]
    fn unsigned_ordering() {
        // 0x8000_0000 is negative as i32 but greater than 1 as u32.
        let small = BsfvFeatureColumnObject::new(1);
        let large = BsfvFeatureColumnObject::new(0x8000_0000);
        assert!(large > small, "unsigned comparison: 0x80000000 > 1");
    }

    #[test]
    fn ordering_equal() {
        let a = BsfvFeatureColumnObject::new(42);
        let b = BsfvFeatureColumnObject::new(42);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn hash_accessor() {
        let obj = BsfvFeatureColumnObject::new(0xCAFE_BABE);
        assert_eq!(obj.hash(), 0xCAFE_BABE);
    }

    #[test]
    fn clone_and_copy() {
        let a = BsfvFeatureColumnObject::new(7);
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
