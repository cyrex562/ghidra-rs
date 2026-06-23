use std::fmt;

/// A no-op statement used to instrument branching operations in the Pcode CFG.
///
/// In the Pcode frontend, JMP instructions that act purely as control-flow
/// transfers are represented as `PcodeNop` nodes — they carry a location but
/// produce no data-flow effect during forward semantics.
///
/// Corresponds to `ghidra.lisa.pcode.statements.PcodeNop` in the Java source.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PcodeNop {
    cfg_id: u64,
    location: String,
}

impl PcodeNop {
    /// Creates a new `PcodeNop` for the CFG identified by `cfg_id` at `location`.
    pub fn new(cfg_id: u64, location: impl Into<String>) -> Self {
        Self { cfg_id, location: location.into() }
    }

    /// Returns the CFG identifier this statement belongs to.
    pub fn cfg_id(&self) -> u64 {
        self.cfg_id
    }

    /// Returns the code location string.
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl fmt::Display for PcodeNop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // JMPs are the only current nops
        write!(f, "JMP @ {}", self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(nop: &PcodeNop) -> u64 {
        let mut h = DefaultHasher::new();
        nop.hash(&mut h);
        h.finish()
    }

    #[test]
    fn display_format() {
        let nop = PcodeNop::new(1, "0x1000");
        assert_eq!(nop.to_string(), "JMP @ 0x1000");
    }

    #[test]
    fn equal_when_same_cfg_and_location() {
        let a = PcodeNop::new(42, "0x2000");
        let b = PcodeNop::new(42, "0x2000");
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_different_location() {
        let a = PcodeNop::new(1, "0x1000");
        let b = PcodeNop::new(1, "0x2000");
        assert_ne!(a, b);
    }

    #[test]
    fn not_equal_different_cfg() {
        let a = PcodeNop::new(1, "0x1000");
        let b = PcodeNop::new(2, "0x1000");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        let a = PcodeNop::new(7, "0xdeadbeef");
        let b = PcodeNop::new(7, "0xdeadbeef");
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn ordering_by_cfg_then_location() {
        let a = PcodeNop::new(1, "0x1000");
        let b = PcodeNop::new(1, "0x2000");
        let c = PcodeNop::new(2, "0x0000");
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn compare_same_class_no_extra_fields() {
        // Two nops with identical cfg and location are equivalent — mirrors
        // Java's compareSameClass returning 0 (no extra fields to compare).
        let a = PcodeNop::new(5, "0x5000");
        let b = PcodeNop::new(5, "0x5000");
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn accessors() {
        let nop = PcodeNop::new(99, "some::location");
        assert_eq!(nop.cfg_id(), 99);
        assert_eq!(nop.location(), "some::location");
    }

    #[test]
    fn clone_is_equal() {
        let a = PcodeNop::new(3, "0x3000");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
