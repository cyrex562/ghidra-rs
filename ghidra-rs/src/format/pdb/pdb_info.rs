use crate::framework::options::options::Options;

/// Bag of information about a Pdb symbol file, usually extracted from information present in a PE
/// binary.
///
/// Port of `ghidra.app.util.bin.format.pdb.PdbInfo`.
pub trait PdbInfo: Send + Sync {
    /// Returns true if this instance is valid.
    fn is_valid(&self) -> bool;

    /// Writes the various PDB info fields to a program's options.
    fn serialize_to_options(&self, options: &dyn Options);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPdbInfo {
        valid: bool,
    }

    impl MockPdbInfo {
        fn new(valid: bool) -> Self {
            Self { valid }
        }
    }

    impl PdbInfo for MockPdbInfo {
        fn is_valid(&self) -> bool {
            self.valid
        }

        fn serialize_to_options(&self, _options: &dyn Options) {
            // mock implementation
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let pdb: Box<dyn PdbInfo> = Box::new(MockPdbInfo::new(true));
        assert!(pdb.is_valid());
    }

    #[test]
    fn mock_pdb_info_valid() {
        let pdb = MockPdbInfo::new(true);
        assert!(pdb.is_valid());
    }

    #[test]
    fn mock_pdb_info_invalid() {
        let pdb = MockPdbInfo::new(false);
        assert!(!pdb.is_valid());
    }
}
