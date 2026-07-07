/// Trait representing the generic components of a Mach-O opcode table.
///
/// Mirrors the abstract `OpcodeTable` class from Ghidra's Java source.
///
/// See <https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOLayout.cpp>
/// See <https://github.com/apple-oss-distributions/dyld/blob/main/common/MachOAnalyzer.cpp>
pub trait OpcodeTable {
    /// Returns opcode offsets from the start of the bind data.
    fn opcode_offsets(&self) -> &[u64];

    /// Returns ULEB128 offsets from the start of the bind data.
    fn uleb_offsets(&self) -> &[u64];

    /// Returns SLEB128 offsets from the start of the bind data.
    fn sleb_offsets(&self) -> &[u64];

    /// Returns string offsets from the start of the bind data.
    fn string_offsets(&self) -> &[u64];
}

/// Base data struct for Mach-O opcode tables.
///
/// Concrete opcode table types embed this struct and delegate to it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpcodeTableData {
    pub opcode_offsets: Vec<u64>,
    pub uleb_offsets: Vec<u64>,
    pub sleb_offsets: Vec<u64>,
    pub string_offsets: Vec<u64>,
}

impl OpcodeTableData {
    /// Creates a new, empty opcode table data.
    pub fn new() -> Self {
        Self::default()
    }
}

impl OpcodeTable for OpcodeTableData {
    fn opcode_offsets(&self) -> &[u64] {
        &self.opcode_offsets
    }

    fn uleb_offsets(&self) -> &[u64] {
        &self.uleb_offsets
    }

    fn sleb_offsets(&self) -> &[u64] {
        &self.sleb_offsets
    }

    fn string_offsets(&self) -> &[u64] {
        &self.string_offsets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_data_is_empty() {
        let t = OpcodeTableData::new();
        assert!(t.opcode_offsets().is_empty());
        assert!(t.uleb_offsets().is_empty());
        assert!(t.sleb_offsets().is_empty());
        assert!(t.string_offsets().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let a = OpcodeTableData::new();
        let b = OpcodeTableData::default();
        assert_eq!(a, b);
    }

    #[test]
    fn getters_return_inserted_offsets() {
        let t = OpcodeTableData {
            opcode_offsets: vec![0, 4, 8],
            uleb_offsets: vec![1, 5],
            sleb_offsets: vec![2],
            string_offsets: vec![3, 7, 11],
        };
        assert_eq!(t.opcode_offsets(), &[0, 4, 8]);
        assert_eq!(t.uleb_offsets(), &[1, 5]);
        assert_eq!(t.sleb_offsets(), &[2]);
        assert_eq!(t.string_offsets(), &[3, 7, 11]);
    }

    #[test]
    fn trait_object_dispatch_works() {
        let t: Box<dyn OpcodeTable> = Box::new(OpcodeTableData {
            opcode_offsets: vec![10, 20],
            uleb_offsets: vec![30],
            sleb_offsets: vec![40, 50],
            string_offsets: vec![],
        });
        assert_eq!(t.opcode_offsets(), &[10, 20]);
        assert_eq!(t.uleb_offsets(), &[30]);
        assert_eq!(t.sleb_offsets(), &[40, 50]);
        assert!(t.string_offsets().is_empty());
    }

    #[test]
    fn clone_produces_equal_independent_copy() {
        let original = OpcodeTableData {
            opcode_offsets: vec![1, 2, 3],
            uleb_offsets: vec![4],
            sleb_offsets: vec![5, 6],
            string_offsets: vec![7],
        };
        let mut cloned = original.clone();
        cloned.opcode_offsets.push(99);
        assert_eq!(original.opcode_offsets(), &[1, 2, 3]);
        assert_eq!(cloned.opcode_offsets(), &[1, 2, 3, 99]);
    }
}
