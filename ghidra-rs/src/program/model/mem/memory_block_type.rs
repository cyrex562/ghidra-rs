use std::fmt;
use std::str::FromStr;

/// Type of a memory block.
///
/// This mirrors Ghidra's `MemoryBlockType` enum display names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryBlockType {
    /// A normal memory block.
    Default,
    /// A memory block whose bytes are mapped bit-by-bit from another block.
    BitMapped,
    /// A memory block whose bytes are mapped byte-by-byte from another block.
    ByteMapped,
}

impl MemoryBlockType {
    /// Returns the Java-compatible display name for this block type.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::BitMapped => "Bit Mapped",
            Self::ByteMapped => "Byte Mapped",
        }
    }

    /// Returns true for bit-mapped and byte-mapped block types.
    pub const fn is_mapped(self) -> bool {
        matches!(self, Self::BitMapped | Self::ByteMapped)
    }
}

impl fmt::Display for MemoryBlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MemoryBlockType {
    type Err = ParseMemoryBlockTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Default" => Ok(Self::Default),
            "Bit Mapped" => Ok(Self::BitMapped),
            "Byte Mapped" => Ok(Self::ByteMapped),
            _ => Err(ParseMemoryBlockTypeError),
        }
    }
}

/// Error returned when parsing an unknown memory block type name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMemoryBlockTypeError;

impl fmt::Display for ParseMemoryBlockTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown memory block type")
    }
}

impl std::error::Error for ParseMemoryBlockTypeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_match_java_enum_names() {
        assert_eq!(MemoryBlockType::Default.to_string(), "Default");
        assert_eq!(MemoryBlockType::BitMapped.to_string(), "Bit Mapped");
        assert_eq!(MemoryBlockType::ByteMapped.to_string(), "Byte Mapped");
    }

    #[test]
    fn parse_display_names() {
        assert_eq!("Default".parse(), Ok(MemoryBlockType::Default));
        assert_eq!("Bit Mapped".parse(), Ok(MemoryBlockType::BitMapped));
        assert_eq!("Byte Mapped".parse(), Ok(MemoryBlockType::ByteMapped));
        assert_eq!(
            "BIT_MAPPED".parse::<MemoryBlockType>(),
            Err(ParseMemoryBlockTypeError)
        );
    }

    #[test]
    fn mapped_types_match_memory_block_semantics() {
        assert!(!MemoryBlockType::Default.is_mapped());
        assert!(MemoryBlockType::BitMapped.is_mapped());
        assert!(MemoryBlockType::ByteMapped.is_mapped());
    }
}
