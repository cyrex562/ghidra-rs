use std::fmt;

/// Enum for the various supported entropy chunk sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntropyChunkSize {
    Small,
    Medium,
    Large,
}

impl EntropyChunkSize {
    /// Returns the label for this chunk size.
    pub fn label(&self) -> &'static str {
        match self {
            EntropyChunkSize::Small => "256 Bytes",
            EntropyChunkSize::Medium => "512 Bytes",
            EntropyChunkSize::Large => "1024 Bytes",
        }
    }

    /// Returns the chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        match self {
            EntropyChunkSize::Small => 256,
            EntropyChunkSize::Medium => 512,
            EntropyChunkSize::Large => 1024,
        }
    }
}

impl fmt::Display for EntropyChunkSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_label() {
        assert_eq!(EntropyChunkSize::Small.label(), "256 Bytes");
    }

    #[test]
    fn test_medium_label() {
        assert_eq!(EntropyChunkSize::Medium.label(), "512 Bytes");
    }

    #[test]
    fn test_large_label() {
        assert_eq!(EntropyChunkSize::Large.label(), "1024 Bytes");
    }

    #[test]
    fn test_small_chunk_size() {
        assert_eq!(EntropyChunkSize::Small.chunk_size(), 256);
    }

    #[test]
    fn test_medium_chunk_size() {
        assert_eq!(EntropyChunkSize::Medium.chunk_size(), 512);
    }

    #[test]
    fn test_large_chunk_size() {
        assert_eq!(EntropyChunkSize::Large.chunk_size(), 1024);
    }

    #[test]
    fn test_display_small() {
        assert_eq!(EntropyChunkSize::Small.to_string(), "256 Bytes");
    }

    #[test]
    fn test_display_medium() {
        assert_eq!(EntropyChunkSize::Medium.to_string(), "512 Bytes");
    }

    #[test]
    fn test_display_large() {
        assert_eq!(EntropyChunkSize::Large.to_string(), "1024 Bytes");
    }

    #[test]
    fn test_clone_and_copy() {
        let size = EntropyChunkSize::Small;
        let cloned = size;
        assert_eq!(size, cloned);
    }

    #[test]
    fn test_equality() {
        assert_eq!(EntropyChunkSize::Small, EntropyChunkSize::Small);
        assert_ne!(EntropyChunkSize::Small, EntropyChunkSize::Medium);
    }

    #[test]
    fn test_all_variants() {
        let variants = [
            EntropyChunkSize::Small,
            EntropyChunkSize::Medium,
            EntropyChunkSize::Large,
        ];

        for variant in variants.iter() {
            assert!(!variant.label().is_empty());
            assert!(variant.chunk_size() > 0);
        }
    }
}
