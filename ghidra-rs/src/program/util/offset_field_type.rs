//! Port of `ghidra.program.util.OffsetFieldType`.

/// The type of offset field.
///
/// Port of `ghidra.program.util.OffsetFieldType`.
///
/// See [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation).
///
/// Note: [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation)
/// currently references a placeholder copy of this enum
/// (`crate::program::seam_stubs::OffsetFieldType`) rather than this one, since rewiring that
/// dependent (and removing the placeholder from `seam_stubs.rs`) falls outside this file's own
/// scope. The two enums are structurally identical (same four variants, same naming), so no
/// behavior differs; a follow-up pass should point `OffsetFieldLocation` at this module and
/// delete the placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OffsetFieldType {
    /// Offset relative to the start of the file.
    File,
    /// Offset relative to the start of a function.
    Function,
    /// Offset relative to the program's image base.
    ImageBase,
    /// Offset relative to the start of a memory block.
    MemoryBlock,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let variants = [
            OffsetFieldType::File,
            OffsetFieldType::Function,
            OffsetFieldType::ImageBase,
            OffsetFieldType::MemoryBlock,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn is_copy_and_clone() {
        let a = OffsetFieldType::MemoryBlock;
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn is_hashable() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(OffsetFieldType::File);
        set.insert(OffsetFieldType::File);
        set.insert(OffsetFieldType::Function);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn debug_format_names_the_variant() {
        assert_eq!(format!("{:?}", OffsetFieldType::ImageBase), "ImageBase");
    }
}
