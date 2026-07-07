/// Types of comments that can be placed at an address or on a code unit.
///
/// The ordinals of these variants are preserved for compatibility with comment storage,
/// as they are used for serialization and must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// Comments that appear at the end of the line.
    Eol,
    /// Comments that appear before the code unit.
    Pre,
    /// Comments that appear after the code unit.
    Post,
    /// Comments that appear before the code unit with a decorated border.
    Plate,
    /// Comments that appear at locations that refer to the address where this comment is defined.
    Repeatable,
}

impl CommentType {
    /// Gets the comment type which corresponds to the specified ordinal value.
    ///
    /// This method is intended for conversion of legacy comment type integer values to the enum type.
    ///
    /// # Arguments
    /// * `ordinal` - The ordinal value corresponding to a comment type.
    ///
    /// # Returns
    /// The comment type enum variant if the ordinal is valid (0-4), or `None` otherwise.
    pub fn from_ordinal(ordinal: i32) -> Option<Self> {
        match ordinal {
            0 => Some(CommentType::Eol),
            1 => Some(CommentType::Pre),
            2 => Some(CommentType::Post),
            3 => Some(CommentType::Plate),
            4 => Some(CommentType::Repeatable),
            _ => None,
        }
    }

    /// Returns the ordinal value of this comment type.
    pub fn ordinal(self) -> i32 {
        match self {
            CommentType::Eol => 0,
            CommentType::Pre => 1,
            CommentType::Post => 2,
            CommentType::Plate => 3,
            CommentType::Repeatable => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ordinal_eol() {
        assert_eq!(CommentType::from_ordinal(0), Some(CommentType::Eol));
    }

    #[test]
    fn from_ordinal_pre() {
        assert_eq!(CommentType::from_ordinal(1), Some(CommentType::Pre));
    }

    #[test]
    fn from_ordinal_post() {
        assert_eq!(CommentType::from_ordinal(2), Some(CommentType::Post));
    }

    #[test]
    fn from_ordinal_plate() {
        assert_eq!(CommentType::from_ordinal(3), Some(CommentType::Plate));
    }

    #[test]
    fn from_ordinal_repeatable() {
        assert_eq!(CommentType::from_ordinal(4), Some(CommentType::Repeatable));
    }

    #[test]
    fn from_ordinal_invalid() {
        assert_eq!(CommentType::from_ordinal(5), None);
        assert_eq!(CommentType::from_ordinal(-1), None);
        assert_eq!(CommentType::from_ordinal(100), None);
    }

    #[test]
    fn ordinal_roundtrip() {
        let variants = [
            CommentType::Eol,
            CommentType::Pre,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ];
        for variant in variants.iter() {
            let ordinal = variant.ordinal();
            let restored = CommentType::from_ordinal(ordinal).unwrap();
            assert_eq!(restored, *variant);
        }
    }

    #[test]
    fn clone_preserves_variant() {
        for v in [
            CommentType::Eol,
            CommentType::Pre,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ] {
            assert_eq!(v.clone(), v);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", CommentType::Eol).contains("Eol"));
        assert!(format!("{:?}", CommentType::Pre).contains("Pre"));
        assert!(format!("{:?}", CommentType::Post).contains("Post"));
        assert!(format!("{:?}", CommentType::Plate).contains("Plate"));
        assert!(format!("{:?}", CommentType::Repeatable).contains("Repeatable"));
    }

    #[test]
    fn equality() {
        assert_eq!(CommentType::Eol, CommentType::Eol);
        assert_ne!(CommentType::Eol, CommentType::Pre);
        assert_ne!(CommentType::Pre, CommentType::Post);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CommentType::Eol);
        assert!(set.contains(&CommentType::Eol));
        assert!(!set.contains(&CommentType::Pre));
    }
}
