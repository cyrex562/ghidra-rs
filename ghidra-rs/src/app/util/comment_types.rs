use crate::program::model::listing::comment_type::CommentType;

/// Provides a convenience method to get all CodeUnit comment types.
///
/// This is a deprecated utility; prefer using [`CommentType`] directly.
/// Port of deprecated Java class `ghidra.app.util.CommentTypes`.
#[deprecated(since = "11.4", note = "use CommentType enum directly")]
pub fn get_types() -> &'static [CommentType] {
    &[
        CommentType::Pre,
        CommentType::Post,
        CommentType::Eol,
        CommentType::Plate,
        CommentType::Repeatable,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_types_count() {
        assert_eq!(get_types().len(), 5);
    }

    #[test]
    fn test_get_types_content() {
        let types = get_types();
        assert_eq!(types[0], CommentType::Pre);
        assert_eq!(types[1], CommentType::Post);
        assert_eq!(types[2], CommentType::Eol);
        assert_eq!(types[3], CommentType::Plate);
        assert_eq!(types[4], CommentType::Repeatable);
    }

    #[test]
    fn test_get_types_returns_slice() {
        let types = get_types();
        assert_eq!(types.len(), 5);
        let _ = &types[..]; // Verify it's a slice
    }

    #[test]
    fn test_all_types_distinct() {
        let types = get_types();
        for i in 0..types.len() {
            for j in i + 1..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }
}
