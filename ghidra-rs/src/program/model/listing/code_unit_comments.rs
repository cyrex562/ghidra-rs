use crate::program::model::listing::CommentType;

/// Container for all the comments at an address.
pub struct CodeUnitComments {
    comments: [Option<String>; 5],
}

impl CodeUnitComments {
    /// Creates a new CodeUnitComments with the given comments array.
    ///
    /// # Arguments
    /// * `comments` - An array of exactly 5 strings (one for each CommentType variant)
    ///
    /// # Panics
    /// Panics if the comments array does not have exactly 5 elements (matching CommentType.values().length)
    pub fn new(comments: [Option<String>; 5]) -> Self {
        Self { comments }
    }

    /// Gets the comment for the given comment type.
    ///
    /// # Arguments
    /// * `comment_type` - The CommentType to retrieve
    ///
    /// # Returns
    /// The comment of the given type as an Option, or None if no comment of that type exists
    pub fn get_comment(&self, comment_type: CommentType) -> Option<&str> {
        self.comments[comment_type.ordinal() as usize].as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_comments() {
        let comments = [
            Some("eol".to_string()),
            Some("pre".to_string()),
            Some("post".to_string()),
            Some("plate".to_string()),
            Some("repeatable".to_string()),
        ];
        let code_unit = CodeUnitComments::new(comments);
        assert_eq!(code_unit.get_comment(CommentType::Eol), Some("eol"));
        assert_eq!(code_unit.get_comment(CommentType::Pre), Some("pre"));
        assert_eq!(code_unit.get_comment(CommentType::Post), Some("post"));
        assert_eq!(code_unit.get_comment(CommentType::Plate), Some("plate"));
        assert_eq!(code_unit.get_comment(CommentType::Repeatable), Some("repeatable"));
    }

    #[test]
    fn get_comment_with_none_values() {
        let comments = [None, None, None, None, None];
        let code_unit = CodeUnitComments::new(comments);
        assert_eq!(code_unit.get_comment(CommentType::Eol), None);
        assert_eq!(code_unit.get_comment(CommentType::Pre), None);
        assert_eq!(code_unit.get_comment(CommentType::Post), None);
        assert_eq!(code_unit.get_comment(CommentType::Plate), None);
        assert_eq!(code_unit.get_comment(CommentType::Repeatable), None);
    }

    #[test]
    fn get_comment_with_mixed_values() {
        let comments = [
            Some("eol".to_string()),
            None,
            Some("post".to_string()),
            None,
            Some("repeatable".to_string()),
        ];
        let code_unit = CodeUnitComments::new(comments);
        assert_eq!(code_unit.get_comment(CommentType::Eol), Some("eol"));
        assert_eq!(code_unit.get_comment(CommentType::Pre), None);
        assert_eq!(code_unit.get_comment(CommentType::Post), Some("post"));
        assert_eq!(code_unit.get_comment(CommentType::Plate), None);
        assert_eq!(code_unit.get_comment(CommentType::Repeatable), Some("repeatable"));
    }

    #[test]
    fn get_comment_returns_none_for_missing_comment() {
        let comments = [
            Some("eol".to_string()),
            None,
            None,
            None,
            None,
        ];
        let code_unit = CodeUnitComments::new(comments);
        assert_eq!(code_unit.get_comment(CommentType::Pre), None);
    }

    #[test]
    fn get_comment_with_empty_string() {
        let comments = [
            Some(String::new()),
            Some("pre".to_string()),
            None,
            None,
            None,
        ];
        let code_unit = CodeUnitComments::new(comments);
        assert_eq!(code_unit.get_comment(CommentType::Eol), Some(""));
    }

    #[test]
    fn get_comment_all_types() {
        let comment_types = [
            CommentType::Eol,
            CommentType::Pre,
            CommentType::Post,
            CommentType::Plate,
            CommentType::Repeatable,
        ];
        let comments = [
            Some("type0".to_string()),
            Some("type1".to_string()),
            Some("type2".to_string()),
            Some("type3".to_string()),
            Some("type4".to_string()),
        ];
        let code_unit = CodeUnitComments::new(comments);
        for (i, &comment_type) in comment_types.iter().enumerate() {
            let expected = match i {
                0 => "type0",
                1 => "type1",
                2 => "type2",
                3 => "type3",
                4 => "type4",
                _ => unreachable!(),
            };
            assert_eq!(code_unit.get_comment(comment_type), Some(expected));
        }
    }
}
