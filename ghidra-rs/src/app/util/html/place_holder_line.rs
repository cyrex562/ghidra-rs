use super::ValidatableLine;

/// Marker trait for lines that are generic place holders for diffing.
///
/// Mirrors `ghidra.app.util.html.PlaceHolderLine`.
pub trait PlaceHolderLine: ValidatableLine {}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::html::{TextLine, Color, INVALID_COLOR};

    /// Test that TextLine can be used as a PlaceHolderLine.
    struct PlaceHolder;
    impl ValidatableLine for PlaceHolder {
        fn update_color(
            &mut self,
            _other_line: Option<&mut dyn ValidatableLine>,
            _invalid_color: Color,
        ) {
        }
        fn is_diff_colored(&self) -> bool {
            false
        }
        fn matches_line(&self, _other_line: &dyn ValidatableLine) -> bool {
            true
        }
        fn copy(&self) -> Box<dyn ValidatableLine> {
            Box::new(PlaceHolder)
        }
        fn get_text(&self) -> &str {
            ""
        }
        fn set_text_color(&mut self, _color: Color) {}
        fn set_validation_line(&mut self, _line: &mut dyn ValidatableLine) {}
        fn is_validated(&self) -> bool {
            false
        }
    }
    impl PlaceHolderLine for PlaceHolder {}

    #[test]
    fn placeholder_trait_is_object_safe() {
        let _ph: &dyn PlaceHolderLine = &PlaceHolder;
    }

    #[test]
    fn text_line_can_be_used_as_placeholder() {
        let line = TextLine::new("test");
        let _ph: &dyn PlaceHolderLine = &line;
    }

    #[test]
    fn placeholder_text_line_trait_methods_accessible() {
        let line = TextLine::new("hello");
        let ph: &dyn PlaceHolderLine = &line;
        assert_eq!(ph.get_text(), "hello");
        assert!(!ph.is_diff_colored());
    }
}
