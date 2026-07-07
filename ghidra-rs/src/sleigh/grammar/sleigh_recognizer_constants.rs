/// Constant values used by the Sleigh recognizer.
///
/// Mirrors `ghidra.sleigh.grammar.SleighRecognizerConstants`.
pub const COMMENT: i32 = 1;
pub const PREPROC: i32 = 2;

pub const BASE: i32 = 0;
pub const DISPLAY: i32 = 1;
pub const SEMANTIC: i32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_constant() {
        assert_eq!(COMMENT, 1);
    }

    #[test]
    fn preproc_constant() {
        assert_eq!(PREPROC, 2);
    }

    #[test]
    fn base_constant() {
        assert_eq!(BASE, 0);
    }

    #[test]
    fn display_constant() {
        assert_eq!(DISPLAY, 1);
    }

    #[test]
    fn semantic_constant() {
        assert_eq!(SEMANTIC, 2);
    }

    #[test]
    fn constants_are_distinct() {
        let values = [COMMENT, PREPROC, BASE, DISPLAY, SEMANTIC];
        assert!(COMMENT != PREPROC);
        assert!(BASE != DISPLAY);
        assert!(DISPLAY != SEMANTIC);
    }
}
