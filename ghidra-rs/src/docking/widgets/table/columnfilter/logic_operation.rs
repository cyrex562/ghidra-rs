/// Logical combinator for column filter conditions.
///
/// Corresponds to `docking.widgets.table.columnfilter.LogicOperation` in the Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicOperation {
    And,
    Or,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(LogicOperation::And, LogicOperation::Or);
    }

    #[test]
    fn copy_semantics() {
        let op = LogicOperation::And;
        let op2 = op;
        assert_eq!(op, op2);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", LogicOperation::And), "And");
        assert_eq!(format!("{:?}", LogicOperation::Or), "Or");
    }
}
