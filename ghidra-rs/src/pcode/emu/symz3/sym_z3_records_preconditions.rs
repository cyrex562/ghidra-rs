/// Trait for objects that record symbolic Z3 preconditions.
///
/// Corresponds to `ghidra.pcode.emu.symz3.SymZ3RecordsPreconditions`.
pub trait SymZ3RecordsPreconditions {
    /// Returns the list of precondition expressions recorded by this object.
    fn get_preconditions(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPreconditions {
        conditions: Vec<String>,
    }

    impl SymZ3RecordsPreconditions for MockPreconditions {
        fn get_preconditions(&self) -> Vec<String> {
            self.conditions.clone()
        }
    }

    #[test]
    fn empty_preconditions() {
        let m = MockPreconditions { conditions: vec![] };
        assert!(m.get_preconditions().is_empty());
    }

    #[test]
    fn single_precondition() {
        let m = MockPreconditions {
            conditions: vec!["x > 0".to_string()],
        };
        let result = m.get_preconditions();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "x > 0");
    }

    #[test]
    fn multiple_preconditions() {
        let m = MockPreconditions {
            conditions: vec!["a != b".to_string(), "c <= 10".to_string()],
        };
        let result = m.get_preconditions();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "a != b");
        assert_eq!(result[1], "c <= 10");
    }
}
