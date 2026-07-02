use super::SymZ3RecordsPreconditions;

/// Trait for internal objects that can record symbolic Z3 preconditions.
///
/// Extends `SymZ3RecordsPreconditions` with the ability to add new preconditions.
///
/// Corresponds to `ghidra.pcode.emu.symz3.InternalSymZ3RecordsPreconditions`.
pub trait InternalSymZ3RecordsPreconditions: SymZ3RecordsPreconditions {
    /// Record a precondition.
    ///
    /// # Arguments
    ///
    /// * `precondition` - The serialized Z3 bool expression.
    fn add_precondition(&mut self, precondition: String);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInternalPreconditions {
        conditions: Vec<String>,
    }

    impl SymZ3RecordsPreconditions for MockInternalPreconditions {
        fn get_preconditions(&self) -> Vec<String> {
            self.conditions.clone()
        }
    }

    impl InternalSymZ3RecordsPreconditions for MockInternalPreconditions {
        fn add_precondition(&mut self, precondition: String) {
            self.conditions.push(precondition);
        }
    }

    #[test]
    fn add_single_precondition() {
        let mut m = MockInternalPreconditions {
            conditions: vec![],
        };
        m.add_precondition("x > 0".to_string());
        assert_eq!(m.get_preconditions(), vec!["x > 0"]);
    }

    #[test]
    fn add_multiple_preconditions() {
        let mut m = MockInternalPreconditions {
            conditions: vec!["a != b".to_string()],
        };
        m.add_precondition("c <= 10".to_string());
        assert_eq!(
            m.get_preconditions(),
            vec!["a != b", "c <= 10"]
        );
    }

    #[test]
    fn add_empty_precondition() {
        let mut m = MockInternalPreconditions {
            conditions: vec![],
        };
        m.add_precondition(String::new());
        assert_eq!(m.get_preconditions(), vec![""]);
    }
}
