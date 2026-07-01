use super::op_behavior::OpBehavior;

/// A behavior marker for p-code operations that have no special evaluation logic.
///
/// These operations (e.g., LOAD, STORE, BRANCH, CALL) are handled by the p-code
/// engine itself rather than through custom evaluation. The `SpecialOpBehavior`
/// type serves as a marker to distinguish them from operations with specialized
/// evaluation implementations.
///
/// Corresponds to `ghidra.pcode.opbehavior.SpecialOpBehavior`.
pub type SpecialOpBehavior = OpBehavior;

/// Construct a `SpecialOpBehavior` for the given numeric opcode.
///
/// This is equivalent to instantiating `SpecialOpBehavior` in the original Java source.
pub fn special_op_behavior(opcode: i32) -> SpecialOpBehavior {
    OpBehavior::new(opcode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_op_behavior_stores_opcode() {
        let b = special_op_behavior(42);
        assert_eq!(b.opcode(), 42);
    }

    #[test]
    fn zero_opcode() {
        let b = special_op_behavior(0);
        assert_eq!(b.opcode(), 0);
    }

    #[test]
    fn negative_opcode() {
        let b = special_op_behavior(-1);
        assert_eq!(b.opcode(), -1);
    }

    #[test]
    fn type_alias_equality() {
        let special = special_op_behavior(7);
        let regular = OpBehavior::new(7);
        assert_eq!(special, regular);
    }
}
