/// Base type representing the behavior of a single p-code operation.
///
/// Stores the numeric opcode identifying which p-code operation this behavior
/// belongs to. Subclasses in the original Java source override evaluation
/// methods; in Rust, callers can branch on `opcode()` directly.
///
/// Corresponds to `ghidra.pcode.opbehavior.OpBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpBehavior {
    opcode: i32,
}

impl OpBehavior {
    /// Construct an `OpBehavior` for the given numeric opcode.
    pub fn new(opcode: i32) -> Self {
        Self { opcode }
    }

    /// Return the numeric p-code opcode associated with this behavior.
    pub fn opcode(&self) -> i32 {
        self.opcode
    }
}

#[cfg(test)]
mod tests {
    use super::OpBehavior;

    #[test]
    fn new_stores_opcode() {
        let b = OpBehavior::new(42);
        assert_eq!(b.opcode(), 42);
    }

    #[test]
    fn zero_opcode() {
        let b = OpBehavior::new(0);
        assert_eq!(b.opcode(), 0);
    }

    #[test]
    fn negative_opcode() {
        let b = OpBehavior::new(-1);
        assert_eq!(b.opcode(), -1);
    }

    #[test]
    fn equality() {
        let a = OpBehavior::new(7);
        let b = OpBehavior::new(7);
        let c = OpBehavior::new(8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn clone_and_copy() {
        let a = OpBehavior::new(5);
        let cloned = a.clone();
        let copied = a;
        assert_eq!(cloned, copied);
    }

    #[test]
    fn debug_format() {
        let b = OpBehavior::new(3);
        assert!(format!("{:?}", b).contains("3"));
    }
}
