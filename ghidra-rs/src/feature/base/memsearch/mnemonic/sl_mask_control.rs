/// Represents a filter for a single instruction, controlling which portions are masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SLMaskControl {
    use_ops: bool,
    use_const: bool,
}

impl SLMaskControl {
    pub fn new(use_operands: bool, constant: bool) -> Self {
        Self { use_ops: use_operands, use_const: constant }
    }

    pub fn use_operands(&self) -> bool {
        self.use_ops
    }

    pub fn use_const(&self) -> bool {
        self.use_const
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_operands_and_const_flags() {
        let ctrl = SLMaskControl::new(true, false);
        assert!(ctrl.use_operands());
        assert!(!ctrl.use_const());
    }

    #[test]
    fn both_false() {
        let ctrl = SLMaskControl::new(false, false);
        assert!(!ctrl.use_operands());
        assert!(!ctrl.use_const());
    }

    #[test]
    fn both_true() {
        let ctrl = SLMaskControl::new(true, true);
        assert!(ctrl.use_operands());
        assert!(ctrl.use_const());
    }

    #[test]
    fn operands_false_const_true() {
        let ctrl = SLMaskControl::new(false, true);
        assert!(!ctrl.use_operands());
        assert!(ctrl.use_const());
    }

    #[test]
    fn clone_is_independent() {
        let a = SLMaskControl::new(true, false);
        let b = a;
        assert_eq!(a, b);
    }
}
