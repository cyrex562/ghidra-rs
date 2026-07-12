use crate::decompiler::opcodes::OpCode;
use crate::decompiler::translate::UnimplError;
use crate::program::model::lang::sleigh::template::{ConstructTpl, OpTpl};

/// Manages pcode generation for SLEIGH constructs.
///
/// Models `ghidra.pcodeCPort.semantics.PcodeBuilder`.
pub struct PcodeBuilder {
    labelbase: i32,
    labelcount: i32,
}

impl PcodeBuilder {
    /// Creates a new PcodeBuilder with the given initial label count.
    pub fn new(lbcnt: i32) -> Self {
        Self {
            labelbase: lbcnt,
            labelcount: lbcnt,
        }
    }

    /// Returns the current label base.
    pub fn label_base(&self) -> i32 {
        self.labelbase
    }

    /// Processes the given construct template, applying pcode operations.
    ///
    /// # Arguments
    /// * `construct` - The construct template to process
    /// * `ops_handler` - Handler for pcode operations
    /// * `secnum` - Section number
    pub fn build<H: PcodeBuilderOps>(
        &mut self,
        construct: &ConstructTpl,
        ops_handler: &mut H,
        secnum: i32,
    ) -> Result<(), UnimplError> {
        let oldbase = self.labelbase;
        self.labelbase = self.labelcount;
        self.labelcount += construct.num_labels as i32;

        for op in &construct.vec {
            match op.get_opcode() {
                OpCode::CpuiMultiequal => ops_handler.append_build(op, secnum),
                OpCode::CpuiIndirect => ops_handler.delay_slot(op),
                OpCode::CpuiPtradd => ops_handler.set_label(op),
                OpCode::CpuiPtrsub => ops_handler.append_cross_build(op, secnum),
                _ => ops_handler.dump(op),
            }
        }

        self.labelbase = oldbase;
        Ok(())
    }

    /// Disposes of resources held by this builder.
    pub fn dispose(&mut self) {}
}

/// Trait for handling pcode generation operations.
///
/// Used by PcodeBuilder to delegate operation-specific logic.
pub trait PcodeBuilderOps {
    /// Outputs the given operation.
    fn dump(&mut self, op: &OpTpl);

    /// Appends a build operation.
    fn append_build(&mut self, bld: &OpTpl, secnum: i32);

    /// Appends a cross-build operation.
    fn append_cross_build(&mut self, bld: &OpTpl, secnum: i32);

    /// Handles a delay slot operation.
    fn delay_slot(&mut self, op: &OpTpl);

    /// Handles a label setting operation.
    fn set_label(&mut self, op: &OpTpl);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOps {
        dump_count: usize,
        append_build_count: usize,
        append_cross_build_count: usize,
        delay_slot_count: usize,
        set_label_count: usize,
    }

    impl PcodeBuilderOps for MockOps {
        fn dump(&mut self, _op: &OpTpl) {
            self.dump_count += 1;
        }

        fn append_build(&mut self, _bld: &OpTpl, _secnum: i32) {
            self.append_build_count += 1;
        }

        fn append_cross_build(&mut self, _bld: &OpTpl, _secnum: i32) {
            self.append_cross_build_count += 1;
        }

        fn delay_slot(&mut self, _op: &OpTpl) {
            self.delay_slot_count += 1;
        }

        fn set_label(&mut self, _op: &OpTpl) {
            self.set_label_count += 1;
        }
    }

    #[test]
    fn new_initializes_labels() {
        let builder = PcodeBuilder::new(42);
        assert_eq!(builder.label_base(), 42);
    }

    #[test]
    fn label_base_returns_labelbase() {
        let builder = PcodeBuilder::new(100);
        assert_eq!(builder.label_base(), 100);
    }

    #[test]
    fn build_empty_construct() {
        let mut builder = PcodeBuilder::new(0);
        let mut ops = MockOps {
            dump_count: 0,
            append_build_count: 0,
            append_cross_build_count: 0,
            delay_slot_count: 0,
            set_label_count: 0,
        };

        let construct = ConstructTpl::new();
        let result = builder.build(&construct, &mut ops, 0);

        assert!(result.is_ok());
        assert_eq!(ops.dump_count, 0);
        assert_eq!(builder.label_base(), 0);
    }

    #[test]
    fn build_restores_labelbase() {
        let mut builder = PcodeBuilder::new(10);
        let initial_labelbase = builder.label_base();
        let mut ops = MockOps {
            dump_count: 0,
            append_build_count: 0,
            append_cross_build_count: 0,
            delay_slot_count: 0,
            set_label_count: 0,
        };

        let construct = ConstructTpl::new();
        let _ = builder.build(&construct, &mut ops, 0);

        assert_eq!(builder.label_base(), initial_labelbase);
    }

    #[test]
    fn dispose_runs_without_error() {
        let mut builder = PcodeBuilder::new(0);
        builder.dispose();
        assert_eq!(builder.label_base(), 0);
    }
}
