use crate::program::model::pcode::Varnode;
use crate::pcode::seam_stubs::Emulate;

/// Extension point for custom CALLOTHER p-code operation behaviors.
///
/// This trait allows language implementations to define behavior for CALLOTHER operations
/// that are not directly representable as standard p-code operations. Each implementation
/// evaluates a specific CALLOTHER operation in the context of an emulator, updating the
/// emulator's memory state as needed.
///
/// Corresponds to `ghidra.pcode.emulate.callother.OpBehaviorOther`.
pub trait OpBehaviorOther {
    /// Evaluate the CALLOTHER operation corresponding to this behavior.
    ///
    /// # Arguments
    ///
    /// * `emu` - The emulator context containing the memory state to be updated by this operation.
    /// * `out` - The output varnode where the result should be stored, or `None` if the operation
    ///           produces no assignment. The implementation is responsible for updating the memory
    ///           state appropriately.
    /// * `inputs` - The input varnodes passed as arguments to this p-code operation.
    ///              The original CALLOTHER index value has been stripped, leaving only the actual
    ///              operand varnodes as specified in the language specification.
    fn evaluate(&self, emu: &dyn Emulate, out: Option<&Varnode>, inputs: &[Varnode]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct TestEmulate;
    impl Emulate for TestEmulate {
        fn dispose(&self) {}

        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("test should not call this")
        }
    }

    struct DummyBehavior;
    impl OpBehaviorOther for DummyBehavior {
        fn evaluate(&self, _emu: &dyn Emulate, _out: Option<&Varnode>, _inputs: &[Varnode]) {
            // Dummy implementation for testing
        }
    }

    #[test]
    fn evaluate_with_no_output() {
        let emu = TestEmulate;
        let behavior = DummyBehavior;
        let inputs = vec![];

        behavior.evaluate(&emu, None, &inputs);
    }

    #[test]
    fn evaluate_with_output() {
        let emu = TestEmulate;
        let behavior = DummyBehavior;

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let out = Varnode::new(Address::new(ram, 0x1000), 4);
        let inputs = vec![];

        behavior.evaluate(&emu, Some(&out), &inputs);
    }

    #[test]
    fn evaluate_with_inputs() {
        let emu = TestEmulate;
        let behavior = DummyBehavior;

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let in1 = Varnode::new(Address::new(ram.clone(), 0x2000), 4);
        let in2 = Varnode::new(Address::new(ram, 0x3000), 4);
        let inputs = vec![in1, in2];

        behavior.evaluate(&emu, None, &inputs);
    }

    #[test]
    fn trait_object_usage() {
        let behavior: Box<dyn OpBehaviorOther> = Box::new(DummyBehavior);
        let emu = TestEmulate;
        let inputs = vec![];

        behavior.evaluate(&emu, None, &inputs);
    }
}
