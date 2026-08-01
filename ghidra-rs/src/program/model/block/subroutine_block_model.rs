use crate::program::model::block::code_block_model::CodeBlockModel;

/// Subroutine block model.
///
/// Port of `ghidra.program.model.block.SubroutineBlockModel`.
pub trait SubroutineBlockModel: CodeBlockModel {
    /// Get the underlying base subroutine model.
    /// This is generally the MultEntSubModel (M-Model).
    ///
    /// Returns the base subroutine model. If there is no base model, this subroutine model is
    /// returned.
    fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A base model (e.g. the M-Model) that reports a fresh instance of itself as its own base
    /// on every call, mirroring the Java contract for a model with no distinct underlying base
    /// model ("if there is no base model, this subroutine model is returned"). Each call bumps a
    /// shared counter so the tests below can prove delegation actually happened, rather than just
    /// type-checking.
    struct MModel {
        calls: Rc<Cell<u32>>,
    }

    impl CodeBlockModel for MModel {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_code_block_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Option<Box<dyn crate::program::seam_stubs::CodeBlock>>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Option<Box<dyn crate::program::seam_stubs::CodeBlock>>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_sources(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_sources(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<i32, crate::util::exception::CancelledException> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_destinations(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<i32, crate::util::exception::CancelledException> {
            unimplemented!()
        }
        fn get_flow_type(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
        ) -> Box<dyn crate::program::seam_stubs::FlowType> {
            unimplemented!()
        }
        fn get_block_name(&self, _block: &dyn crate::program::seam_stubs::CodeBlock) -> String {
            unimplemented!()
        }
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
    }

    impl SubroutineBlockModel for MModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            self.calls.set(self.calls.get() + 1);
            Box::new(MModel { calls: self.calls.clone() })
        }
    }

    /// A layered model (e.g. an isolated-entry or overlap model) whose base model is a distinct
    /// `MModel`, proving `SubroutineBlockModel` is object-safe and that a layered model can
    /// delegate `get_base_subroutine_model` down to its underlying base rather than returning
    /// itself.
    struct DerivedModel {
        base_calls: Rc<Cell<u32>>,
    }

    impl CodeBlockModel for DerivedModel {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_code_block_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Option<Box<dyn crate::program::seam_stubs::CodeBlock>>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &crate::program::model::address::Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Option<Box<dyn crate::program::seam_stubs::CodeBlock>>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_sources(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_sources(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<i32, crate::util::exception::CancelledException> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_destinations(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<i32, crate::util::exception::CancelledException> {
            unimplemented!()
        }
        fn get_flow_type(
            &self,
            _block: &dyn crate::program::seam_stubs::CodeBlock,
        ) -> Box<dyn crate::program::seam_stubs::FlowType> {
            unimplemented!()
        }
        fn get_block_name(&self, _block: &dyn crate::program::seam_stubs::CodeBlock) -> String {
            unimplemented!()
        }
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
    }

    impl SubroutineBlockModel for DerivedModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            Box::new(MModel { calls: self.base_calls.clone() })
        }
    }

    #[test]
    fn base_model_bumps_shared_counter_on_each_chained_call() {
        let calls = Rc::new(Cell::new(0));
        let base: Box<dyn SubroutineBlockModel> = Box::new(MModel { calls: calls.clone() });

        let base_of_base = base.get_base_subroutine_model();
        assert_eq!(calls.get(), 1);

        let _base_of_base_of_base = base_of_base.get_base_subroutine_model();
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn derived_model_delegates_to_distinct_base_model() {
        let base_calls = Rc::new(Cell::new(0));
        let derived: Box<dyn SubroutineBlockModel> =
            Box::new(DerivedModel { base_calls: base_calls.clone() });

        // Delegating from the derived model itself must not touch the base model's counter yet.
        let base = derived.get_base_subroutine_model();
        assert_eq!(base_calls.get(), 0);

        // Once we're chained onto the real base model, further delegation does bump its counter,
        // proving `DerivedModel` handed off to a genuine `MModel` rather than looping back to
        // itself.
        let _base_of_base = base.get_base_subroutine_model();
        assert_eq!(base_calls.get(), 1);
    }
}
