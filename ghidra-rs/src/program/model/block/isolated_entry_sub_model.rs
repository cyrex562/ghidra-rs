use crate::program::model::block::overlap_code_sub_model::OverlapCodeSubModel;

/// Display name for this block model.
///
/// Stands in for `IsolatedEntrySubModel.ISOLATED_MODEL_NAME`.
pub const NAME: &str = "Isolated Entry";

/// Model-S: defines subroutines with a unique entry point, which may share code with other
/// subroutines. Each entry-point may either be a source or called entry-point and is identified
/// using the M-Model. This model extends the O-Model, redefining the set of addresses contained
/// within each subroutine. Unlike the O-Model, the address set of an Isolated-Entry subroutine is
/// permitted to span entry-points of other subroutines based upon the possible flows from its
/// entry-point.
///
/// Port of `ghidra.program.model.block.IsolatedEntrySubModel` to a trait, matching the precedent
/// set by [`OverlapCodeSubModel`] (the class this one extends in Java): the subroutine-discovery
/// algorithm (`getSubroutine`'s override) walks basic blocks via the M-Model's basic-block model
/// and the `Listing`/`CodeBlockCache` machinery that `OverlapCodeSubModel` itself already elides
/// (see that trait's own doc comment) as private/protected implementation detail, not part of
/// the public API. So only the public surface -- the `getName()` override, captured as the `NAME`
/// constant above (mirroring `OverlapCodeSubModel::NAME`) -- is modeled here, via the
/// [`OverlapCodeSubModel`] supertrait bound.
pub trait IsolatedEntrySubModel: OverlapCodeSubModel {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::block::code_block_model::CodeBlockModel;
    use crate::program::model::block::subroutine_block_model::SubroutineBlockModel;
    use crate::program::model::listing::listing::Listing;
    use crate::program::seam_stubs::FlowType;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;

    /// A minimal model exercising just enough of the [`CodeBlockModel`]/[`SubroutineBlockModel`]/
    /// [`OverlapCodeSubModel`] surface to prove [`IsolatedEntrySubModel`] is object-safe and
    /// correctly inherits every supertrait method through a `Box<dyn IsolatedEntrySubModel>`.
    /// `get_base_subroutine_model` bumps a shared counter so the test can prove delegation
    /// actually happened rather than merely type-checking.
    struct SModel {
        base_calls: Rc<Cell<u32>>,
    }

    impl CodeBlockModel for SModel {
        fn get_name(&self) -> String {
            NAME.to_string()
        }
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn crate::program::model::block::CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn crate::program::model::block::CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_sources(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_sources(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_destinations(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_flow_type(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
        ) -> Box<dyn FlowType> {
            unimplemented!()
        }
        fn get_block_name(&self, _block: &dyn crate::program::model::block::CodeBlock) -> String {
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
    }

    impl SubroutineBlockModel for SModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            self.base_calls.set(self.base_calls.get() + 1);
            Box::new(SModel {
                base_calls: self.base_calls.clone(),
            })
        }
    }

    impl OverlapCodeSubModel for SModel {
        fn get_listing(&self) -> Arc<dyn Listing> {
            unimplemented!()
        }
    }

    impl IsolatedEntrySubModel for SModel {}

    #[test]
    fn name_constant_matches_java_display_name() {
        assert_eq!(NAME, "Isolated Entry");
    }

    #[test]
    fn is_object_safe_and_inherits_supertrait_behavior() {
        let base_calls = Rc::new(Cell::new(0));
        let model: Box<dyn IsolatedEntrySubModel> = Box::new(SModel {
            base_calls: base_calls.clone(),
        });

        // CodeBlockModel::get_name, reachable through the OverlapCodeSubModel /
        // SubroutineBlockModel / CodeBlockModel supertrait chain.
        assert_eq!(model.get_name(), NAME);

        // SubroutineBlockModel::get_base_subroutine_model, likewise reachable, and dispatching
        // to this instance's own state rather than some shared default.
        let _base = model.get_base_subroutine_model();
        assert_eq!(base_calls.get(), 1);
    }
}
