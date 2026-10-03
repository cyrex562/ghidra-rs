use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::block::code_block::CodeBlock;
use crate::program::model::block::code_block_iterator::CodeBlockIterator;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::model::listing::program::Program;
use crate::program::seam_stubs::FlowType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// An implementation of a `CodeBlockModel` produces [`CodeBlock`]s based on some algorithm.
///
/// Port of `ghidra.program.model.block.CodeBlockModel`. Java's overloaded `getCodeBlocksContaining`
/// (by `Address`, returning `CodeBlock[]`, vs. by `AddressSetView`, returning a
/// `CodeBlockIterator`) and `getName` (no-arg model name vs. by-`CodeBlock` block name) become
/// distinctly-named methods here since Rust traits cannot overload by parameter type/arity,
/// matching the naming already established by
/// [`SimpleBlockModel`](crate::program::model::block::simple_block_model::SimpleBlockModel) (which
/// folds this same interface directly into its own trait, since this type was not ported yet when
/// it was written).
///
/// This trait absorbs (see `STUBS.tsv`) the members of two pre-existing, independently-minimal
/// placeholders used before this interface was ported: `crate::program::seam_stubs::CodeBlockModel`
/// (referenced by
/// [`SubroutineBlockModel`](crate::program::model::block::subroutine_block_model::SubroutineBlockModel)
/// and
/// [`SubroutineDestReferenceIterator`](crate::program::model::block::subroutine_dest_reference_iterator))
/// and `crate::app::seam_stubs::CodeBlockModel` (referenced by
/// [`BlockModelService`](crate::app::services::BlockModelService)). In particular,
/// [`get_code_blocks_containing`](Self::get_code_blocks_containing) keeps the first placeholder's
/// signature (taking a `&dyn CodeBlock` rather than a `&dyn AddressSetView`) since `CodeBlock` --
/// which extends `AddressSetView` in Java -- is the only concrete address set every existing caller
/// passes, and the real `CodeBlock` port will implement `AddressSetView` directly.
pub trait CodeBlockModel {
    /// Returns the model name.
    fn get_name(&self) -> String;

    /// Get the code block with a starting address (i.e. entry-point) of `addr`. Returns `None` if
    /// there is no codeblock starting at the address.
    fn get_code_block_at(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException>;

    /// Get the first code block that contains the given address, or `None` otherwise.
    fn get_first_code_block_containing(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException>;

    /// Get all the code blocks containing `addr`.
    ///
    /// Stands in for `CodeBlockModel.getCodeBlocksContaining(Address, TaskMonitor)`. Defaults to
    /// wrapping [`get_first_code_block_containing`](Self::get_first_code_block_containing);
    /// implementors whose [`allows_block_overlap`](Self::allows_block_overlap) is `true` should
    /// override this to report every containing block rather than just the first.
    fn get_code_blocks_containing_addr(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<Box<dyn CodeBlock>>, CancelledException> {
        Ok(self
            .get_first_code_block_containing(addr, monitor)?
            .into_iter()
            .collect())
    }

    /// Get an iterator over the code blocks in the entire program.
    fn get_code_blocks(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockIterator>, CancelledException>;

    /// Get an iterator over code blocks which overlap the specified address set.
    ///
    /// Stands in for `CodeBlockModel.getCodeBlocksContaining(AddressSetView, TaskMonitor)`. See the
    /// trait docs for why this takes a [`CodeBlock`] rather than a `&dyn AddressSetView`.
    fn get_code_blocks_containing(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockIterator>, CancelledException>;

    /// Get an iterator over the source flows into the block.
    fn get_sources(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;

    /// Get the number of source flows into the block.
    fn get_num_sources(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<i32, CancelledException>;

    /// Get an iterator over the destination flows out of the block.
    fn get_destinations(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;

    /// Get the number of destination flows out of the block.
    fn get_num_destinations(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<i32, CancelledException>;

    /// Get the basic block model used by this model.
    fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel>;

    /// Returns true if externals are handled by the model, false if externals are ignored. When
    /// handled, externals are represented by an `ExtCodeBlockImpl`. Defaults to `false`, matching
    /// the pre-existing placeholders' default.
    fn externals_included(&self) -> bool {
        false
    }

    /// Return in general how things flow out of `block`. If there are any abnormal ways to flow
    /// out of the block (jump, call, etc.) the block's flow type takes on that type; if there are
    /// multiple unique ways out, `FlowType.UNKNOWN`/`MULTIFLOW` is returned. Fallthrough is
    /// returned if that is the only way out.
    fn get_flow_type(&self, block: &dyn CodeBlock) -> Box<dyn FlowType>;

    /// Get a name for `block`: usually the label at its start address, though the model can choose
    /// any name it wants.
    ///
    /// Stands in for `CodeBlockModel.getName(CodeBlock)`.
    fn get_block_name(&self, block: &dyn CodeBlock) -> String;

    /// Returns the program object associated with this model instance.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Return true if this model allows overlapping of address sets for the blocks it returns.
    /// This implies [`get_code_blocks_containing_addr`](Self::get_code_blocks_containing_addr) can
    /// return more than one block; `false` implies it returns at most one.
    fn allows_block_overlap(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    /// A trivial single-block model with a fixed entry address, proving `CodeBlockModel` is
    /// object-safe and that the [`get_code_blocks_containing_addr`] default correctly wraps
    /// [`get_first_code_block_containing`] (returning zero or one block, never fabricating extras)
    /// while [`get_name`]/[`externals_included`]/[`allows_block_overlap`] report real,
    /// caller-distinguishable state rather than shared placeholder defaults.
    crate::impl_empty_address_set_view!(MockCodeBlock);

    struct MockCodeBlock;

    impl CodeBlock for MockCodeBlock {
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct SingleEntryModel {
        entry: Address,
        include_externals: bool,
    }

    impl CodeBlockModel for SingleEntryModel {
        fn get_name(&self) -> String {
            "Single Entry".to_string()
        }

        fn get_code_block_at(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(if addr == &self.entry {
                Some(Box::new(MockCodeBlock))
            } else {
                None
            })
        }

        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(if addr == &self.entry {
                Some(Box::new(MockCodeBlock))
            } else {
                None
            })
        }

        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_code_blocks_containing(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }

        fn externals_included(&self) -> bool {
            self.include_externals
        }

        fn get_flow_type(&self, _block: &dyn CodeBlock) -> Box<dyn FlowType> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn get_code_blocks_containing_addr_default_wraps_first_containing_block() {
        let space = ram_space();
        let entry = Address::new(space.clone(), 0x400000);
        let model: Box<dyn CodeBlockModel> = Box::new(SingleEntryModel {
            entry: entry.clone(),
            include_externals: false,
        });
        let monitor = crate::util::task::DummyMonitor;

        let hit = model
            .get_code_blocks_containing_addr(&entry, &monitor)
            .unwrap();
        assert_eq!(hit.len(), 1);

        let miss_addr = Address::new(space, 0x500000);
        let miss = model
            .get_code_blocks_containing_addr(&miss_addr, &monitor)
            .unwrap();
        assert!(miss.is_empty());
    }

    #[test]
    fn defaults_and_overrides_are_distinguishable_per_instance() {
        let space = ram_space();
        let entry = Address::new(space, 0x400000);

        let plain: Box<dyn CodeBlockModel> = Box::new(SingleEntryModel {
            entry: entry.clone(),
            include_externals: false,
        });
        let with_externals: Box<dyn CodeBlockModel> = Box::new(SingleEntryModel {
            entry,
            include_externals: true,
        });

        assert_eq!(plain.get_name(), "Single Entry");
        assert!(!plain.externals_included());
        assert!(with_externals.externals_included());
        assert!(!plain.allows_block_overlap());
    }
}
