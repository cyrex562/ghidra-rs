use std::sync::Arc;

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::block::code_block_iterator::CodeBlockIterator;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::CodeBlock;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Display name for this block model.
///
/// Stands in for `SimpleBlockModel.NAME`.
pub const NAME: &str = "Simple Block";

/// Implements the simple block model.
///
/// Each `CodeBlock` is made up of contiguous instructions in address order. Blocks satisfy the
/// following:
/// 1. Any instruction with a label starts a block.
/// 2. Each instruction that could cause program control flow to change is the last instruction of
///    a `CodeBlock`.
/// 3. All other instructions are "NOP" fallthroughs, meaning after execution the program counter
///    will be at the instruction immediately following.
/// 4. Any instruction that is unreachable and has no label is also considered the start of a
///    block.
///
/// This model does not implement the pure simple block model because unreachable code is still
/// considered a block.
///
/// Port of `ghidra.program.model.block.SimpleBlockModel` to a trait: this type was selected as a
/// dependency-cycle cut-point (its private helper methods construct `CodeBlockImpl`/
/// `ExtCodeBlockImpl`/`SimpleBlockIterator`/`SimpleSourceReferenceIterator`/
/// `SimpleDestReferenceIterator`, which in turn hold a reference back to the model that created
/// them). Only the type's public API -- plus the one `protected` method
/// ([`has_end_of_block_flow`](Self::has_end_of_block_flow)) that `BasicBlockModel` overrides -- is
/// captured here; the private helpers (`getCodeBlockAt(Instruction, TaskMonitor)`,
/// `createSimpleBlock`, `createSimpleDataBlock`, `createSimpleExtBlock`, the `foundBlockMap`
/// cache, ...) are implementation details of a concrete implementor, not part of the trait
/// contract.
///
/// Also stands in for the `ghidra.program.model.block.CodeBlockModel` interface that
/// `SimpleBlockModel` implements: `CodeBlockModel` itself has not been ported yet (it is a
/// separate Java type), so its method surface is folded directly into this trait rather than
/// pulled in as a supertrait. Java's overloaded `getCodeBlocksContaining` (by `Address` vs. by
/// `AddressSetView`) and `getName` (no-arg vs. by `CodeBlock`) become distinctly-named methods
/// here since Rust traits cannot overload by parameter type/arity.
pub trait SimpleBlockModel {
    /// Get the code/data block starting at this address.
    ///
    /// Stands in for `SimpleBlockModel.getCodeBlockAt(Address, TaskMonitor)`.
    ///
    /// Returns `None` if there is no codeblock starting at the address.
    fn get_code_block_at(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException>;

    /// Get the first code block that contains the given address.
    ///
    /// Stands in for `CodeBlockModel.getFirstCodeBlockContaining(Address, TaskMonitor)`.
    fn get_first_code_block_containing(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException>;

    /// Get all the code blocks containing the address.
    ///
    /// Stands in for `CodeBlockModel.getCodeBlocksContaining(Address, TaskMonitor)`. Defaults to
    /// wrapping [`get_first_code_block_containing`](Self::get_first_code_block_containing),
    /// mirroring `SimpleBlockModel`'s own implementation (this model never returns more than one
    /// containing block since [`allows_block_overlap`](Self::allows_block_overlap) is `false`).
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
    ///
    /// Stands in for `CodeBlockModel.getCodeBlocks(TaskMonitor)`.
    fn get_code_blocks(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockIterator>, CancelledException>;

    /// Get an iterator over code blocks which overlap the specified address set.
    ///
    /// Stands in for `CodeBlockModel.getCodeBlocksContaining(AddressSetView, TaskMonitor)`.
    fn get_code_blocks_overlapping(
        &self,
        addr_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockIterator>, CancelledException>;

    /// Returns the program object associated with this model instance.
    ///
    /// Stands in for `CodeBlockModel.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get a name for the given block.
    ///
    /// Stands in for `CodeBlockModel.getName(CodeBlock)`. Usually the label at the block's start
    /// address, falling back to the address itself if unlabeled.
    fn get_block_name(&self, block: &dyn CodeBlock) -> String;

    /// Return in general how things flow out of the given block.
    ///
    /// Stands in for `CodeBlockModel.getFlowType(CodeBlock)`. `RefType` stands in for Java's
    /// `FlowType` here (see [`RefType`]'s own docs: it already mirrors `RefType`, `DataRefType`,
    /// and `FlowType` together).
    fn get_flow_type(&self, block: &dyn CodeBlock) -> RefType;

    /// Get an iterator over source blocks flowing into this block.
    ///
    /// Stands in for `CodeBlockModel.getSources(CodeBlock, TaskMonitor)`.
    fn get_sources(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;

    /// Get number of source blocks flowing into this block.
    ///
    /// Stands in for `CodeBlockModel.getNumSources(CodeBlock, TaskMonitor)`. Deprecated in Java
    /// since it repeats the work of the [`get_sources`](Self::get_sources) iterator.
    fn get_num_sources(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<i32, CancelledException>;

    /// Get an iterator over destination blocks flowing from this block.
    ///
    /// Stands in for `CodeBlockModel.getDestinations(CodeBlock, TaskMonitor)`.
    fn get_destinations(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;

    /// Get number of destination blocks flowing out of this block.
    ///
    /// Stands in for `CodeBlockModel.getNumDestinations(CodeBlock, TaskMonitor)`. Deprecated in
    /// Java since it repeats the work of the [`get_destinations`](Self::get_destinations)
    /// iterator.
    fn get_num_destinations(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<i32, CancelledException>;

    /// Get the basic block model used by this model.
    ///
    /// Stands in for `CodeBlockModel.getBasicBlockModel()`. `SimpleBlockModel` just returns
    /// `this`; as with
    /// [`SubroutineBlockModel::get_base_subroutine_model`](crate::program::model::block::subroutine_block_model::SubroutineBlockModel::get_base_subroutine_model),
    /// there is no blanket default that can honor Java's reference-identity "return this" from
    /// behind `&self` without a `Self: Clone` bound (which would break object-safety), so
    /// implementors construct whatever boxed handle to themselves is appropriate.
    fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel>;

    /// Returns the model name.
    ///
    /// Stands in for `CodeBlockModel.getName()`. Defaults to [`NAME`], matching
    /// `SimpleBlockModel.getName()`.
    fn get_name(&self) -> String {
        NAME.to_string()
    }

    /// Return true if this model allows overlapping of address sets for the blocks it returns.
    ///
    /// Stands in for `CodeBlockModel.allowsBlockOverlap()`. Defaults to `false`, matching
    /// `SimpleBlockModel.allowsBlockOverlap()` (which is not overridden by any known subclass).
    fn allows_block_overlap(&self) -> bool {
        false
    }

    /// Returns true if externals are handled by the model, false if externals are ignored.
    ///
    /// Stands in for `CodeBlockModel.externalsIncluded()`. When handled, externals are
    /// represented by an `ExtCodeBlockImpl`.
    fn externals_included(&self) -> bool;

    /// Check if the given instruction is the start of a Simple block.
    ///
    /// Stands in for `SimpleBlockModel.isBlockStart(Instruction)`.
    fn is_block_start(&self, instruction: &dyn Instruction) -> bool;

    /// Examine an instruction for out-bound flows which qualify it as an end-of-block.
    ///
    /// Stands in for `SimpleBlockModel.hasEndOfBlockFlow(Instruction)`. This is the one
    /// `protected` extension point `BasicBlockModel` overrides (to also treat local
    /// jump/terminator flows -- as opposed to just non-fallthrough flow-type -- as ending a
    /// block), so it is captured here as a required method rather than folded into
    /// [`get_code_block_at`](Self::get_code_block_at)'s (unmodeled) private algorithm.
    fn has_end_of_block_flow(&self, instr: &dyn Instruction) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::instruction_stub::InstructionStub;
    use crate::program::model::symbol::Reference;
    use std::sync::Arc as StdArc;

    /// A `CodeBlock` whose only meaningfully-implemented member is
    /// [`CodeBlock::get_model`](crate::program::seam_stubs::CodeBlock::get_model), unused by the
    /// tests below (which only exercise the block model's own methods).
    struct MockCodeBlock;

    impl CodeBlock for MockCodeBlock {
        fn get_model(&self) -> Box<dyn crate::program::seam_stubs::CodeBlockModel> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
    }

    /// A minimal instruction whose flow type is fixed at construction, standing in for a real
    /// disassembled `Instruction`.
    struct FixedFlowInstruction {
        flow_type: RefType,
    }

    impl InstructionStub for FixedFlowInstruction {
        fn get_flow_type(&self) -> RefType {
            self.flow_type
        }

        fn get_references_from(&self) -> Vec<StdArc<dyn Reference>> {
            Vec::new()
        }
    }

    /// A model that only ever finds a single fixed block (or nothing), proving
    /// [`SimpleBlockModel::get_code_blocks_containing_addr`]'s default correctly wraps
    /// [`SimpleBlockModel::get_first_code_block_containing`] and that the trait is object-safe.
    struct FixedLookupModel {
        found: bool,
        include_externals: bool,
    }

    impl SimpleBlockModel for FixedLookupModel {
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!()
        }

        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(if self.found {
                Some(Box::new(MockCodeBlock))
            } else {
                None
            })
        }

        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!()
        }

        fn get_code_blocks_overlapping(
            &self,
            _addr_set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!()
        }

        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!()
        }

        fn get_flow_type(&self, _block: &dyn CodeBlock) -> RefType {
            unimplemented!()
        }

        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }

        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }

        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }

        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }

        fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel> {
            Box::new(FixedLookupModel {
                found: self.found,
                include_externals: self.include_externals,
            })
        }

        fn externals_included(&self) -> bool {
            self.include_externals
        }

        fn is_block_start(&self, _instruction: &dyn Instruction) -> bool {
            unimplemented!()
        }

        fn has_end_of_block_flow(&self, instr: &dyn Instruction) -> bool {
            instr.get_flow_type() != RefType::FallThrough
        }
    }

    /// A model standing in for `BasicBlockModel`, which overrides
    /// [`SimpleBlockModel::has_end_of_block_flow`] to only end a block on local (jump/terminal)
    /// flow, treating calls as ordinary fallthroughs (since a call doesn't leave the containing
    /// function). Every other member delegates to a wrapped [`FixedLookupModel`], mirroring how
    /// `BasicBlockModel extends SimpleBlockModel` and overrides exactly one method.
    struct BasicLikeModel {
        inner: FixedLookupModel,
    }

    impl SimpleBlockModel for BasicLikeModel {
        fn get_code_block_at(
            &self,
            addr: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            self.inner.get_code_block_at(addr, monitor)
        }

        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            self.inner.get_first_code_block_containing(addr, monitor)
        }

        fn get_code_blocks(
            &self,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            self.inner.get_code_blocks(monitor)
        }

        fn get_code_blocks_overlapping(
            &self,
            addr_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            self.inner.get_code_blocks_overlapping(addr_set, monitor)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            self.inner.get_program()
        }

        fn get_block_name(&self, block: &dyn CodeBlock) -> String {
            self.inner.get_block_name(block)
        }

        fn get_flow_type(&self, block: &dyn CodeBlock) -> RefType {
            self.inner.get_flow_type(block)
        }

        fn get_sources(
            &self,
            block: &dyn CodeBlock,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            self.inner.get_sources(block, monitor)
        }

        fn get_num_sources(
            &self,
            block: &dyn CodeBlock,
            monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            self.inner.get_num_sources(block, monitor)
        }

        fn get_destinations(
            &self,
            block: &dyn CodeBlock,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            self.inner.get_destinations(block, monitor)
        }

        fn get_num_destinations(
            &self,
            block: &dyn CodeBlock,
            monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            self.inner.get_num_destinations(block, monitor)
        }

        fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel> {
            self.inner.get_basic_block_model()
        }

        fn externals_included(&self) -> bool {
            self.inner.externals_included()
        }

        fn is_block_start(&self, instruction: &dyn Instruction) -> bool {
            self.inner.is_block_start(instruction)
        }

        fn has_end_of_block_flow(&self, instr: &dyn Instruction) -> bool {
            let flow_type = instr.get_flow_type();
            if flow_type.is_jump() || flow_type.is_terminal() {
                return true;
            }
            instr
                .get_references_from()
                .iter()
                .any(|r| r.reference_type().is_jump() || r.reference_type().is_terminal())
        }
    }

    #[test]
    fn code_blocks_containing_addr_default_wraps_first_containing_block() {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::util::task::DummyMonitor;

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x400);

        let hit = FixedLookupModel {
            found: true,
            include_externals: false,
        };
        let blocks = hit.get_code_blocks_containing_addr(&addr, &DummyMonitor).unwrap();
        assert_eq!(blocks.len(), 1);

        let miss = FixedLookupModel {
            found: false,
            include_externals: false,
        };
        let blocks = miss.get_code_blocks_containing_addr(&addr, &DummyMonitor).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn get_name_and_overlap_defaults_match_java_simple_block_model() {
        let model = FixedLookupModel {
            found: false,
            include_externals: true,
        };
        assert_eq!(model.get_name(), NAME);
        assert!(!model.allows_block_overlap());
        assert!(model.externals_included());
    }

    #[test]
    fn basic_block_model_style_override_treats_call_as_fallthrough_unlike_simple_model() {
        let boxed_simple: Box<dyn SimpleBlockModel> = Box::new(FixedLookupModel {
            found: false,
            include_externals: false,
        });
        let boxed_basic: Box<dyn SimpleBlockModel> = Box::new(BasicLikeModel {
            inner: FixedLookupModel {
                found: false,
                include_externals: false,
            },
        });

        let call_instr = FixedFlowInstruction {
            flow_type: RefType::UnconditionalCall,
        };
        let jump_instr = FixedFlowInstruction {
            flow_type: RefType::UnconditionalJump,
        };
        let fallthrough_instr = FixedFlowInstruction {
            flow_type: RefType::FallThrough,
        };

        // SimpleBlockModel's default treats any non-fallthrough flow type (including calls) as
        // ending the block.
        assert!(boxed_simple.has_end_of_block_flow(&call_instr));
        assert!(boxed_simple.has_end_of_block_flow(&jump_instr));
        assert!(!boxed_simple.has_end_of_block_flow(&fallthrough_instr));

        // BasicBlockModel's override only ends the block on local jump/terminal flow, so a call
        // (which doesn't leave the containing function) is treated like a fallthrough.
        assert!(!boxed_basic.has_end_of_block_flow(&call_instr));
        assert!(boxed_basic.has_end_of_block_flow(&jump_instr));
        assert!(!boxed_basic.has_end_of_block_flow(&fallthrough_instr));
    }
}
